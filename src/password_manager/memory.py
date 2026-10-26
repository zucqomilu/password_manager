# Best-effort hardening of the memory that holds the data key. Python and cryptography keep copies of their own
# (str, bytes, Fernet's derived keys) that no code here can reach, so this narrows exposure; it does not remove it.
import ctypes
import resource

from .logger import logger

# The C library pm runs on, for mlock() and prctl()
libc = ctypes.CDLL(None)

# From <linux/prctl.h>
PR_SET_DUMPABLE = 4


# Overwrites the buffer's own memory in place: an equal-length slice assignment never reallocates, so no copy of the
# old bytes is left behind. Mutates its argument on purpose, against the no-mutation convention: zeroing a copy
# would leave the original untouched.
def wipe(buffer: bytearray) -> None:
    buffer[:] = bytes(len(buffer))


# Keeps the buffer's pages out of swap. from_buffer() gives the buffer's own address without copying it, and the
# lock stays on its pages after the view is released, until the process exits; the buffer must never be resized,
# or its bytes would move off the locked pages. A refusal (over RLIMIT_MEMLOCK, or not permitted) never blocks the
# agent: the key stays usable, and only a fixed warning without the buffer goes to the log.
def lock_buffer(buffer: bytearray) -> bool:
    if libc.mlock(ctypes.c_void_p(ctypes.addressof((ctypes.c_char * len(buffer)).from_buffer(buffer))),
                  ctypes.c_size_t(len(buffer))) == 0:
        return True
    logger.warning("Could not lock the key in memory; it may be written to swap.")
    return False


# Makes the running process (the agent, or a pm command) refuse to dump its memory, where the key and its copies
# live. Soft and hard RLIMIT_CORE both 0: a crash writes no core file, and no code in the process can raise the
# limit again. Lowering a limit is always permitted, so this cannot fail.
# PR_SET_DUMPABLE 0 goes further: the kernel makes no core dump whatever core_pattern says, and other processes of
# the same user can no longer ptrace this one or read its /proc/<pid>/mem, which covers the copies of the key no
# wipe() can reach. The kernel reads prctl()'s arguments as unsigned longs, hence c_ulong. Setting 0 cannot fail.
def harden_process() -> None:
    resource.setrlimit(resource.RLIMIT_CORE, (0, 0))
    libc.prctl(PR_SET_DUMPABLE, ctypes.c_ulong(0), ctypes.c_ulong(0), ctypes.c_ulong(0), ctypes.c_ulong(0))
