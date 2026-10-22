# Best-effort hardening of the memory that holds the data key. Python and cryptography keep copies of their own
# (str, bytes, Fernet's derived keys) that no code here can reach, so this narrows exposure; it does not remove it.


# Overwrites the buffer's own memory in place: an equal-length slice assignment never reallocates, so no copy of the
# old bytes is left behind. Mutates its argument on purpose, against the no-mutation convention: zeroing a copy
# would leave the original untouched.
def wipe(buffer: bytearray) -> None:
    buffer[:] = bytes(len(buffer))
