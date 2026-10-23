import ctypes
import logging
import resource
from unittest.mock import Mock

import pytest

from password_manager.memory import harden_process, lock_buffer, wipe


@pytest.mark.unit
def test_wipe_zeroes_every_byte_of_a_bytearray():
    # A filler pattern the length of a Fernet key, never a real key
    buffer = bytearray(b"\xa5" * 44)

    wipe(buffer)

    # Zeroed in place: the caller's own buffer, at its full length, not a zeroed copy
    assert buffer == bytearray(44)


# mlock() is faked, so the test controls whether the kernel allows it. Both refusals, over RLIMIT_MEMLOCK (ENOMEM)
# and not permitted at all (EPERM), return -1 and must leave the key usable, only unprotected from swap.
@pytest.mark.unit
@pytest.mark.parametrize("result, locked", [
    (0, True),
    (-1, False),
    (-1, False),
], ids=["locked", "over-limit", "not-permitted"])
def test_lock_buffer_mlocks_a_bytearray_and_warns_instead_of_failing_when_not_permitted(monkeypatch, caplog, result, locked):
    mlock = Mock(return_value=result)
    monkeypatch.setattr("password_manager.memory.libc.mlock", mlock)
    buffer = bytearray(44)

    with caplog.at_level(logging.WARNING):
        assert lock_buffer(buffer) is locked

    # The buffer's own memory, at its full length: not a copy's
    (address, length), = [call.args for call in mlock.call_args_list]
    assert (address.value, length.value) == (ctypes.addressof((ctypes.c_char * 44).from_buffer(buffer)), 44)
    # A fixed message that never shows the buffer
    assert caplog.messages == ([] if locked else ["Could not lock the key in memory; it may be written to swap."])


# setrlimit() is faked: lowering the hard limit in the pytest process itself could not be undone
@pytest.mark.unit
def test_harden_process_sets_rlimit_core_to_0(monkeypatch):
    setrlimit = Mock()
    monkeypatch.setattr("password_manager.memory.resource.setrlimit", setrlimit)

    harden_process()

    # Soft and hard limit both 0, so the process can never raise it again and a crash writes no core file
    setrlimit.assert_called_once_with(resource.RLIMIT_CORE, (0, 0))
