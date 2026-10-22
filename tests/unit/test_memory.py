import pytest

from password_manager.memory import wipe


@pytest.mark.unit
def test_wipe_zeroes_every_byte_of_a_bytearray():
    # A filler pattern the length of a Fernet key, never a real key
    buffer = bytearray(b"\xa5" * 44)

    wipe(buffer)

    # Zeroed in place: the caller's own buffer, at its full length, not a zeroed copy
    assert buffer == bytearray(44)
