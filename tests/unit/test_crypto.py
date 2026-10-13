import base64
import pytest
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives.kdf.argon2 import Argon2id
from password_manager.crypto import derive_key, derive_master_key, generate_salt, unwrap_data_key, wrap_data_key

@pytest.mark.unit
def test_generate_salt_length():
    salt = generate_salt()
    assert isinstance(salt, bytes)
    assert len(salt) == 16

@pytest.mark.unit
def test_generate_salt_custom_length():
    salt = generate_salt(32)
    assert len(salt) == 32

@pytest.mark.unit
def test_derive_key_consistency():
    password = "securepassword"
    salt = b"0123456789abcdef"
    key1 = derive_key(password, salt)
    key2 = derive_key(password, salt)
    assert key1 == key2  # Deterministic output

@pytest.mark.unit
def test_derive_key_different_salts():
    password = "securepassword"
    salt1 = b"0123456789abcdef"
    salt2 = b"abcdef0123456789"
    key1 = derive_key(password, salt1)
    key2 = derive_key(password, salt2)
    assert key1 != key2  # Different salt → different key

@pytest.mark.unit
def test_derive_key_type_and_length():
    password = "securepassword"
    salt = b"0123456789abcdef"
    key = derive_key(password, salt)
    assert isinstance(key, bytes)
    assert len(key) == 44


@pytest.mark.unit
def test_derive_master_key_uses_argon2id_with_the_stored_parameters():
    params = {"salt": base64.b64encode(b"0123456789abcdef").decode(), "time_cost": 2, "memory_cost": 64, "parallelism": 2}
    assert derive_master_key("securepassword", params) == Argon2id(
        salt=b"0123456789abcdef", length=32, iterations=2, lanes=2, memory_cost=64,
    ).derive(b"securepassword")

@pytest.mark.unit
def test_wrap_and_unwrap_data_key_round_trip():
    params = {"salt": base64.b64encode(b"0123456789abcdef").decode(), "time_cost": 2, "memory_cost": 64, "parallelism": 2}
    data_key = Fernet.generate_key()
    assert unwrap_data_key(wrap_data_key(data_key, "securepassword", params), "securepassword", params) == data_key
