# tests/test_crypto.py

from src.crypto import derive_key, generate_salt

def test_generate_salt_length():
    salt = generate_salt()
    assert isinstance(salt, bytes)
    assert len(salt) == 16

def test_generate_salt_custom_length():
    salt = generate_salt(32)
    assert len(salt) == 32

def test_derive_key_consistency():
    password = "securepassword"
    salt = b"0123456789abcdef"
    key1 = derive_key(password, salt)
    key2 = derive_key(password, salt)
    assert key1 == key2  # Deterministic output

def test_derive_key_different_salts():
    password = "securepassword"
    salt1 = b"0123456789abcdef"
    salt2 = b"abcdef0123456789"
    key1 = derive_key(password, salt1)
    key2 = derive_key(password, salt2)
    assert key1 != key2  # Different salt → different key

def test_derive_key_type_and_length():
    password = "securepassword"
    salt = b"0123456789abcdef"
    key = derive_key(password, salt)
    assert isinstance(key, bytes)
    assert len(key) == 44

