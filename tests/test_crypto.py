from password_manager import derive_key

def test_derive_key_consistency():
    password = "testpass"
    salt = b"1234567890123456"
    key1 = derive_key(password, salt)
    key2 = derive_key(password, salt)
    assert key1 == key2

def test_derive_key_type():
    password = "password123"
    salt = b"abcdef1234567890"
    key = derive_key(password, salt)
    assert isinstance(key, bytes)
