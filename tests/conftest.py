# tests/conftest.py
import pytest, base64

# Helper to generate valid base64 strings
def b64(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).decode()

@pytest.fixture
def valid_b64():
    return base64.urlsafe_b64encode(b"secret12345678901234567890").decode()

@pytest.fixture
def corrupted_json():
    return '{ "alice": {"email": "incomplete'

@pytest.fixture
def invalid_json():
    return "{ this is not valid JSON }"

@pytest.fixture
def not_dict():
    return (["not", "a", "dict"])

@pytest.fixture
def value_not_dict():
    return ({"alice": "this should be a dict"})

@pytest.fixture
def valid_user():
    salt = b64(b"1234567890123456")
    pw = b64(b"somepasswordstring12345678901234")
    return ({
        "alice": {
            "auth_salt": salt,
            "enc_salt": salt,
            "password": pw
        }
    })

@pytest.fixture
def valid_users():
    salt1 = b64(b"1234567890123456")
    salt2 = b64(b"abcdefghijklmnop")
    pw1 = b64(b"password_for_alice_1234567890abc")
    pw2 = b64(b"bob_secure_pass_1234567890xyzxyz")
    return ({
        "alice": {
            "auth_salt": salt1,
            "enc_salt": salt1,
            "password": pw1
        },
        "bob": {
            "auth_salt": salt2,
            "enc_salt": salt2,
            "password": pw2
        }
    })

@pytest.fixture
def valid_vault():
    return ({
        "alice": {
            "email": b64(b"secret-encrypted-password")
        }
    })

@pytest.fixture
def valid_vault_multiple_entries(valid_b64):
    return ({
        "alice": {
            "email": valid_b64,
            "email__v1": valid_b64
        },
        "bob": {
            "github": valid_b64
        }
    })
