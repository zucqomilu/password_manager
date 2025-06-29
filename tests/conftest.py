# tests/conftest.py
import pytest, base64, json
from src.crypto import derive_key

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
def valid_user_json(valid_user):
    return json.dumps(valid_user)

@pytest.fixture
def valid_vault_json(valid_vault):
    return json.dumps(valid_vault)

@pytest.fixture
def make_user():
    def _make_user(username="alice", password="alice_wonderland", auth_salt=b"1234567890123456", enc_salt=b"abcdefghijklmnop"):
        auth_key = derive_key(password, auth_salt).decode()
        return ({
            username: {
                "auth_salt": b64(auth_salt),
                "enc_salt": b64(enc_salt),
                "password": auth_key
            }
        })
    return _make_user

@pytest.fixture
def valid_user():
    auth_salt = b"1234567890123456"
    enc_salt = b"1234567890123456"
    auth_key = derive_key("alice_wonderland", auth_salt).decode()
    return ({
        "alice": {
            "auth_salt": b64(auth_salt),
            "enc_salt": b64(enc_salt),
            "password": auth_key
        }
    })

@pytest.fixture
def valid_users():
    auth_salt = b"1234567890123456"
    enc_salt  = b"abcdefghijklmnop"
    auth_key1 = derive_key("alice_password12", auth_salt).decode()
    auth_key2 = derive_key("bob_secure_pass1", auth_salt).decode()
    return ({
        "alice": {
            "auth_salt": b64(auth_salt),
            "enc_salt": b64(enc_salt),
            "password": auth_key1
        },
        "bob": {
            "auth_salt": b64(auth_salt),
            "enc_salt": b64(enc_salt),
            "password": auth_key2
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
