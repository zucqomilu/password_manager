import pytest, base64, json, builtins, tempfile, os
from keyring.errors import PasswordDeleteError
from src.crypto import derive_key
from cryptography.fernet import Fernet
from unittest.mock import mock_open, patch


test_keyring = {}


def mock_get_password(service, username):
    return test_keyring.get((service, username))


def mock_set_password(service, username, password):
    test_keyring[(service, username)] = password


def mock_delete_password(service, username):
    key = (service, username)

    if key not in test_keyring:
        raise PasswordDeleteError("Password not found")

    del test_keyring[key]


# Helper to generate valid base64 strings
def b64(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).decode()


@pytest.fixture
def set_test_env(monkeypatch):
    test_keyring.clear()

    with tempfile.TemporaryDirectory() as tmpdir:
        monkeypatch.setenv("VAULT_FILE", os.path.join(tmpdir, "vault.json"))
        monkeypatch.setenv("USERS_FILE", os.path.join(tmpdir, "users.json"))

        monkeypatch.setattr("src.session.keyring.get_password", mock_get_password)
        monkeypatch.setattr("src.session.keyring.set_password", mock_set_password)
        monkeypatch.setattr("src.session.keyring.delete_password", mock_delete_password)
        
        yield tmpdir

    test_keyring.clear()


@pytest.fixture
def mock_session_keyring():
    def set_session(data):
        test_keyring[("password_manager", "session")] = data

    def get_session():
        return test_keyring.get(("password_manager", "session"))

    return set_session, get_session


@pytest.fixture()
def fernet(password="alice_wonderland", salt=b"1234567890123456"):
    return Fernet(derive_key(password, salt))


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
def mock_json_file():
    """
    Returns a context manager to patch 'open' for reading JSON.
    Supports both .read() and iteration (required by json.load).
    
    Usage:
        with mock_json_file(json_string):
            ...
    """
    def _mock(json_string):
        m = mock_open(read_data=json_string)
        m.return_value.__iter__ = lambda _: iter(json_string.splitlines())
        return patch.object(builtins, "open", m)
    return _mock


@pytest.fixture
def valid_vault(fernet):
    encrypted_github_pw =      fernet.encrypt(b"supersecurepass1").decode()
    new_encrypted_twitter_pw = fernet.encrypt(b"newsecurepass123").decode()
    encrypted_twitter_pw =     fernet.encrypt(b"anothersecurepas").decode()
    encrypted_login =          fernet.encrypt(b"alice@example.com").decode()

    return {
        "alice": {
            "github": {
                "password": encrypted_github_pw,
                "login": encrypted_login
            },
            "twitter": {
                "password": new_encrypted_twitter_pw
            },
            "twitter__v1": {
                "password": encrypted_twitter_pw
            }
        }
    }


@pytest.fixture
def valid_vault_multiple_users(fernet):
    encrypted_github_pw =  fernet.encrypt(b"supersecurepass1").decode()
    encrypted_twitter_pw = fernet.encrypt(b"anothersecurepas").decode()
    encrypted_login =      fernet.encrypt(b"alice@example.com").decode()

    return {
        "alice": {
            "github": {
                "password": encrypted_github_pw,
                "login": encrypted_login
            },
            "twitter": {
                "password": encrypted_twitter_pw
            }
        },
        "bob": {
            "github": {
                "password": encrypted_github_pw,
                "login": encrypted_login
            }
        }
    }
