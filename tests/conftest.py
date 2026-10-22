import pytest, base64, json, builtins, tempfile, os, shutil, time
import keyring
from keyring.backends.null import Keyring as NullKeyring
from keyring.errors import PasswordDeleteError
from password_manager.agent import AgentState, handle_request
from password_manager.crypto import derive_key, wrap_data_key
from cryptography.fernet import Fernet
from unittest.mock import mock_open, patch


# Point PM_DATA_DIR at a throwaway folder before any test module imports the package
# (logger.py opens vault.log at import), so no test run touches the real data dir.
# PM_AGENT_SOCKET goes in the same folder, so no test run can reach the agent holding the real key.
def pytest_configure(config):
    os.environ["PM_DATA_DIR"] = tempfile.mkdtemp(prefix="pm-tests-")
    os.environ["PM_AGENT_SOCKET"] = os.path.join(os.environ["PM_DATA_DIR"], "agent.sock")


def pytest_unconfigure(config):
    os.environ.pop("PM_AGENT_SOCKET")
    shutil.rmtree(os.environ.pop("PM_DATA_DIR"), ignore_errors=True)


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


# Guarantee no test can read or write the real OS keyring, even one that forgets to mock it
@pytest.fixture(autouse=True)
def no_real_keyring():
    previous = keyring.get_keyring()
    keyring.set_keyring(NullKeyring())
    yield
    keyring.set_keyring(previous)


# Helper to generate valid base64 strings
def b64(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).decode()


# An in-process stand-in for the agent daemon: the real handle_request() core, with no process and no socket.
# "calls" records what pm asked of the agent, in order; "state" is what the agent holds.
@pytest.fixture
def fake_agent(monkeypatch):
    agent = {"state": AgentState(), "calls": []}

    def fake_start_agent(path):
        agent["calls"].append(("start_agent", path))

    def fake_send_request(path, request_):
        agent["calls"].append(("send_request", path, request_))
        agent["state"], response = handle_request(agent["state"], request_, time.time())
        return response

    monkeypatch.setattr("password_manager.agent.start_agent", fake_start_agent)
    monkeypatch.setattr("password_manager.agent.send_request", fake_send_request)
    return agent


@pytest.fixture
def set_test_env(monkeypatch, fake_agent):
    test_keyring.clear()

    with tempfile.TemporaryDirectory() as tmpdir:
        monkeypatch.setenv("VAULT_FILE", os.path.join(tmpdir, "vault.json"))
        monkeypatch.setenv("USERS_FILE", os.path.join(tmpdir, "users.json"))

        monkeypatch.setattr("password_manager.session.keyring.get_password", mock_get_password)
        monkeypatch.setattr("password_manager.session.keyring.set_password", mock_set_password)
        monkeypatch.setattr("password_manager.session.keyring.delete_password", mock_delete_password)
        
        yield tmpdir

    test_keyring.clear()


# Freezes time.time() for the whole test, which is the clock the (fake) agent checks the TTL against
@pytest.fixture
def test_clock(monkeypatch):
    current_time = [time.time()]

    monkeypatch.setattr(
        "time.time",
        lambda: current_time[0],
    )

    return current_time


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


# A v2 user record: Argon2id parameters plus the data key wrapped under the master password.
# Tiny Argon2id costs keep tests fast; real records use the defaults from register_user().
@pytest.fixture
def make_v2_user():
    def _make_v2_user(username="alice", password="alice_wonderland", data_key=None, salt=b"1234567890123456"):
        kdf = {"salt": base64.b64encode(salt).decode(), "time_cost": 2, "memory_cost": 64, "parallelism": 2}
        return {username: {"version": 2, "kdf": kdf, "wrapped_key": wrap_data_key(data_key or Fernet.generate_key(), password, kdf)}}
    return _make_v2_user


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
