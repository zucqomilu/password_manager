import pytest
import time
import json
import base64
from cryptography.fernet import Fernet

from src.session import (
    clear_session,
    load_session,
    save_session,
)


@pytest.mark.unit
def test_save_session_stores_session_in_keyring(set_test_env):
    _ = set_test_env
    key = Fernet.generate_key()
    save_session("testuser", key)

    result = load_session()

    assert result is not None

    username, fernet = result

    assert username == "testuser"
    assert isinstance(fernet, Fernet)
    assert fernet.decrypt(
        fernet.encrypt(b"test")
    ) == b"test"

@pytest.mark.unit
def test_load_session_reads_session_from_keyring(set_test_env):
    _ = set_test_env
    key = Fernet.generate_key()

    save_session("testuser", key)

    result = load_session()

    assert result is not None

    username, fernet = result

    assert username == "testuser"
    assert isinstance(fernet, Fernet)

    # Verify that the returned Fernet object uses the correct key.
    test_data = b"secret test data"
    encrypted = fernet.encrypt(test_data)

    assert fernet.decrypt(encrypted) == test_data


@pytest.mark.unit
def test_load_session_returns_none_if_no_session(set_test_env):
    _ = set_test_env
    result = load_session()
    
    assert result is None


@pytest.mark.unit
def test_load_session_returns_none_on_invalid_session_data(set_test_env, mock_session_keyring):
    _ = set_test_env

    set_session, _ = mock_session_keyring
    set_session("invalid json")

    result = load_session()

    assert result is None

@pytest.mark.unit
def test_clear_session_deletes_keyring_entry(set_test_env):
    _ = set_test_env
    key = Fernet.generate_key()

    save_session("testuser", key)

    assert load_session() is not None

    clear_session()

    assert load_session() is None


@pytest.mark.unit
def test_clear_session_handles_missing_session(set_test_env):
    _ = set_test_env

    clear_session()

    assert load_session() is None


@pytest.mark.unit
def test_save_session_stores_last_activity(set_test_env, mock_session_keyring):
    _ = set_test_env
    _, get_session = mock_session_keyring

    key = Fernet.generate_key()

    before = time.time()
    save_session("testuser", key)
    after = time.time()

    stored = get_session()
    assert stored is not None

    data = json.loads(stored)

    assert data["username"] == "testuser"
    assert data["last_activity"] >= before
    assert data["last_activity"] <= after


@pytest.mark.unit
def test_load_session_accepts_session_without_last_activity(
    set_test_env,
    mock_session_keyring,
):
    _ = set_test_env
    set_session, _ = mock_session_keyring

    key = Fernet.generate_key()

    set_session(json.dumps({
        "username": "testuser",
        "fernet_key": base64.urlsafe_b64encode(key).decode(),
    }))

    result = load_session()

    assert result is not None

    username, fernet = result

    assert username == "testuser"
    assert isinstance(fernet, Fernet)
