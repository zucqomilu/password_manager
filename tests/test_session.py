import pytest
from cryptography.fernet import Fernet

from src.session import (
    clear_session,
    load_session,
    save_session,
)


SERVICE_NAME = "password_manager"
ACCOUNT_NAME = "session"


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

    mock_session_keyring("invalid json")

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
