import os
import pytest
import time
import json
from cryptography.fernet import Fernet, InvalidToken

from password_manager.session import (
    SessionLocked,
    clear_session,
    load_session,
    refresh_session,
    save_session,
)


@pytest.mark.unit
def test_save_session_sends_unlock_with_the_key_to_the_agent(set_test_env, fake_agent):
    key = Fernet.generate_key()

    save_session("testuser", key)

    assert fake_agent["calls"] == [
        ("start_agent", os.environ["PM_AGENT_SOCKET"]),
        ("send_request", os.environ["PM_AGENT_SOCKET"], {"cmd": "UNLOCK", "username": "testuser", "key": key.decode()}),
    ]


# Stands in for an agent function that fails outright
def raise_error(error):
    def fail(*args):
        raise error
    return fail


# The ways login can fail to hand the key to an agent: none can be started (the socket path is taken by
# something else), or the agent is gone before the UNLOCK arrives
def block_agent_start(monkeypatch):
    monkeypatch.setattr("password_manager.agent.start_agent", raise_error(OSError(98, "Address already in use")))


def lose_agent_before_unlock(monkeypatch):
    monkeypatch.setattr("password_manager.agent.send_request", lambda path, request_: None)


@pytest.mark.unit
@pytest.mark.parametrize("break_agent", [block_agent_start, lose_agent_before_unlock])
def test_save_session_reports_a_failed_login_when_the_agent_cannot_be_reached(set_test_env, monkeypatch, break_agent):
    break_agent(monkeypatch)

    # main() reports a ValueError from login as "Login failed: ..." and stops before any command runs
    with pytest.raises(ValueError, match="^could not start the session agent$"):
        save_session("testuser", Fernet.generate_key())


@pytest.mark.unit
def test_load_session_returns_the_username_and_an_agent_backed_cipher(set_test_env, fake_agent):
    key = Fernet.generate_key()
    save_session("testuser", key)

    username, cipher = load_session()

    assert username == "testuser"
    assert Fernet(key).decrypt(cipher.encrypt(b"secret")) == b"secret"
    assert cipher.decrypt(Fernet(key).encrypt(b"secret")) == b"secret"
    # Both went to the agent: a cipher holding the key itself would never send ENCRYPT or DECRYPT
    assert [call[2]["cmd"] for call in fake_agent["calls"][2:]] == ["STATUS", "ENCRYPT", "DECRYPT"]


@pytest.mark.unit
def test_agent_cipher_raises_invalid_token_for_a_token_the_agent_rejects(set_test_env):
    save_session("testuser", Fernet.generate_key())
    _, cipher = load_session()

    with pytest.raises(InvalidToken):
        cipher.decrypt(Fernet(Fernet.generate_key()).encrypt(b"secret"))


# The two ways the agent stops holding the key: it is locked but still answers, or it has exited
def lock_agent(monkeypatch):
    clear_session()


def stop_agent(monkeypatch):
    monkeypatch.setattr("password_manager.agent.send_request", lambda path, request_: None)


@pytest.mark.unit
@pytest.mark.parametrize("lose_key", [lock_agent, stop_agent])
@pytest.mark.parametrize("use_cipher", [
    lambda cipher, key: cipher.encrypt(b"secret"),
    lambda cipher, key: cipher.decrypt(Fernet(key).encrypt(b"secret")),
], ids=["encrypt", "decrypt"])
def test_agent_cipher_raises_session_locked_when_the_agent_no_longer_holds_the_key(set_test_env, monkeypatch, lose_key, use_cipher):
    key = Fernet.generate_key()
    save_session("testuser", key)
    _, cipher = load_session()
    lose_key(monkeypatch)

    with pytest.raises(SessionLocked):
        use_cipher(cipher, key)


@pytest.mark.unit
def test_load_session_returns_none_if_no_session(set_test_env):
    _ = set_test_env
    result = load_session()
    
    assert result is None


@pytest.mark.unit
def test_load_session_returns_none_when_no_agent_is_running(set_test_env, monkeypatch, capsys):
    monkeypatch.setattr("password_manager.agent.send_request", lambda path, request_: None)

    assert load_session() is None
    # Not logged in is a normal state, not an error: main() prints the login prompt
    assert capsys.readouterr().out == ""


@pytest.mark.unit
@pytest.mark.parametrize("error", [
    PermissionError(13, "Permission denied"),   # a socket owned by someone else
    TimeoutError("timed out"),                  # a stuck agent
    json.JSONDecodeError("Expecting value", "", 0),  # a garbled reply
], ids=["permission", "timeout", "garbled"])
def test_load_session_reports_an_error_and_returns_none_when_the_agent_cannot_be_asked(set_test_env, monkeypatch, capsys, error):
    monkeypatch.setattr("password_manager.agent.send_request", raise_error(error))

    assert load_session() is None
    assert capsys.readouterr().out.startswith("Error loading session:")


@pytest.mark.unit
def test_clear_session_deletes_keyring_entry(set_test_env):
    _ = set_test_env
    key = Fernet.generate_key()

    save_session("testuser", key)

    assert load_session() is not None

    clear_session()

    assert load_session() is None


@pytest.mark.unit
def test_clear_session_sends_lock_to_the_agent(set_test_env, fake_agent):
    clear_session()

    assert fake_agent["calls"] == [("send_request", os.environ["PM_AGENT_SOCKET"], {"cmd": "LOCK"})]


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
def test_load_session_returns_session_before_ttl(set_test_env, test_clock):
    _ = set_test_env
    key = Fernet.generate_key()
    save_session("testuser", key)
    
    test_clock[0] += 14 * 60

    result = load_session()

    assert result is not None

    username, _ = result
    assert username == "testuser"


@pytest.mark.unit
def test_load_session_returns_none_after_ttl(set_test_env, test_clock):
    _ = set_test_env
    key = Fernet.generate_key()
    save_session("testuser", key)

    test_clock[0] += 15 * 60

    assert load_session() is None


@pytest.mark.unit
def test_refresh_session_returns_false_if_no_session(set_test_env):
    _ = set_test_env
    assert refresh_session() is False


@pytest.mark.unit
def test_refresh_session_returns_false_on_invalid_session_data(set_test_env, mock_session_keyring):
    _ = set_test_env
    set_session, _ = mock_session_keyring

    set_session("invalid json")

    assert refresh_session() is False


@pytest.mark.unit
def test_refresh_session_preserves_fernet_key(set_test_env, test_clock):
    _ = set_test_env
    key = Fernet.generate_key()

    save_session("testuser", key)

    test_clock[0] += 5 * 60

    assert refresh_session() is True

    result = load_session()

    assert result is not None

    username, fernet = result

    assert username == "testuser"

    plaintext = b"important secret"
    encrypted = fernet.encrypt(plaintext)

    assert fernet.decrypt(encrypted) == plaintext
