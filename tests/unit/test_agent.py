import pytest
from cryptography.fernet import Fernet

from password_manager.agent import AgentState, handle_request


@pytest.mark.unit
def test_handle_request_unlock_stores_the_username_and_key_in_the_returned_state():
    key = Fernet.generate_key()
    state, response = handle_request(AgentState(), {"cmd": "UNLOCK", "username": "alice", "key": key.decode()}, now=1000.0)
    assert response == {"ok": True}
    assert state == AgentState(username="alice", key=key, last_activity=1000.0)


@pytest.mark.unit
def test_agent_state_repr_never_shows_the_key():
    key = Fernet.generate_key()
    assert key.decode() not in repr(AgentState(username="alice", key=key, last_activity=1000.0))


@pytest.mark.unit
def test_handle_request_encrypt_returns_ciphertext_the_held_key_can_decrypt():
    key = Fernet.generate_key()
    _, response = handle_request(AgentState(username="alice", key=key, last_activity=1000.0), {"cmd": "ENCRYPT", "plaintext": "test-only-pass-1"}, now=1001.0)
    assert response["ok"] is True
    assert Fernet(key).decrypt(response["token"].encode()) == b"test-only-pass-1"


@pytest.mark.unit
def test_handle_request_decrypt_returns_plaintext_for_a_valid_token():
    key = Fernet.generate_key()
    token = Fernet(key).encrypt(b"test-only-pass-1").decode()
    _, response = handle_request(AgentState(username="alice", key=key, last_activity=1000.0), {"cmd": "DECRYPT", "token": token}, now=1001.0)
    assert response == {"ok": True, "plaintext": "test-only-pass-1"}


@pytest.mark.unit
@pytest.mark.parametrize("token", [
    Fernet(Fernet.generate_key()).encrypt(b"test-only-pass-1").decode(),
    "not-a-token",
], ids=["token from another key", "garbage"])
def test_handle_request_decrypt_returns_an_error_for_an_invalid_token(token):
    state = AgentState(username="alice", key=Fernet.generate_key(), last_activity=1000.0)
    assert handle_request(state, {"cmd": "DECRYPT", "token": token}, now=1001.0) == (state, {"ok": False, "error": "invalid token"})


@pytest.mark.unit
@pytest.mark.parametrize("request_", [
    {"cmd": "ENCRYPT", "plaintext": "test-only-pass-1"},
    {"cmd": "DECRYPT", "token": Fernet(Fernet.generate_key()).encrypt(b"test-only-pass-1").decode()},
], ids=["ENCRYPT", "DECRYPT"])
def test_handle_request_returns_locked_for_encrypt_and_decrypt_when_no_key_is_held(request_):
    assert handle_request(AgentState(), request_, now=1000.0) == (AgentState(), {"ok": False, "error": "locked"})
