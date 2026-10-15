import pytest
from cryptography.fernet import Fernet

from password_manager.agent import AgentState, handle_request


@pytest.mark.unit
def test_handle_request_unlock_stores_the_username_and_key_in_the_returned_state():
    key = Fernet.generate_key()
    state, response = handle_request(AgentState(), {"cmd": "UNLOCK", "username": "alice", "key": key.decode()}, now=1000.0)
    assert response == {"ok": True}
    assert state == AgentState(username="alice", key=key, last_activity=1000.0)
