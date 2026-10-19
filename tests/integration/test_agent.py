import os
import socket
import stat
import threading

import pytest
from cryptography.fernet import Fernet

from password_manager.agent import create_listener, decode_message, encode_message, read_message, run_agent


# One request over a fresh connection, the way pm will talk to the agent
def ask(socket_path, request_):
    with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as client:
        client.settimeout(5)
        client.connect(str(socket_path))
        client.sendall(encode_message(request_))
        return decode_message(read_message(client))


@pytest.mark.integration
def test_create_listener_creates_the_socket_dir_with_0700_and_the_socket_with_0600(tmp_path):
    socket_path = tmp_path / "run" / "agent.sock"
    listener = create_listener(str(socket_path))
    try:
        assert stat.S_IMODE(os.stat(socket_path.parent).st_mode) == 0o700
        assert stat.S_ISSOCK(os.stat(socket_path).st_mode)
        assert stat.S_IMODE(os.stat(socket_path).st_mode) == 0o600
    finally:
        listener.close()


@pytest.mark.integration
def test_create_listener_replaces_a_stale_socket_file_left_by_a_dead_agent(tmp_path):
    socket_path = tmp_path / "run" / "agent.sock"
    # Closing without unlinking leaves the socket file behind, like an agent killed with kill -9
    create_listener(str(socket_path)).close()
    listener = create_listener(str(socket_path))
    try:
        with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as client:
            client.connect(str(socket_path))
    finally:
        listener.close()


@pytest.mark.integration
def test_create_listener_leaves_a_live_agents_socket_in_place(tmp_path):
    socket_path = tmp_path / "run" / "agent.sock"
    listener = create_listener(str(socket_path))
    try:
        with pytest.raises(OSError, match="Address already in use"):
            create_listener(str(socket_path))
        # The running agent still answers on its own socket
        with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as client:
            client.connect(str(socket_path))
            listener.accept()[0].close()
    finally:
        listener.close()


@pytest.mark.integration
@pytest.mark.parametrize("make_path", [
    lambda socket_path, target: socket_path.write_text("not a socket"),
    lambda socket_path, target: socket_path.symlink_to(target),
], ids=["regular file", "symlink"])
def test_create_listener_never_removes_a_file_that_is_not_a_socket(tmp_path, make_path):
    socket_path = tmp_path / "run" / "agent.sock"
    socket_path.parent.mkdir()
    target = tmp_path / "target.txt"
    target.write_text("keep me")
    make_path(socket_path, target)
    with pytest.raises(OSError, match="Address already in use"):
        create_listener(str(socket_path))
    assert os.path.lexists(socket_path)
    assert target.read_text() == "keep me"


@pytest.mark.integration
def test_run_agent_answers_requests_until_lock_then_removes_its_socket_and_returns(tmp_path):
    socket_path = tmp_path / "run" / "agent.sock"
    # daemon=True so a run_agent that never returns cannot hang the suite
    agent = threading.Thread(target=run_agent, args=(create_listener(str(socket_path)),), daemon=True)
    agent.start()
    assert ask(socket_path, {"cmd": "UNLOCK", "username": "alice", "key": Fernet.generate_key().decode()}) == {"ok": True}
    token = ask(socket_path, {"cmd": "ENCRYPT", "plaintext": "test-only-pass-1"})["token"]
    assert ask(socket_path, {"cmd": "DECRYPT", "token": token}) == {"ok": True, "plaintext": "test-only-pass-1"}
    assert ask(socket_path, {"cmd": "LOCK"}) == {"ok": True, "shutdown": True}
    agent.join(timeout=5)
    assert not agent.is_alive()
    assert not os.path.lexists(socket_path)


@pytest.mark.integration
def test_run_agent_exits_when_no_unlock_arrives_within_session_ttl(tmp_path, monkeypatch):
    # An agent spawned by a login that then failed must not wait forever for a key that never comes
    monkeypatch.setattr("password_manager.agent.SESSION_TTL", 0.2)
    socket_path = tmp_path / "run" / "agent.sock"
    agent = threading.Thread(target=run_agent, args=(create_listener(str(socket_path)),), daemon=True)
    agent.start()
    agent.join(timeout=5)
    assert not agent.is_alive()
    assert not os.path.lexists(socket_path)
