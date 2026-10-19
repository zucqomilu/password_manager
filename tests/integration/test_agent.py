import os
import socket
import stat
import threading
import time

import pytest
from cryptography.fernet import Fernet

from password_manager.agent import (
    create_listener, decode_message, encode_message, read_message, run_agent, send_request, start_agent,
)


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


@pytest.mark.integration
def test_run_agent_exits_at_the_ttl_even_while_requests_that_do_not_refresh_the_session_keep_arriving(
    tmp_path, monkeypatch,
):
    monkeypatch.setattr("password_manager.agent.SESSION_TTL", 1.0)
    socket_path = tmp_path / "run" / "agent.sock"
    agent = threading.Thread(target=run_agent, args=(create_listener(str(socket_path)),), daemon=True)
    agent.start()
    assert ask(socket_path, {"cmd": "UNLOCK", "username": "alice", "key": Fernet.generate_key().decode()}) == {"ok": True}
    # STATUS at about 0.3, 0.6 and 0.9 s: each is answered, but none refreshes the session
    for _ in range(3):
        time.sleep(0.3)
        assert ask(socket_path, {"cmd": "STATUS"})["ok"] is True
    # The key expires 1 s after UNLOCK; a wait that restarts after every connection would run until about 1.9 s
    agent.join(timeout=0.5)
    assert not agent.is_alive()
    assert not os.path.lexists(socket_path)


@pytest.mark.integration
@pytest.mark.parametrize("leave_stale_socket", [False, True], ids=["no socket file", "stale socket file"])
def test_send_request_returns_none_when_no_agent_is_listening(tmp_path, leave_stale_socket):
    socket_path = tmp_path / "run" / "agent.sock"
    if leave_stale_socket:
        # Closed without unlinking, like an agent killed with kill -9
        create_listener(str(socket_path)).close()
    assert send_request(str(socket_path), {"cmd": "STATUS"}) is None


@pytest.mark.integration
def test_send_request_returns_the_agents_response(tmp_path):
    socket_path = tmp_path / "run" / "agent.sock"
    agent = threading.Thread(target=run_agent, args=(create_listener(str(socket_path)),), daemon=True)
    agent.start()
    try:
        assert send_request(str(socket_path), {"cmd": "UNLOCK", "username": "alice", "key": Fernet.generate_key().decode()}) == {"ok": True}
        assert send_request(str(socket_path), {"cmd": "STATUS"})["username"] == "alice"
    finally:
        # Stop the agent through its own socket, so no thread is left behind even when an assert fails
        ask(socket_path, {"cmd": "LOCK"})
        agent.join(timeout=5)


@pytest.mark.integration
def test_start_agent_spawns_a_detached_daemon_when_no_agent_is_reachable(tmp_path):
    socket_path = str(tmp_path / "run" / "agent.sock")
    pid = start_agent(socket_path)
    try:
        # Answers straight away, with no polling, and holds no key until UNLOCK
        assert send_request(socket_path, {"cmd": "STATUS"}) == {"ok": False, "error": "locked"}
        # A separate process that leads its own session, so closing the terminal does not take it down
        assert pid != os.getpid()
        assert os.getsid(pid) == pid
    finally:
        send_request(socket_path, {"cmd": "LOCK"})


@pytest.mark.integration
def test_start_agent_reuses_an_already_running_agent(tmp_path):
    socket_path = str(tmp_path / "run" / "agent.sock")
    start_agent(socket_path)
    try:
        assert send_request(socket_path, {"cmd": "UNLOCK", "username": "alice", "key": Fernet.generate_key().decode()}) == {"ok": True}
        assert start_agent(socket_path) is None
        # Still the same agent, still holding the session: a second login must not replace it or drop its key
        assert send_request(socket_path, {"cmd": "STATUS"})["username"] == "alice"
    finally:
        send_request(socket_path, {"cmd": "LOCK"})
