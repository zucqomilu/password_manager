import os
import threading
import time
from unittest.mock import patch

import pytest

from password_manager.agent import create_listener, run_agent, send_request
from password_manager.cli import main


# Files and agent socket in a throwaway dir, with a real agent daemon instead of the fake one set_test_env gives.
# Whatever the test does, the agent is sent LOCK at the end, so no daemon outlives it.
@pytest.fixture
def real_agent_socket(tmp_path, monkeypatch):
    socket_path = str(tmp_path / "run" / "agent.sock")
    monkeypatch.setenv("VAULT_FILE", str(tmp_path / "vault.json"))
    monkeypatch.setenv("USERS_FILE", str(tmp_path / "users.json"))
    monkeypatch.setenv("PM_AGENT_SOCKET", socket_path)
    yield socket_path
    send_request(socket_path, {"cmd": "LOCK"})


# The agent removes its socket on its way out, just after it has answered the LOCK
def wait_for_removal(path, timeout=2):
    deadline = time.monotonic() + timeout
    while os.path.exists(path) and time.monotonic() < deadline:
        time.sleep(0.01)
    return not os.path.exists(path)


@pytest.mark.integration
def test_login_starts_the_agent_set_and_get_work_logout_stops_it(real_agent_socket, capsys, tmp_path):
    main(["register", "--username", "alice", "--password", "correct horse battery"])
    main(["login", "--username", "alice", "--password", "correct horse battery"])
    assert send_request(real_agent_socket, {"cmd": "STATUS"})["username"] == "alice"

    main(["set", "github", "--password", "supersecurepass1"])
    with patch("password_manager.core.pyperclip.copy"):
        main(["get", "github", "--show"])
    assert "Password: supersecurepass1" in capsys.readouterr().out
    # Encrypted by the agent: the vault on disk never holds the plaintext
    assert "supersecurepass1" not in (tmp_path / "vault.json").read_text()

    main(["logout"])
    assert capsys.readouterr().out == "Session cleared.\n"
    assert wait_for_removal(real_agent_socket)
    assert send_request(real_agent_socket, {"cmd": "STATUS"}) is None


# The agent runs in a thread here, not as a daemon, so test_clock's frozen time.time() is the clock it checks the TTL
# against: the full 15 minutes pass in an instant, with no sleep and no shortened TTL.
@pytest.mark.integration
def test_the_agent_expires_after_the_ttl_and_get_asks_for_login(real_agent_socket, test_clock, capsys):
    agent_thread = threading.Thread(target=run_agent, args=(create_listener(real_agent_socket),), daemon=True)
    agent_thread.start()
    main(["register", "--username", "alice", "--password", "correct horse battery"])
    main(["login", "--username", "alice", "--password", "correct horse battery"])
    main(["set", "github", "--password", "supersecurepass1"])
    capsys.readouterr()

    test_clock[0] += 15 * 60
    with patch("password_manager.core.pyperclip.copy") as mock_copy:
        main(["get", "github", "--show"])

    assert capsys.readouterr().out == "You are not logged in. Please run `login` first.\n"
    mock_copy.assert_not_called()
    # The login reused this agent instead of spawning a daemon, so the thread is what held the key
    send_request(real_agent_socket, {"cmd": "LOCK"})
    agent_thread.join(timeout=2)
    assert not agent_thread.is_alive()


# Nothing arrives after the login, so only the agent's own accept timeout can end it. A thread again, with the TTL
# patched down to a second; the register runs first, so the locked agent's wait for UNLOCK is not part of the test.
@pytest.mark.integration
def test_an_idle_agent_exits_after_the_ttl_without_receiving_any_request(real_agent_socket, monkeypatch, capsys):
    monkeypatch.setattr("password_manager.agent.SESSION_TTL", 1.0)
    main(["register", "--username", "alice", "--password", "correct horse battery"])
    agent_thread = threading.Thread(target=run_agent, args=(create_listener(real_agent_socket),), daemon=True)
    agent_thread.start()
    main(["login", "--username", "alice", "--password", "correct horse battery"])
    capsys.readouterr()
    assert agent_thread.is_alive()

    agent_thread.join(timeout=3)

    # Gone on its own: the key has left memory and the socket is removed, with no LOCK and no request at all
    assert not agent_thread.is_alive()
    assert not os.path.exists(real_agent_socket)
    main(["get", "github"])
    assert capsys.readouterr().out == "You are not logged in. Please run `login` first.\n"
