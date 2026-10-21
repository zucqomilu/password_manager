import os
import time
from unittest.mock import patch

import pytest

from password_manager.agent import send_request
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
