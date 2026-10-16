import os
import socket
import stat

import pytest

from password_manager.agent import create_listener


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
