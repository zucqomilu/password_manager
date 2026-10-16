import os
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
