import pytest

from password_manager.constants import get_data_dir, get_log, get_socket_path, get_users, get_vault


# Keep a PM_DATA_DIR exported in the developer's shell from leaking into these tests
@pytest.fixture(autouse=True)
def no_pm_data_dir(monkeypatch):
    monkeypatch.delenv("PM_DATA_DIR", raising=False)


@pytest.mark.unit
def test_get_data_dir_defaults_to_xdg_data_home(monkeypatch):
    monkeypatch.setenv("XDG_DATA_HOME", "/xdg/data")
    assert get_data_dir() == "/xdg/data/password_manager"


@pytest.mark.unit
def test_get_data_dir_falls_back_to_local_share_without_xdg_data_home(monkeypatch):
    monkeypatch.delenv("XDG_DATA_HOME", raising=False)
    monkeypatch.setenv("HOME", "/home/alice")
    assert get_data_dir() == "/home/alice/.local/share/password_manager"


@pytest.mark.unit
def test_get_data_dir_treats_empty_xdg_data_home_as_unset(monkeypatch):
    monkeypatch.setenv("XDG_DATA_HOME", "")
    monkeypatch.setenv("HOME", "/home/alice")
    assert get_data_dir() == "/home/alice/.local/share/password_manager"


@pytest.mark.unit
def test_get_data_dir_ignores_relative_xdg_data_home(monkeypatch):
    monkeypatch.setenv("XDG_DATA_HOME", "relative/data")
    monkeypatch.setenv("HOME", "/home/alice")
    assert get_data_dir() == "/home/alice/.local/share/password_manager"


@pytest.mark.unit
def test_get_data_dir_honors_pm_data_dir_override(monkeypatch):
    monkeypatch.setenv("PM_DATA_DIR", "/custom/pm")
    monkeypatch.setenv("XDG_DATA_HOME", "/xdg/data")
    assert get_data_dir() == "/custom/pm"


@pytest.mark.unit
def test_get_vault_resolves_vault_json_inside_data_dir(monkeypatch):
    monkeypatch.delenv("VAULT_FILE", raising=False)
    monkeypatch.setenv("PM_DATA_DIR", "/custom/pm")
    assert get_vault() == "/custom/pm/vault.json"


@pytest.mark.unit
def test_get_users_resolves_users_json_inside_data_dir(monkeypatch):
    monkeypatch.delenv("USERS_FILE", raising=False)
    monkeypatch.setenv("PM_DATA_DIR", "/custom/pm")
    assert get_users() == "/custom/pm/users.json"


@pytest.mark.unit
def test_get_log_resolves_vault_log_inside_data_dir(monkeypatch):
    monkeypatch.setenv("PM_DATA_DIR", "/custom/pm")
    assert get_log() == "/custom/pm/vault.log"


@pytest.mark.unit
def test_get_socket_path_uses_xdg_runtime_dir(monkeypatch):
    monkeypatch.delenv("PM_AGENT_SOCKET", raising=False)
    monkeypatch.setenv("XDG_RUNTIME_DIR", "/run/user/1000")
    assert get_socket_path() == "/run/user/1000/password_manager/agent.sock"


@pytest.mark.unit
@pytest.mark.parametrize("xdg_runtime_dir", [None, "", "relative/run"])
def test_get_socket_path_falls_back_to_the_data_dir_without_an_absolute_xdg_runtime_dir(monkeypatch, xdg_runtime_dir):
    monkeypatch.delenv("PM_AGENT_SOCKET", raising=False)
    monkeypatch.setenv("PM_DATA_DIR", "/custom/pm")
    if xdg_runtime_dir is None:
        monkeypatch.delenv("XDG_RUNTIME_DIR", raising=False)
    else:
        monkeypatch.setenv("XDG_RUNTIME_DIR", xdg_runtime_dir)
    assert get_socket_path() == "/custom/pm/agent.sock"
