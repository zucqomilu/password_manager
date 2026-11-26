import pytest

from password_manager.constants import clipboard_timeout, get_data_dir, get_database_url, get_log, get_socket_path, get_users, get_vault


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


@pytest.mark.unit
def test_get_socket_path_honors_pm_agent_socket_override(monkeypatch):
    monkeypatch.setenv("PM_AGENT_SOCKET", "/custom/agent.sock")
    monkeypatch.setenv("XDG_RUNTIME_DIR", "/run/user/1000")
    assert get_socket_path() == "/custom/agent.sock"


# A local socket connection to a database of pm's own: no host, no password, so the default URL holds no secret and
# peer authentication as the logged-in user is what admits it
@pytest.mark.unit
def test_get_database_url_defaults_to_postgresql_password_manager(monkeypatch):
    monkeypatch.delenv("PM_DATABASE_URL", raising=False)
    assert get_database_url() == "postgresql:///password_manager"


# The URL is a secret once it holds a password, so it is read from the environment and never from a file in the repo
@pytest.mark.unit
def test_get_database_url_honors_pm_database_url_override(monkeypatch):
    monkeypatch.setenv("PM_DATABASE_URL", "postgresql://pm@db.example/vault")
    assert get_database_url() == "postgresql://pm@db.example/vault"


# A copied password is cleared from the clipboard after half a minute unless PM_CLIPBOARD_TIMEOUT says otherwise
@pytest.mark.unit
def test_clipboard_timeout_defaults_to_30_seconds(monkeypatch):
    monkeypatch.delenv("PM_CLIPBOARD_TIMEOUT", raising=False)
    assert clipboard_timeout() == 30


# PM_CLIPBOARD_TIMEOUT sets how many seconds a copied password stays on the clipboard
@pytest.mark.unit
def test_clipboard_timeout_reads_pm_clipboard_timeout(monkeypatch):
    monkeypatch.setenv("PM_CLIPBOARD_TIMEOUT", "45")
    assert clipboard_timeout() == 45


# A typo in PM_CLIPBOARD_TIMEOUT must never break pm get or leave the password on the clipboard for good
@pytest.mark.unit
@pytest.mark.parametrize("value", ["abc", "", "-5", "1.5", " "])
def test_clipboard_timeout_falls_back_to_default_for_invalid_or_negative_value(monkeypatch, value):
    monkeypatch.setenv("PM_CLIPBOARD_TIMEOUT", value)
    assert clipboard_timeout() == 30


# PM_CLIPBOARD_TIMEOUT=0 turns clearing off: the copied password stays on the clipboard until something replaces it
@pytest.mark.unit
def test_clipboard_timeout_returns_0_when_pm_clipboard_timeout_is_0(monkeypatch):
    monkeypatch.setenv("PM_CLIPBOARD_TIMEOUT", "0")
    assert clipboard_timeout() == 0
