import os
import stat

import pytest

from password_manager.cli import main
from password_manager.constants import ensure_data_dir


@pytest.mark.integration
def test_ensure_data_dir_creates_data_dir_with_0700_permissions(monkeypatch, tmp_path):
    monkeypatch.setenv("PM_DATA_DIR", str(tmp_path / "pm"))
    ensure_data_dir()
    assert stat.S_IMODE(os.stat(tmp_path / "pm").st_mode) == 0o700


@pytest.mark.integration
def test_ensure_data_dir_tightens_existing_data_dir_to_0700(monkeypatch, tmp_path):
    (tmp_path / "pm").mkdir()
    os.chmod(tmp_path / "pm", 0o755)
    monkeypatch.setenv("PM_DATA_DIR", str(tmp_path / "pm"))
    ensure_data_dir()
    assert stat.S_IMODE(os.stat(tmp_path / "pm").st_mode) == 0o700


@pytest.mark.integration
def test_register_login_set_get_round_trip_in_pm_data_dir(set_test_env, monkeypatch, tmp_path, capsys):
    monkeypatch.delenv("VAULT_FILE")
    monkeypatch.delenv("USERS_FILE")
    monkeypatch.setenv("PM_DATA_DIR", str(tmp_path / "pm"))
    # A real pm process creates the data dir when it imports the logger; this test runs in-process
    ensure_data_dir()

    main(["register", "--username", "alice", "--password", "alice_wonderland"])
    main(["login", "--username", "alice", "--password", "alice_wonderland"])
    main(["set", "github", "--password", "test-only-pass-1"])
    main(["get", "github", "--show"])

    assert "Password: test-only-pass-1" in capsys.readouterr().out
    assert sorted(path.name for path in (tmp_path / "pm").iterdir()) == ["users.json", "vault.json"]
