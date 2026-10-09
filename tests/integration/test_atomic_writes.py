import json
import os

import pytest

from password_manager.storage import save_users, save_vault


# Record (temp file folder, target) for every os.replace call, while still doing the real rename
@pytest.fixture
def replace_calls(monkeypatch):
    real_replace = os.replace
    calls = []

    def recording_replace(src, dst):
        calls.append((os.path.dirname(src), dst))
        real_replace(src, dst)

    monkeypatch.setattr(os, "replace", recording_replace)
    return calls


@pytest.mark.integration
def test_save_vault_writes_via_temp_file_and_os_replace(set_test_env, replace_calls, valid_vault):
    save_vault(valid_vault)

    assert replace_calls == [(set_test_env, os.environ["VAULT_FILE"])]
    assert os.listdir(set_test_env) == ["vault.json"]
    with open(os.environ["VAULT_FILE"]) as f:
        assert json.load(f) == valid_vault


@pytest.mark.integration
def test_save_vault_leaves_original_vault_intact_when_write_fails(set_test_env, monkeypatch, valid_vault):
    save_vault(valid_vault)

    def failing_fsync(fd):
        raise OSError("No space left on device")

    monkeypatch.setattr(os, "fsync", failing_fsync)
    with pytest.raises(OSError):
        save_vault({"alice": {}})

    assert os.listdir(set_test_env) == ["vault.json"]
    with open(os.environ["VAULT_FILE"]) as f:
        assert json.load(f) == valid_vault


@pytest.mark.integration
def test_save_users_writes_via_temp_file_and_os_replace(set_test_env, replace_calls, valid_user):
    save_users(valid_user)

    assert replace_calls == [(set_test_env, os.environ["USERS_FILE"])]
    assert os.listdir(set_test_env) == ["users.json"]
    with open(os.environ["USERS_FILE"]) as f:
        assert json.load(f) == valid_user
