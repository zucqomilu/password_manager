import json
import os

import pytest

from password_manager.storage import save_vault


@pytest.mark.integration
def test_save_vault_writes_via_temp_file_and_os_replace(set_test_env, monkeypatch, valid_vault):
    real_replace = os.replace
    replace_calls = []

    def recording_replace(src, dst):
        replace_calls.append((os.path.dirname(src), dst))
        real_replace(src, dst)

    monkeypatch.setattr(os, "replace", recording_replace)
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
