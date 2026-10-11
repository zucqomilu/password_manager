import builtins
import glob
import json
import os

import pytest

from password_manager.cli import main


@pytest.mark.integration
def test_deleted_label_disappears_from_list_and_get_but_remains_in_backup(set_test_env, monkeypatch, capsys):
    monkeypatch.setattr(builtins, "input", lambda prompt: "y")

    main(["register", "--username", "alice", "--password", "alice_wonderland"])
    main(["login", "--username", "alice", "--password", "alice_wonderland"])
    main(["set", "github", "--password", "test-only-pass-1", "--login", "alice@example.com"])
    main(["set", "gitlab", "--password", "test-only-pass-2"])
    main(["delete", "github"])
    capsys.readouterr()

    main(["list"])
    main(["get", "github"])

    assert capsys.readouterr().out == "Stored labels:\n- gitlab\nNo password found for 'github'.\n"
    [backup] = glob.glob(os.path.join(set_test_env, "vault_backup_*.json"))
    with open(backup) as f:
        assert json.load(f)["alice"].keys() == {"github", "gitlab"}
