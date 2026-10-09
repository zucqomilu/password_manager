import builtins

import pytest

from password_manager.cli import main


@pytest.mark.integration
def test_verify_passes_on_vault_built_through_cli(set_test_env, monkeypatch, capsys):
    monkeypatch.setattr(builtins, "input", lambda prompt: "y")

    main(["register", "--username", "alice", "--password", "alice_wonderland"])
    main(["login", "--username", "alice", "--password", "alice_wonderland"])
    main(["set", "github", "--password", "test-only-pass-1", "--login", "alice@example.com"])
    main(["set", "gitlab", "--password", "test-only-pass-2", "--tag", "work"])
    main(["set", "github", "--password", "test-only-pass-3"])
    capsys.readouterr()

    main(["verify"])

    assert capsys.readouterr().out == "3 entries OK\n"
