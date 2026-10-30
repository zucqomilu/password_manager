import builtins
import os

import pytest

from password_manager import postgres_storage, storage
from password_manager.cli import main


# The migration as it is run by hand: users.json and vault.json, built through the CLI, go into an empty database,
# alice's entries are verified with her session, and the counts are reported. Both JSON files stay byte for byte
# as they were, so the JSON backend keeps working whatever happens next. The passwords are test placeholders.
@pytest.mark.integration
def test_main_db_import_imports_verifies_and_reports_counts(set_test_env, postgres_database, monkeypatch, capsys):
    monkeypatch.setenv("PM_DATABASE_URL", postgres_database)
    monkeypatch.setattr(builtins, "input", lambda prompt: "y")
    main(["register", "--username", "bob", "--password", "bob_secure_pass1"])
    main(["register", "--username", "alice", "--password", "alice_wonderland"])
    main(["login", "--username", "alice", "--password", "alice_wonderland"])
    main(["set", "github", "--password", "test-only-pass-1", "--login", "alice@example.com"])
    main(["set", "gitlab", "--password", "test-only-pass-2", "--tag", "work"])
    main(["set", "github", "--password", "test-only-pass-3"])
    files = {name: open(os.path.join(set_test_env, name), "rb").read() for name in ("users.json", "vault.json")}
    capsys.readouterr()

    main(["db", "import"])

    assert capsys.readouterr().out == (
        "Imported into Postgres: 2 users, 2 entries, 1 kept versions\n"
        "Verified alice's entries: 3 of 3 decrypt identically from Postgres\n"
    )
    assert postgres_storage.load_vault() == storage.load_vault()
    assert {name: open(os.path.join(set_test_env, name), "rb").read() for name in files} == files
