import builtins
import dataclasses
import os

import pytest

from password_manager import postgres_storage, storage
from password_manager.cli import main


# users.json with bob and alice, alice logged in, and her vault.json: github (with a kept version) and gitlab
def build_json_files(monkeypatch):
    monkeypatch.setattr(builtins, "input", lambda prompt: "y")
    main(["register", "--username", "bob", "--password", "bob_secure_pass1"])
    main(["register", "--username", "alice", "--password", "alice_wonderland"])
    main(["login", "--username", "alice", "--password", "alice_wonderland"])
    main(["set", "github", "--password", "test-only-pass-1", "--login", "alice@example.com"])
    main(["set", "gitlab", "--password", "test-only-pass-2", "--tag", "work"])
    main(["set", "github", "--password", "test-only-pass-3"])


# The migration as it is run by hand: users.json and vault.json, built through the CLI, go into an empty database,
# alice's entries are verified with her session, and the counts are reported. Both JSON files stay byte for byte
# as they were, so the JSON backend keeps working whatever happens next. The passwords are test placeholders.
@pytest.mark.integration
def test_main_db_import_imports_verifies_and_reports_counts(set_test_env, postgres_database, monkeypatch, capsys):
    monkeypatch.setenv("PM_DATABASE_URL", postgres_database)
    build_json_files(monkeypatch)
    files = {name: open(os.path.join(set_test_env, name), "rb").read() for name in ("users.json", "vault.json")}
    capsys.readouterr()

    main(["db", "import"])

    assert capsys.readouterr().out == (
        "Imported into Postgres: 2 users, 2 entries, 1 kept versions\n"
        "Verified alice's entries: 3 of 3 decrypt identically from Postgres\n"
    )
    assert postgres_storage.load_vault() == storage.load_vault()
    assert {name: open(os.path.join(set_test_env, name), "rb").read() for name in files} == files


# What verification is for: a conversion that loses or alters a row. Here it drops gitlab and gives github__v1 the
# current github password; both labels are named, with the advice to stay on the JSON files, which are unchanged.
@pytest.mark.integration
def test_main_db_import_lists_the_labels_that_differ_in_postgres(set_test_env, postgres_database, monkeypatch, capsys):
    monkeypatch.setenv("PM_DATABASE_URL", postgres_database)
    build_json_files(monkeypatch)
    real_vault_to_rows = postgres_storage.vault_to_rows

    def faulty_vault_to_rows(vault):
        rows = real_vault_to_rows(vault)
        github = next(row for row in rows.entries if row.label == "github")
        return postgres_storage.VaultRows(
            entries=tuple(row for row in rows.entries if row.label != "gitlab"),
            tags=tuple(row for row in rows.tags if row.label != "gitlab"),
            history=tuple(dataclasses.replace(row, password=github.password) for row in rows.history),
        )

    monkeypatch.setattr(postgres_storage, "vault_to_rows", faulty_vault_to_rows)
    capsys.readouterr()

    main(["db", "import"])

    assert capsys.readouterr().out == (
        "Imported into Postgres: 2 users, 2 entries, 1 kept versions\n"
        "Verified alice's entries: 1 of 3 decrypt identically from Postgres\n"
        "Differs in Postgres: github__v1\n"
        "Differs in Postgres: gitlab\n"
        "Keep using the JSON files (leave PM_STORAGE unset); users.json and vault.json are unchanged\n"
    )


# import_json()'s refusals are messages, not tracebacks: a tagged kept version stops the import before it connects,
# the reason and its fix are printed, and the database and both JSON files are left exactly as they were
@pytest.mark.integration
def test_main_db_import_prints_import_jsons_refusal_and_writes_nothing(set_test_env, postgres_database, monkeypatch, capsys):
    monkeypatch.setenv("PM_DATABASE_URL", postgres_database)
    build_json_files(monkeypatch)
    main(["set", "github__v1", "--tag", "old"])
    files = {name: open(os.path.join(set_test_env, name), "rb").read() for name in ("users.json", "vault.json")}
    capsys.readouterr()

    main(["db", "import"])

    assert capsys.readouterr().out == (
        "Import failed: 'github__v1' is an old password version and has tags; "
        "remove them with `pm remove github__v1 --tag old` first\n"
    )
    assert postgres_storage.load_vault() == {}
    with postgres_storage.connect() as connection:
        assert postgres_storage.fetch_user(connection, "alice") is None
    assert {name: open(os.path.join(set_test_env, name), "rb").read() for name in files} == files
