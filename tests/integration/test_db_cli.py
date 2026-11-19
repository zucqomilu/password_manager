import builtins
import dataclasses
import json
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


# The way back to JSON: after an import, a label saved under PM_STORAGE=postgres exists only in the database, and
# pm db export writes it out with the rest, next to users.json as the JSON backend holds it, both 0600
@pytest.mark.integration
def test_main_db_export_writes_json_files_to_the_given_directory(set_test_env, postgres_database, monkeypatch, capsys, tmp_path):
    monkeypatch.setenv("PM_DATABASE_URL", postgres_database)
    build_json_files(monkeypatch)
    main(["db", "import"])
    monkeypatch.setenv("PM_STORAGE", "postgres")
    main(["set", "mail", "--password", "test-only-pass-4"])
    export_dir = tmp_path / "export"
    export_dir.mkdir()
    capsys.readouterr()

    main(["db", "export", str(export_dir)])

    assert capsys.readouterr().out == f"Exported users.json and vault.json to {export_dir}\n"
    assert {path.name: os.stat(path).st_mode & 0o777 for path in export_dir.iterdir()} == {"users.json": 0o600, "vault.json": 0o600}
    assert json.loads((export_dir / "vault.json").read_text()) == postgres_storage.load_vault()
    assert "mail" in json.loads((export_dir / "vault.json").read_text())["alice"]
    assert json.loads((export_dir / "users.json").read_text()) == storage.load_users()


# export_json()'s refusal is a message, not a traceback: a directory that already has vault.json (here a stand-in,
# as the live data dir would have the real one) gets neither file, and the one there stays byte for byte as it was
@pytest.mark.integration
def test_main_db_export_prints_export_jsons_refusal_and_writes_nothing(set_test_env, postgres_database, monkeypatch, capsys, tmp_path):
    monkeypatch.setenv("PM_DATABASE_URL", postgres_database)
    build_json_files(monkeypatch)
    main(["db", "import"])
    export_dir = tmp_path / "export"
    export_dir.mkdir()
    (export_dir / "vault.json").write_text('{"existing": {}}')
    capsys.readouterr()

    main(["db", "export", str(export_dir)])

    assert capsys.readouterr().out == (
        f"Export failed: '{export_dir}' already has vault.json; export only into a directory without users.json or vault.json\n"
    )
    assert [path.name for path in export_dir.iterdir()] == ["vault.json"]
    assert (export_dir / "vault.json").read_text() == '{"existing": {}}'


# With PM_STORAGE=postgres and no server (conftest's PM_DATABASE_URL points at a socket dir nothing listens in), a
# command ends with what happened and how to reach the passwords through the JSON files, never a traceback; the
# database URL is not printed, and the JSON files are not touched
@pytest.mark.integration
def test_main_prints_fallback_instructions_when_postgres_is_unreachable(set_test_env, monkeypatch, capsys):
    build_json_files(monkeypatch)
    files = {name: open(os.path.join(set_test_env, name), "rb").read() for name in ("users.json", "vault.json")}
    monkeypatch.setenv("PM_STORAGE", "postgres")
    capsys.readouterr()

    main(["list"])

    assert capsys.readouterr().out == (
        "Could not reach the Postgres database; nothing was read or changed.\n"
        "To use the JSON files instead, run pm with PM_STORAGE unset. vault.json holds the vault as of pm db import;\n"
        "changes made under Postgres since then are only in the database.\n"
    )
    assert {name: open(os.path.join(set_test_env, name), "rb").read() for name in files} == files


# After pm rotate-key under Postgres, vault.json (frozen at pm db import) is under the old key while users.json and the
# session hold the new one, so "use the JSON files" would only give decryption errors. When the database is then
# unreachable, the fallback checks vault.json with the session key (labels only, nothing is printed decrypted) and,
# finding it under an older key, points to pm db export instead. The JSON files are not touched.
@pytest.mark.integration
def test_main_fallback_message_points_to_pm_db_export_when_vault_json_is_under_an_older_key(set_test_env, postgres_database, monkeypatch, capsys, tmp_path):
    monkeypatch.setenv("PM_DATABASE_URL", postgres_database)
    build_json_files(monkeypatch)
    main(["db", "import"])
    monkeypatch.setenv("PM_STORAGE", "postgres")
    main(["rotate-key", "--password", "alice_wonderland"])
    monkeypatch.setenv("PM_DATABASE_URL", f"postgresql:///password_manager?host={tmp_path}")
    files = {name: open(os.path.join(set_test_env, name), "rb").read() for name in ("users.json", "vault.json")}
    capsys.readouterr()

    main(["list"])

    assert capsys.readouterr().out == (
        "Could not reach the Postgres database; nothing was read or changed.\n"
        "vault.json is under an older data key (pm rotate-key ran after pm db import), so the JSON files cannot stand in\n"
        "for the database. Start the database and run pm db export to get JSON files under the current key.\n"
    )
    assert {name: open(os.path.join(set_test_env, name), "rb").read() for name in files} == files
