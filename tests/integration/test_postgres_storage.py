import base64
import json
import os
import re

import psycopg
import pytest

from cryptography.fernet import Fernet

from password_manager import storage
from password_manager.postgres_storage import (
    EntryRow, UserRow, apply_migrations, backup_vault, connect, export_json, fetch_entry, fetch_user, import_json, insert_user,
    load_vault, save_vault, upsert_entry, user_record_to_row, verify_import,
)
from password_manager.user import authenticate_user


# A placeholder in the shape validate_vault() accepts for a Fernet token (url-safe base64); it encrypts nothing
def token(name):
    return base64.urlsafe_b64encode(name.encode()).decode()


# A migrated connection with one user, alice, for the entry tests; the user fields are placeholders, never a real key
@pytest.fixture
def connection(postgres_database):
    with psycopg.connect(postgres_database) as connection:
        apply_migrations(connection)
        insert_user(connection, UserRow("alice", "salt", 2, 64, 2, "wrapped"))
        yield connection


# The four tables the rows map to, plus the table that records which migrations have run
@pytest.mark.integration
def test_apply_migrations_creates_the_schema_on_an_empty_database(postgres_database):
    with psycopg.connect(postgres_database) as connection:
        apply_migrations(connection)
        tables = {row[0] for row in connection.execute(
            "SELECT table_name FROM information_schema.tables WHERE table_schema = 'public'")}
        versions = [row[0] for row in connection.execute("SELECT version FROM schema_migrations ORDER BY version")]
    assert tables == {"users", "entries", "tags", "password_history", "schema_migrations"}
    assert versions == [1]


# pm migrates on every connection, so a second run must leave the schema and the stored rows exactly as they were
@pytest.mark.integration
def test_apply_migrations_is_a_no_op_when_the_schema_is_current(postgres_database):
    with psycopg.connect(postgres_database) as connection:
        apply_migrations(connection)
        connection.execute("INSERT INTO users VALUES ('alice', 'salt', 2, 64, 2, 'wrapped')")
        apply_migrations(connection)
        users = connection.execute("SELECT username FROM users").fetchall()
        versions = [row[0] for row in connection.execute("SELECT version FROM schema_migrations")]
    assert users == [("alice",)]
    assert versions == [1]


# A real v2 record (the fixture's tiny Argon2id costs) goes in as a row and comes back field for field, so login can
# unwrap the data key from what Postgres returns. A username with no row gives None, as load_users() gives no record.
@pytest.mark.integration
def test_insert_user_and_fetch_user_round_trip_a_user(postgres_database, make_v2_user):
    row = user_record_to_row("alice", make_v2_user()["alice"])
    with psycopg.connect(postgres_database) as connection:
        apply_migrations(connection)
        insert_user(connection, row)
        assert fetch_user(connection, "alice") == row
        assert fetch_user(connection, "bob") is None


# A new label becomes an entry row holding the Fernet tokens as given; a label never stored gives None
@pytest.mark.integration
def test_upsert_entry_creates_an_entry_that_fetch_entry_returns(connection):
    upsert_entry(connection, EntryRow("alice", "github", "token-pw-1", "token-login"))
    assert fetch_entry(connection, "alice", "github") == EntryRow("alice", "github", "token-pw-1", "token-login")
    assert fetch_entry(connection, "alice", "gitlab") is None


# pm's one way in: the database PM_DATABASE_URL names, already migrated, so every command sees the current schema
@pytest.mark.integration
def test_connect_opens_get_database_url_and_applies_the_migrations(postgres_database, monkeypatch):
    monkeypatch.setenv("PM_DATABASE_URL", postgres_database)
    with connect() as connection:
        database = connection.execute("SELECT current_database()").fetchone()[0]
        versions = [row[0] for row in connection.execute("SELECT version FROM schema_migrations")]
    assert postgres_database.startswith(f"postgresql:///{database}?")
    assert versions == [1]


# The Storage pair core.py calls. Users stay in users.json, so the vault's users have no rows in the users table.
# Two users, ordered tags, a label past __v9 and versions whose label was deleted all come back exactly.
@pytest.mark.integration
def test_save_vault_stores_a_vault_that_load_vault_returns_unchanged(postgres_database, monkeypatch):
    monkeypatch.setenv("PM_DATABASE_URL", postgres_database)
    vault = {
        "alice": {
            "github": {"password": token("pw-12"), "login": token("login-1"), "tags": ["work", "dev", "code"]},
            **{f"github__v{version}": {"password": token(f"pw-{version}"), "login": token("login-1")} for version in range(1, 12)},
            "mail": {"password": token("pw-20"), "tags": ["personal"]},
            "old-bank__v1": {"password": token("pw-30")},
        },
        "bob": {"bank": {"password": token("pw-40"), "login": token("login-3")}},
    }
    save_vault(vault)
    assert load_vault() == vault


# pm delete hands save_vault() a vault without the label: it must be gone from Postgres too, with its tags, while the
# label's kept versions stay as long as the vault still has them
@pytest.mark.integration
def test_save_vault_removes_labels_that_are_no_longer_in_the_vault(postgres_database, monkeypatch):
    monkeypatch.setenv("PM_DATABASE_URL", postgres_database)
    save_vault({"alice": {
        "github": {"password": token("pw-2"), "tags": ["work"]},
        "github__v1": {"password": token("pw-1")},
        "mail": {"password": token("pw-3")},
    }})
    save_vault({"alice": {"github__v1": {"password": token("pw-1")}, "mail": {"password": token("pw-3")}}})
    assert load_vault() == {"alice": {"github__v1": {"password": token("pw-1")}, "mail": {"password": token("pw-3")}}}


# A vault can pass validate_vault() and still break a table rule: a __v0 label hits the history version check only
# after the old rows are deleted and the new entries inserted. The error reaches the caller, and every old row is
# still there, as a failed write of vault.json leaves the old file.
@pytest.mark.integration
def test_save_vault_rolls_back_entirely_when_a_row_fails(postgres_database, monkeypatch):
    monkeypatch.setenv("PM_DATABASE_URL", postgres_database)
    stored = {"alice": {"github": {"password": token("pw-2"), "tags": ["work"]}, "github__v1": {"password": token("pw-1")}}}
    save_vault(stored)
    with pytest.raises(psycopg.errors.CheckViolation):
        save_vault({"alice": {"mail": {"password": token("pw-3"), "tags": ["home"]}, "github__v0": {"password": token("pw-0")}}})
    assert load_vault() == stored


# A database pm has never written to, not even migrated, reads as an empty vault, as a missing vault.json does,
# so the first pm set on Postgres starts from nothing instead of failing
@pytest.mark.integration
def test_load_vault_returns_an_empty_dict_for_an_empty_database(postgres_database, monkeypatch):
    monkeypatch.setenv("PM_DATABASE_URL", postgres_database)
    assert load_vault() == {}


# What pm delete and an overwrite rely on: before the rows change, the stored vault is written to a vault_backup_*.json
# next to where vault.json lives, readable by the JSON backend and as private as vault.json (0600)
@pytest.mark.integration
def test_backup_vault_writes_a_vault_backup_json_of_the_stored_vault(postgres_database, monkeypatch, tmp_path):
    monkeypatch.setenv("PM_DATABASE_URL", postgres_database)
    monkeypatch.setenv("VAULT_FILE", str(tmp_path / "vault.json"))
    stored = {"alice": {"github": {"password": token("pw-2"), "tags": ["work"]}, "github__v1": {"password": token("pw-1")}}}
    save_vault(stored)
    backup_vault()
    backups = list(tmp_path.glob("vault_backup_*.json"))
    assert len(backups) == 1
    assert json.loads(backups[0].read_text()) == stored
    assert os.stat(backups[0]).st_mode & 0o777 == 0o600


# The migration itself: users.json and vault.json as loaded go into an empty database, every user record field for
# field (real v2 records, the fixture's tiny Argon2id costs) and the vault with its tags and kept versions unchanged
@pytest.mark.integration
def test_import_json_imports_users_entries_tags_and_history_in_one_transaction(postgres_database, monkeypatch, make_v2_user):
    monkeypatch.setenv("PM_DATABASE_URL", postgres_database)
    users = {**make_v2_user("alice"), **make_v2_user("bob", salt=b"abcdefghijklmnop")}
    vault = {
        "alice": {
            "github": {"password": token("pw-2"), "login": token("login-1"), "tags": ["work", "dev"]},
            "github__v1": {"password": token("pw-1"), "login": token("login-1")},
            "old-bank__v1": {"password": token("pw-3")},
        },
        "bob": {"bank": {"password": token("pw-4")}},
    }
    import_json(users, vault)
    assert load_vault() == vault
    with connect() as connection:
        assert fetch_user(connection, "alice") == user_record_to_row("alice", users["alice"])
        assert fetch_user(connection, "bob") == user_record_to_row("bob", users["bob"])


# All or nothing: the users and entries go in first, then a history row the schema rejects (version 0) fails the
# import, and nothing it wrote is left behind, so a retry after fixing vault.json starts from an empty database again
@pytest.mark.integration
def test_import_json_rolls_back_entirely_on_failure(postgres_database, monkeypatch, make_v2_user):
    monkeypatch.setenv("PM_DATABASE_URL", postgres_database)
    users = {**make_v2_user("alice"), **make_v2_user("bob", salt=b"abcdefghijklmnop")}
    vault = {"alice": {"github": {"password": token("pw-2"), "tags": ["work"]}, "github__v0": {"password": token("pw-1")}}}
    with pytest.raises(psycopg.errors.CheckViolation):
        import_json(users, vault)
    assert load_vault() == {}
    with connect() as connection:
        assert fetch_user(connection, "alice") is None
        assert fetch_user(connection, "bob") is None


# An import never merges: bob's rows would not collide with alice's, so only the check stops them mixing into an
# existing vault. The refusal leaves the database exactly as it was.
@pytest.mark.integration
def test_import_json_refuses_to_import_into_a_non_empty_database(postgres_database, monkeypatch, make_v2_user):
    monkeypatch.setenv("PM_DATABASE_URL", postgres_database)
    vault = {"alice": {"github": {"password": token("pw-1")}}}
    import_json(make_v2_user("alice"), vault)
    with pytest.raises(ValueError, match=r"^The database already holds a vault; pm db import only fills an empty database$"):
        import_json(make_v2_user("bob"), {"bob": {"bank": {"password": token("pw-2")}}})
    assert load_vault() == vault
    with connect() as connection:
        assert fetch_user(connection, "bob") is None


# The check pm db import runs before it reports success: every password and login of the logged-in user, kept
# versions included, decrypted from both sides with the session cipher. A token re-encrypted from the same value still
# counts as identical; a changed value or a missing label is reported by label, and no decrypted value is returned.
@pytest.mark.integration
def test_verify_import_confirms_every_json_entry_decrypts_identically_from_postgres(postgres_database, monkeypatch, make_v2_user, fernet):
    monkeypatch.setenv("PM_DATABASE_URL", postgres_database)
    encrypt = lambda value: fernet.encrypt(value.encode()).decode()
    vault = {"alice": {
        "github": {"password": encrypt("pw-2"), "login": encrypt("alice@example.com"), "tags": ["work"]},
        "github__v1": {"password": encrypt("pw-1")},
        "mail": {"password": encrypt("pw-3")},
        "bank": {"password": encrypt("pw-4")},
    }}
    import_json(make_v2_user("alice"), vault)
    assert verify_import(vault, "alice", fernet) == ()
    with connect() as connection:
        connection.execute("UPDATE entries SET password = %s WHERE label = 'bank'", (encrypt("pw-4"),))
        connection.execute("UPDATE entries SET login = %s WHERE label = 'github'", (encrypt("mallory@example.com"),))
        connection.execute("UPDATE password_history SET password = %s WHERE label = 'github'", (encrypt("pw-x"),))
        connection.execute("DELETE FROM entries WHERE label = 'mail'")
    assert verify_import(vault, "alice", fernet) == ("github", "github__v1", "mail")


# The way back: the Postgres vault and the users as users.json holds them are written as users.json and vault.json
# (0600) into a directory, and the JSON backend pointed there logs alice in with her master password and decrypts
# her password. The dummy password and values are test placeholders.
@pytest.mark.integration
def test_export_json_writes_files_the_json_backend_can_log_in_with(postgres_database, monkeypatch, make_v2_user, tmp_path):
    monkeypatch.setenv("PM_DATABASE_URL", postgres_database)
    data_key = Fernet.generate_key()
    users = make_v2_user("alice", password="alice_wonderland", data_key=data_key)
    vault = {"alice": {
        "github": {"password": Fernet(data_key).encrypt(b"pw-2").decode(), "tags": ["work"]},
        "github__v1": {"password": Fernet(data_key).encrypt(b"pw-1").decode()},
    }}
    import_json(users, vault)
    export_json(tmp_path, users)
    assert {path.name: os.stat(path).st_mode & 0o777 for path in tmp_path.iterdir()} == {"users.json": 0o600, "vault.json": 0o600}
    monkeypatch.setenv("USERS_FILE", str(tmp_path / "users.json"))
    monkeypatch.setenv("VAULT_FILE", str(tmp_path / "vault.json"))
    assert storage.load_vault() == vault
    assert Fernet(authenticate_user("alice", "alice_wonderland")).decrypt(storage.load_vault()["alice"]["github"]["password"].encode()) == b"pw-2"


# An export never overwrites: pointed at a directory that has either file, such as the live data dir, it writes
# neither, so the file already there (here a stand-in, not a real vault) is left byte for byte as it was
@pytest.mark.integration
@pytest.mark.parametrize("name", ["users.json", "vault.json"])
def test_export_json_refuses_a_directory_that_already_has_users_json_or_vault_json(postgres_database, monkeypatch, make_v2_user, tmp_path, name):
    monkeypatch.setenv("PM_DATABASE_URL", postgres_database)
    users = make_v2_user("alice")
    import_json(users, {"alice": {"github": {"password": token("pw-1")}}})
    (tmp_path / name).write_text('{"existing": {}}')
    with pytest.raises(ValueError, match=rf"^'{re.escape(str(tmp_path))}' already has {name}; export only into a directory without users.json or vault.json$"):
        export_json(tmp_path, users)
    assert [path.name for path in tmp_path.iterdir()] == [name]
    assert (tmp_path / name).read_text() == '{"existing": {}}'
