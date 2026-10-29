import psycopg
import pytest

from password_manager.postgres_storage import (
    EntryRow, UserRow, apply_migrations, connect, fetch_entry, fetch_user, insert_user, upsert_entry, user_record_to_row,
)


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
