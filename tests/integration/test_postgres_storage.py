import psycopg
import pytest

from password_manager.postgres_storage import apply_migrations


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
