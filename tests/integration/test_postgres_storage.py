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
