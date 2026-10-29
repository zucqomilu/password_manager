import re
from dataclasses import dataclass, field
from .constants import get_database_url
from .logger import logger
from .validate_storage import validate_vault

# The __vN labels save_password() keeps of overwritten passwords; the same pattern as core.is_versioned_backup()
VERSIONED_LABEL = re.compile(r"^(.*)__v(\d+)$")


# One row of each table. password and login are the Fernet tokens from vault.json, never plaintext.
@dataclass(frozen=True)
class EntryRow:
    username: str
    label: str
    password: str
    login: str | None


# position keeps the order of an entry's tags, which SQL rows do not have
@dataclass(frozen=True)
class TagRow:
    username: str
    label: str
    position: int
    tag: str


# Keyed by label and version, not tied to an entry: delete_label() keeps a label's versions after the label is gone
@dataclass(frozen=True)
class HistoryRow:
    username: str
    label: str
    version: int
    password: str
    login: str | None


@dataclass(frozen=True)
class VaultRows:
    entries: tuple
    tags: tuple
    history: tuple


# History rows have no tags: refuse such a vault rather than drop them
def check_untagged_versions(vault):
    tagged = next(((label, entry["tags"]) for labels in vault.values() for label, entry in labels.items()
                   if VERSIONED_LABEL.match(label) and entry.get("tags")), None)
    if tagged:
        raise ValueError(f"'{tagged[0]}' is an old password version and has tags; "
                         f"remove them with `pm remove {tagged[0]} --tag {' '.join(tagged[1])}` first")


def vault_to_rows(vault):
    check_untagged_versions(vault)
    return VaultRows(
        entries=tuple(
            EntryRow(username, label, entry["password"], entry.get("login"))
            for username, labels in vault.items() for label, entry in labels.items() if not VERSIONED_LABEL.match(label)
        ),
        tags=tuple(
            TagRow(username, label, position, tag)
            for username, labels in vault.items() for label, entry in labels.items() if not VERSIONED_LABEL.match(label)
            # A tag once per label, at its first occurrence: the tags key allows nothing else
            for position, tag in enumerate(dict.fromkeys(entry.get("tags", [])))
        ),
        # Numeric order, so __v10 follows __v2 whatever order vault.json lists the labels in
        history=tuple(sorted(
            (
                HistoryRow(username, match[1], int(match[2]), entry["password"], entry.get("login"))
                for username, labels in vault.items() for label, entry in labels.items()
                for match in [VERSIONED_LABEL.match(label)] if match
            ),
            key=lambda row: (row.username, row.label, row.version),
        )),
    )


def entry_fields(password, login):
    return {"password": password, **({"login": login} if login is not None else {})}


# Tags in position order; no "tags" key at all when there are none, as in vault.json
def tags_field(rows, username, label):
    tags = [row.tag for row in sorted(rows.tags, key=lambda row: row.position) if (row.username, row.label) == (username, label)]
    return {"tags": tags} if tags else {}


# The vault shape core.py works on, with each history row back under its <label>__vN label
def rows_to_vault(rows):
    return {
        username: {
            **{row.label: {**entry_fields(row.password, row.login), **tags_field(rows, username, row.label)}
               for row in rows.entries if row.username == username},
            **{f"{row.label}__v{row.version}": entry_fields(row.password, row.login)
               for row in rows.history if row.username == username},
        }
        for username in dict.fromkeys(row.username for row in (*rows.entries, *rows.history))
    }


# A v2 users.json record, one column per field; the wrapped key stays wrapped and out of any printed row
@dataclass(frozen=True)
class UserRow:
    username: str
    salt: str
    time_cost: int
    memory_cost: int
    parallelism: int
    wrapped_key: str = field(repr=False)


# Only v2 records: the database never holds a v1 PBKDF2 password verifier. A login upgrades a v1 record in users.json.
def user_record_to_row(username, record):
    if record.get("version") != 2:
        raise ValueError(f"'{username}' still has a v1 user record; run `pm login` once to upgrade it, then import again")
    return UserRow(username, record["kdf"]["salt"], record["kdf"]["time_cost"], record["kdf"]["memory_cost"],
                   record["kdf"]["parallelism"], record["wrapped_key"])


def row_to_user_record(row):
    return {"version": 2,
            "kdf": {"salt": row.salt, "time_cost": row.time_cost, "memory_cost": row.memory_cost, "parallelism": row.parallelism},
            "wrapped_key": row.wrapped_key}


# Each migration runs once, in order, and is recorded in schema_migrations. The tables hold what the JSON files hold:
# Fernet tokens, plaintext tags and the wrapped data key with its KDF parameters. All SQL here is fixed text.
MIGRATIONS = (
    (1, (
        """CREATE TABLE users (
            username text PRIMARY KEY, salt text NOT NULL, time_cost integer NOT NULL,
            memory_cost integer NOT NULL, parallelism integer NOT NULL, wrapped_key text NOT NULL)""",
        # Entries and history do not reference users: users stay in users.json, and the users table is only filled by
        # the import, so a user who registers later still has a vault
        """CREATE TABLE entries (
            username text NOT NULL, label text NOT NULL,
            password text NOT NULL, login text, PRIMARY KEY (username, label))""",
        # The (username, label, tag) key makes a duplicate tag impossible; tags go with their entry
        """CREATE TABLE tags (
            username text NOT NULL, label text NOT NULL, position integer NOT NULL, tag text NOT NULL,
            PRIMARY KEY (username, label, tag), UNIQUE (username, label, position),
            FOREIGN KEY (username, label) REFERENCES entries ON DELETE CASCADE)""",
        # Not tied to the entry, so deleting an entry keeps its old passwords, as delete_label() does
        """CREATE TABLE password_history (
            username text NOT NULL, label text NOT NULL, version integer NOT NULL CHECK (version > 0),
            password text NOT NULL, login text, PRIMARY KEY (username, label, version))""",
    )),
)


# Takes an open connection, so this module never imports psycopg itself and a JSON-only install still starts.
# One transaction: a migration that fails leaves the schema as it was.
def apply_migrations(connection):
    with connection.transaction():
        connection.execute("CREATE TABLE IF NOT EXISTS schema_migrations (version integer PRIMARY KEY)")
        applied = {row[0] for row in connection.execute("SELECT version FROM schema_migrations")}
        for version, statements in MIGRATIONS:
            if version not in applied:
                for statement in statements:
                    connection.execute(statement)
                connection.execute("INSERT INTO schema_migrations (version) VALUES (%s)", (version,))


# Values always go in as bound parameters, never into the SQL text. Nothing here commits: the caller's transaction
# decides, so an import writes everything or nothing. An existing username fails on the key instead of being replaced.
def insert_user(connection, row):
    connection.execute(
        "INSERT INTO users (username, salt, time_cost, memory_cost, parallelism, wrapped_key) VALUES (%s, %s, %s, %s, %s, %s)",
        (row.username, row.salt, row.time_cost, row.memory_cost, row.parallelism, row.wrapped_key))


def fetch_user(connection, username):
    found = connection.execute(
        "SELECT username, salt, time_cost, memory_cost, parallelism, wrapped_key FROM users WHERE username = %s",
        (username,)).fetchone()
    return UserRow(*found) if found else None


def upsert_entry(connection, row):
    connection.execute("INSERT INTO entries (username, label, password, login) VALUES (%s, %s, %s, %s)",
                       (row.username, row.label, row.password, row.login))


def fetch_entry(connection, username, label):
    found = connection.execute("SELECT username, label, password, login FROM entries WHERE username = %s AND label = %s",
                               (username, label)).fetchone()
    return EntryRow(*found) if found else None


# The only place psycopg is imported, so a JSON-only install (no postgres extra) never needs it.
# The URL may hold a password: it goes to psycopg and nowhere else, never into a message or the log.
def connect():
    import psycopg
    connection = psycopg.connect(get_database_url())
    apply_migrations(connection)
    return connection


# Rewrites the whole vault, as vault.json is rewritten whole: one transaction, so a failure leaves the old rows.
# The same validation gate as the JSON save_vault() comes first, so an invalid vault never reaches the database.
def save_vault(data):
    if not validate_vault(data):
        logger.error("Aborting save: vault validation failed.")
        return
    rows = vault_to_rows(data)
    with connect() as connection, connection.transaction():
        connection.execute("DELETE FROM tags")
        connection.execute("DELETE FROM password_history")
        connection.execute("DELETE FROM entries")
        for row in rows.entries:
            upsert_entry(connection, row)
        connection.cursor().executemany("INSERT INTO tags (username, label, position, tag) VALUES (%s, %s, %s, %s)",
                                        [(row.username, row.label, row.position, row.tag) for row in rows.tags])
        connection.cursor().executemany(
            "INSERT INTO password_history (username, label, version, password, login) VALUES (%s, %s, %s, %s, %s)",
            [(row.username, row.label, row.version, row.password, row.login) for row in rows.history])


def load_vault():
    with connect() as connection:
        return rows_to_vault(VaultRows(
            entries=tuple(EntryRow(*row) for row in connection.execute(
                "SELECT username, label, password, login FROM entries ORDER BY username, label")),
            tags=tuple(TagRow(*row) for row in connection.execute(
                "SELECT username, label, position, tag FROM tags ORDER BY username, label, position")),
            history=tuple(HistoryRow(*row) for row in connection.execute(
                "SELECT username, label, version, password, login FROM password_history ORDER BY username, label, version")),
        ))


# A placeholder until its own test fills it in: it fails loudly rather than skip the backup a delete relies on
def backup_vault():
    raise NotImplementedError("Postgres storage is not available yet")
