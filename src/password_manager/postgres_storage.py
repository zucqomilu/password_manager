import re
from dataclasses import dataclass, field

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
            for position, tag in enumerate(entry.get("tags", []))
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


# Placeholders until the row tests fill them in: every call fails loudly,
# so PM_STORAGE=postgres can never silently drop a write or show an empty vault.
def load_vault():
    raise NotImplementedError("Postgres storage is not available yet")

def save_vault(data):
    raise NotImplementedError("Postgres storage is not available yet")

def backup_vault():
    raise NotImplementedError("Postgres storage is not available yet")
