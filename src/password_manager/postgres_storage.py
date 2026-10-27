import re
from dataclasses import dataclass

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


def vault_to_rows(vault):
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


# Placeholders until the row tests fill them in: every call fails loudly,
# so PM_STORAGE=postgres can never silently drop a write or show an empty vault.
def load_vault():
    raise NotImplementedError("Postgres storage is not available yet")

def save_vault(data):
    raise NotImplementedError("Postgres storage is not available yet")

def backup_vault():
    raise NotImplementedError("Postgres storage is not available yet")
