import pytest

from password_manager.postgres_storage import EntryRow, HistoryRow, TagRow, VaultRows, vault_to_rows


# One JSON label becomes one entry row plus one row per tag, and each __vN label a history row of its base label.
# The fields are copied as they are: rows hold the same Fernet tokens as vault.json, so Postgres never sees plaintext.
@pytest.mark.unit
def test_vault_to_rows_splits_labels_into_entries_tags_and_password_history():
    vault = {"alice": {
        "github": {"password": "token-pw-2", "login": "token-login", "tags": ["work", "dev"]},
        "github__v1": {"password": "token-pw-1", "login": "token-login"},
        "mail": {"password": "token-pw-3"},
    }}
    assert vault_to_rows(vault) == VaultRows(
        entries=(EntryRow("alice", "github", "token-pw-2", "token-login"), EntryRow("alice", "mail", "token-pw-3", None)),
        tags=(TagRow("alice", "github", 0, "work"), TagRow("alice", "github", 1, "dev")),
        history=(HistoryRow("alice", "github", 1, "token-pw-1", "token-login"),),
    )
