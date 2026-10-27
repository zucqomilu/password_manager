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


# By number, not by text, so __v10 comes after __v2; the order the labels happen to have in vault.json does not matter
@pytest.mark.unit
def test_vault_to_rows_orders_vn_history_by_version_number():
    vault = {"alice": {
        "github__v10": {"password": "token-pw-10"},
        "github": {"password": "token-pw-11"},
        "github__v2": {"password": "token-pw-2"},
        "github__v1": {"password": "token-pw-1"},
    }}
    assert [row.version for row in vault_to_rows(vault).history] == [1, 2, 10]


# History rows have no tags, so converting such a vault would silently drop them; refusing it stops the import with
# vault.json untouched, and the message says which label to fix
@pytest.mark.unit
def test_vault_to_rows_refuses_a_vn_label_that_has_tags():
    vault = {"alice": {
        "github": {"password": "token-pw-2"},
        "github__v1": {"password": "token-pw-1", "tags": ["work"]},
    }}
    with pytest.raises(ValueError, match=r"^'github__v1' is an old password version and has tags; remove them with `pm remove github__v1 --tag work` first$"):
        vault_to_rows(vault)
