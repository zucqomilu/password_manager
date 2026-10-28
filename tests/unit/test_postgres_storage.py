import pytest

from password_manager.postgres_storage import (
    EntryRow, HistoryRow, TagRow, UserRow, VaultRows, row_to_user_record, rows_to_vault, user_record_to_row, vault_to_rows,
)


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


# The shape core.py works on: each history row becomes a <label>__vN label again, tags come back in position order,
# and an entry without a login or tags gets no such key. mail__v1 has no entry, as after delete_label(), and is kept.
@pytest.mark.unit
def test_rows_to_vault_rebuilds_the_json_vault_shape_including_vn_labels():
    rows = VaultRows(
        entries=(EntryRow("alice", "github", "token-pw-2", "token-login"), EntryRow("bob", "bank", "token-pw-4", None)),
        tags=(TagRow("alice", "github", 1, "dev"), TagRow("alice", "github", 0, "work")),
        history=(HistoryRow("alice", "github", 1, "token-pw-1", "token-login"), HistoryRow("alice", "mail", 1, "token-pw-3", None)),
    )
    assert rows_to_vault(rows) == {
        "alice": {
            "github": {"password": "token-pw-2", "login": "token-login", "tags": ["work", "dev"]},
            "github__v1": {"password": "token-pw-1", "login": "token-login"},
            "mail__v1": {"password": "token-pw-3"},
        },
        "bob": {"bank": {"password": "token-pw-4"}},
    }


# The guarantee the import rests on: a vault survives the trip to rows and back unchanged, so nothing is lost or altered.
# Two users, tags in a non-alphabetical order, a label past __v9, and versions whose label was deleted.
@pytest.mark.unit
def test_rows_to_vault_inverts_vault_to_rows_for_a_vault_with_tags_and_versions():
    vault = {
        "alice": {
            "github": {"password": "token-pw-12", "login": "token-login-1", "tags": ["work", "dev", "code"]},
            **{f"github__v{version}": {"password": f"token-pw-{version}", "login": "token-login-1"} for version in range(1, 12)},
            "mail": {"password": "token-pw-20", "tags": ["personal"]},
            "old-bank__v1": {"password": "token-pw-30"},
            "old-bank__v2": {"password": "token-pw-31", "login": "token-login-2"},
        },
        "bob": {"bank": {"password": "token-pw-40", "login": "token-login-3"}},
    }
    assert rows_to_vault(vault_to_rows(vault)) == vault


# A users row holds what users.json holds for a v2 user: the Argon2id parameters and the wrapped data key, one column
# each. There is no password hash and no unwrapped key, so the row is exactly as safe at rest as the JSON record.
@pytest.mark.unit
def test_user_record_to_row_and_row_to_user_record_round_trip_a_v2_record(make_v2_user):
    record = make_v2_user()["alice"]
    row = user_record_to_row("alice", record)
    assert row == UserRow(
        "alice", record["kdf"]["salt"], record["kdf"]["time_cost"], record["kdf"]["memory_cost"],
        record["kdf"]["parallelism"], record["wrapped_key"],
    )
    assert row_to_user_record(row) == record


# The database only ever holds the Argon2id format: a v1 record (a PBKDF2 password verifier) is refused, and the
# message names the fix, since a single login upgrades it in users.json
@pytest.mark.unit
def test_user_record_to_row_refuses_v1_records(make_user):
    with pytest.raises(ValueError, match=r"^'alice' still has a v1 user record; run `pm login` once to upgrade it, then import again$"):
        user_record_to_row("alice", make_user()["alice"])
