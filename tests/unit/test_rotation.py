import pytest
from cryptography.fernet import Fernet, InvalidToken
from unittest.mock import Mock, patch

from password_manager.rotation import RotationAborted, reencrypt_vault, rotate_data_key
from password_manager.storage import Storage


# Rotation's core: every password and login of the rotating user, kept versions included, decrypts under the new key
# to the same value and no longer under the old one. Tags are plain text and stay as they are, an entry without a
# login gets none, and other users' entries (encrypted under their own keys) are left exactly as they were.
@pytest.mark.unit
def test_reencrypt_vault_reencrypts_one_users_passwords_and_logins_under_a_new_key_leaving_tags_and_other_users_unchanged():
    old, new, bobs = Fernet(Fernet.generate_key()), Fernet(Fernet.generate_key()), Fernet(Fernet.generate_key())
    encrypt = lambda cipher, value: cipher.encrypt(value.encode()).decode()
    vault = {
        "alice": {
            "github": {"password": encrypt(old, "pw-2"), "login": encrypt(old, "alice@example.com"), "tags": ["work", "dev"]},
            "github__v1": {"password": encrypt(old, "pw-1")},
            "mail": {"password": encrypt(old, "pw-3"), "tags": ["personal"]},
        },
        "bob": {"bank": {"password": encrypt(bobs, "pw-4"), "login": encrypt(bobs, "bob@example.com")}},
    }

    rotated = reencrypt_vault(vault, "alice", old, new)

    decrypted = {label: {field: new.decrypt(value.encode()).decode() if field != "tags" else value
                         for field, value in entry.items()} for label, entry in rotated["alice"].items()}
    assert decrypted == {
        "github": {"password": "pw-2", "login": "alice@example.com", "tags": ["work", "dev"]},
        "github__v1": {"password": "pw-1"},
        "mail": {"password": "pw-3", "tags": ["personal"]},
    }
    with pytest.raises(InvalidToken):
        old.decrypt(rotated["alice"]["github"]["password"].encode())
    assert rotated["bob"] == vault["bob"]


# One login encrypted under some other key (a damaged or foreign entry) stops the whole re-encryption: half a rotation
# would leave that value under a key that is about to be discarded. The vault passed in is not changed.
@pytest.mark.unit
def test_reencrypt_vault_raises_invalid_token_when_an_entry_does_not_decrypt_with_the_old_key():
    old, new, other = Fernet(Fernet.generate_key()), Fernet(Fernet.generate_key()), Fernet(Fernet.generate_key())
    vault = {"alice": {
        "github": {"password": old.encrypt(b"pw-1").decode()},
        "mail": {"password": old.encrypt(b"pw-2").decode(), "login": other.encrypt(b"alice@example.com").decode()},
    }}
    original = {"alice": {label: dict(entry) for label, entry in vault["alice"].items()}}
    with pytest.raises(InvalidToken):
        reencrypt_vault(vault, "alice", old, new)
    assert vault == original


# A v1 record has no kdf to wrap the new key with, and login upgrades it only when users.json can be backed up first, so
# one can still be there after the password check. The rotation refuses it with the fix and writes nothing: neither
# file, nor the agent. Storage, users.json and the agent are stand-ins, so nothing touches the disk.
@pytest.mark.unit
def test_rotate_data_key_refuses_a_v1_user_record(make_user):
    key = Fernet.generate_key()
    store = Storage(load_vault=lambda: {"alice": {"github": {"password": Fernet(key).encrypt(b"pw-1").decode()}}},
                    save_vault=Mock(), backup_vault=Mock())
    with patch("password_manager.rotation.authenticate_user", return_value=key), \
         patch("password_manager.rotation.load_users", return_value=make_user()), \
         patch("password_manager.rotation.save_users") as save_users, \
         patch("password_manager.rotation.save_session") as save_session:
        with pytest.raises(RotationAborted, match=r"^'alice' still has a v1 user record; run `pm login` once to upgrade it, then rotate again$"):
            rotate_data_key("alice", "alice_wonderland", storage=store)

    save_users.assert_not_called()
    store.save_vault.assert_not_called()
    store.backup_vault.assert_not_called()
    save_session.assert_not_called()


# load_vault() returns None for a corrupt or invalid vault. There is nothing to re-encrypt, and rotating anyway would
# put the user's key out of step with entries no one can read, so the rotation stops with the reason and writes
# nothing. Storage, users.json and the agent are stand-ins, so nothing touches the disk.
@pytest.mark.unit
def test_rotate_data_key_refuses_an_unreadable_vault_and_writes_nothing(make_v2_user):
    store = Storage(load_vault=lambda: None, save_vault=Mock(), backup_vault=Mock())
    with patch("password_manager.rotation.authenticate_user", return_value=Fernet.generate_key()), \
         patch("password_manager.rotation.load_users", return_value=make_v2_user()), \
         patch("password_manager.rotation.save_users") as save_users, \
         patch("password_manager.rotation.save_session") as save_session:
        with pytest.raises(RotationAborted, match="^the vault could not be read; nothing was changed$"):
            rotate_data_key("alice", "alice_wonderland", storage=store)

    save_users.assert_not_called()
    store.save_vault.assert_not_called()
    store.backup_vault.assert_not_called()
    save_session.assert_not_called()
