import pytest
from cryptography.fernet import Fernet, InvalidToken

from password_manager.rotation import reencrypt_vault


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
