from cryptography.fernet import Fernet

from .crypto import wrap_data_key
from .session import save_session
from .storage import get_storage, load_users, save_users
from .user import authenticate_user


# users.json refused or lost the pending key, so nothing else is written
class RotationAborted(Exception):
    pass


# Every password and login of username, decrypted with old and encrypted with new; tags and other users unchanged.
# Pure: the caller decides whether to save, so a failure here leaves nothing written.
def reencrypt_vault(vault, username, old, new):
    return {user: {label: reencrypt_entry(entry, old, new) for label, entry in entries.items()} if user == username else entries
            for user, entries in vault.items()}


def reencrypt_entry(entry, old, new):
    return {field: new.encrypt(old.decrypt(value.encode())).decode() if field in ("password", "login") else value
            for field, value in entry.items()}


# Replace username's data key: their entries re-encrypted under a new key, wrapped under the same master password and
# kdf. users.json first holds the new key as pending_wrapped_key beside the old one, then the vault is saved, then the
# record keeps only the new key, so an interruption at any point leaves login a key that decrypts the vault.
def rotate_data_key(username, master_password, storage=None):
    store = storage or get_storage()
    old_key = authenticate_user(username, master_password)
    new_key = Fernet.generate_key()
    vault = reencrypt_vault(store.load_vault(), username, Fernet(old_key), Fernet(new_key))
    users = load_users()
    pending = wrap_data_key(new_key, master_password, users[username]["kdf"])
    save_users({**users, username: {**users[username], "pending_wrapped_key": pending}})
    if load_users()[username].get("pending_wrapped_key") != pending:
        raise RotationAborted("users.json did not take the new key; nothing was changed")
    store.save_vault(vault)
    save_users({**users, username: {**users[username], "wrapped_key": pending}})
    save_session(username, new_key)
