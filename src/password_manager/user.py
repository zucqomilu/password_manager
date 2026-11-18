import base64
import hmac
from cryptography.fernet import Fernet, InvalidToken
from .crypto import derive_key, generate_salt, unwrap_data_key, wrap_data_key
from .constants import ARGON2_PARAMS
from .storage import save_users, load_users, backup_users, get_storage
from .logger import logger

# A v2 record: fresh random salt plus the current Argon2id costs, with data_key wrapped under the master password
def make_v2_record(data_key: bytes, master_password: str) -> dict:
    kdf = {"salt": base64.b64encode(generate_salt()).decode(), **ARGON2_PARAMS}
    return {"version": 2, "kdf": kdf, "wrapped_key": wrap_data_key(data_key, master_password, kdf)}

def register_user(username: str, master_password: str) -> bool:
    users = load_users()

    if users is None:
        print("Error: Failed to load users database.")
        logger.error("Aborting operation due to invalid users file.")
        return False

    if username in users:
        print(f"User '{username}' already exists.")
        logger.warning(f"User '{username}' already exists.")
        return False

    # v2: a random data key (the Fernet key) wrapped under an Argon2id key derived from the master password
    save_users({**users, username: make_v2_record(Fernet.generate_key(), master_password)})
    print(f"User '{username}' registered successfully.")
    logger.info(f"User '{username}' registered successfully.")
    return True

def authenticate_user(username: str, password: str) -> bytes:
    users = load_users()
    if users is None:
        logger.error("Failed to load users data during authentication.")
        raise ValueError("User database is corrupted.")
    
    if username not in users:
        logger.error("User does not exist.")
        raise ValueError("User does not exist.")

    user_data = users[username]

    # v2: the password unwraps the stored data key (Argon2id + AES-GCM); v1 records fall through unchanged
    if user_data.get("version") == 2:
        try:
            data_key = unwrap_data_key(user_data["wrapped_key"], password, user_data["kdf"])
        except ValueError:
            logger.error("Incorrect password.")
            raise
        logger.info(f"User '{username}' authenticated successfully.")
        return resolve_pending_key(username, users, password, data_key) if "pending_wrapped_key" in user_data else data_key

    # v1: upgrade_user_record() checks the PBKDF2 password (constant-time) and wraps the same Fernet key in a v2 record,
    # so the vault is untouched. users.json is backed up first; a failed save leaves the v1 record on disk and is retried on the next login.
    try:
        upgraded = upgrade_user_record(user_data, password)
    except ValueError:
        logger.error("Incorrect password.")
        raise
    # Without a backup there is no rollback path, so stay on v1 and retry the upgrade on the next login.
    # A disk error (full, permissions) must never block login: the atomic save leaves the v1 record intact.
    try:
        if backup_users():
            save_users({**users, username: upgraded})
        else:
            logger.error("users.json backup failed; staying on v1 for now.")
    except OSError:
        logger.error("Could not save the v2 upgrade; staying on v1 for now.")
    logger.info(f"User '{username}' authenticated successfully.")
    return derive_key(password + ":fernet", base64.b64decode(user_data["enc_salt"]))

# An interrupted rotate_data_key() left the new key pending beside the old one. Login finishes the rotation only when
# every one of the user's entries decrypts with the pending key; otherwise it logs in with the old key and keeps both,
# since users.json is shared by both backends and the vault read here may not be the one the rotation wrote.
def resolve_pending_key(username, users, password, data_key):
    pending_key = unwrap_data_key(users[username]["pending_wrapped_key"], password, users[username]["kdf"])
    vault = get_storage().load_vault()
    if vault is None:
        logger.error("Vault unreadable while resolving a pending data key.")
        raise ValueError("A key rotation is unfinished and the vault cannot be read; "
                         "restore the vault from a vault_backup_*.json file, then log in again.")
    if not decrypts_with(vault.get(username, {}), pending_key):
        return data_key
    save_users({**users, username: {**{field: value for field, value in users[username].items() if field != "pending_wrapped_key"},
                                    "wrapped_key": users[username]["pending_wrapped_key"]}})
    return pending_key

def decrypts_with(entries, key):
    try:
        return all(Fernet(key).decrypt(value.encode()) is not None for entry in entries.values()
                   for field, value in entry.items() if field in ("password", "login"))
    except InvalidToken:
        return False

# Wrap the v1 Fernet key (the key every vault entry is already encrypted with) in a v2 record,
# so upgrading never re-encrypts the vault. Pure: the caller decides when to save.
# Refuses a wrong password, which would otherwise wrap a wrong key and lock the user out of the vault.
def upgrade_user_record(record: dict, master_password: str) -> dict:
    if not hmac.compare_digest(derive_key(master_password, base64.b64decode(record["auth_salt"])).decode(), record["password"]):
        raise ValueError("Incorrect password.")
    return make_v2_record(derive_key(master_password + ":fernet", base64.b64decode(record["enc_salt"])), master_password)
