import shutil, json, os, tempfile
from datetime import datetime
from .logger import logger
from .validate_storage import validate_users, validate_vault
import password_manager.constants

def load_users():
    path = password_manager.constants.get_users()
    
    if not os.path.exists(path):
        logger.warning(f"Users file does not exist at: {path}")
        return {}

    try:
        with open(path, 'r') as f:
            data = json.load(f)
    except json.JSONDecodeError as e:
        logger.error(f"Failed to decode users file: {path} — {e}")
        return None
    except Exception as e:
        logger.exception(f"Unexpected error reading users file: {path}")
        return None

    if not validate_users(data):
        logger.error("Loading failed: user validation failed.")
        return None

    return data

def save_users(users):
    if not validate_users(users):
        logger.error("Aborting save: user validation failed.")
        return
    
    logger.debug(f"Saving users to {password_manager.constants.get_users()}: {json.dumps(users, indent=2)}")
    write_json_atomically(password_manager.constants.get_users(), users)

def load_vault():
    path = password_manager.constants.get_vault()
    if not os.path.exists(path):
        logger.warning(f"Vault file does not exist at: {path}")
        return {}

    try:
        with open(path, 'r') as f:
            data = json.load(f)
    except json.JSONDecodeError as e:
        logger.error(f"Failed to decode vault file: {path} — {e}")
        return None
    except Exception as e:
        logger.exception(f"Unexpected error reading vault file: {path}")
        return None

    if not validate_vault(data):
        logger.error("Loading failed: vault validation failed.")
        return None

    return data

def save_vault(data):
    if not validate_vault(data):
        logger.error("Aborting save: vault validation failed.")
        return

    logger.debug(f"Saving vault to {password_manager.constants.get_vault()}: {json.dumps(data, indent=2)}")
    write_json_atomically(password_manager.constants.get_vault(), data)

# Write to a temp file in the target's folder, flush it to disk, then rename it over the target,
# so a crash mid-write leaves either the complete old file or the complete new one
def write_json_atomically(path, data):
    f = tempfile.NamedTemporaryFile('w', dir=os.path.dirname(path), delete=False)
    try:
        with f:
            json.dump(data, f, indent=4)
            f.flush()
            os.fsync(f.fileno())
        os.replace(f.name, path)
    # Remove the temp file on any failure (including Ctrl+C) so no stray vault copy is left behind
    except BaseException:
        os.remove(f.name)
        raise

def backup_vault():
    vault_path = password_manager.constants.get_vault()
    if not os.path.exists(vault_path):
        logger.error("Aborting backup: vault not found.")
        return None
    
    backup_dir = os.path.dirname(vault_path)
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    backup_filename = os.path.join(backup_dir, f"vault_backup_{timestamp}.json")
    shutil.copy2(vault_path, backup_filename)
    logger.info(f"Creating backup for '{backup_filename}' (backup saved as '{backup_filename}').")
    print(f"Created backup: {backup_filename}")

# Copy users.json next to itself before it is rewritten (e.g. the v2 upgrade), as the rollback path.
# copy2 keeps the 0600 mode; microseconds keep two backups in the same second from overwriting each other.
def backup_users():
    if not os.path.exists(password_manager.constants.get_users()):
        logger.error("Aborting backup: users file not found.")
        return None
    backup_filename = shutil.copy2(
        password_manager.constants.get_users(),
        os.path.join(os.path.dirname(password_manager.constants.get_users()), f"users_backup_{datetime.now():%Y%m%d_%H%M%S_%f}.json"),
    )
    logger.info(f"Created users backup '{backup_filename}'.")
    print(f"Created backup: {backup_filename}")
    return backup_filename
