import shutil, json, os
from datetime import datetime
from .logger import logger
from .validate_storage import validate_users, validate_vault
import src.constants

def load_users():
    path = src.constants.get_users()
    
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
    
    logger.debug(f"Saving users to {src.constants.get_users()}: {json.dumps(users, indent=2)}")
    with open(src.constants.get_users(), 'w') as f:
        json.dump(users, f, indent=4)

def load_vault():
    path = src.constants.get_vault()
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

    logger.debug(f"Saving vault to {src.constants.get_vault()}: {json.dumps(data, indent=2)}")
    with open(src.constants.get_vault(), 'w') as f:
        json.dump(data, f, indent=4)

def backup_vault():
    vault_path = src.constants.get_vault()
    if not os.path.exists(vault_path):
        logger.error("Aborting backup: vault not found.")
        return None
    
    backup_dir = os.path.dirname(vault_path)
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    backup_filename = os.path.join(backup_dir, f"vault_backup_{timestamp}.json")
    shutil.copy2(vault_path, backup_filename)
    logger.info(f"Creating backup for '{backup_filename}' (backup saved as '{backup_filename}').")
    print(f"Created backup: {backup_filename}")
