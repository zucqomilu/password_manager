import shutil, json, os, base64
from datetime import datetime
from .logger import logger
import src.constants

REQUIRED_USER_KEYS = {"auth_salt", "enc_salt", "password"}

EXPECTED_LENGTHS = {
    "auth_salt": 16,
    "enc_salt": 16,
    "password": 32
}

def is_valid_base64(value, expected_decoded_len=None):
    if not isinstance(value, str):
        return False
    try:
        decoded = base64.urlsafe_b64decode(value)
        if expected_decoded_len is not None and len(decoded) != expected_decoded_len:
            return False
        return True
    except Exception:
        return False

def load_users():
    path = src.constants.get_users()
    
    # Case 1: File does not exist — we allow creating a new one
    if not os.path.exists(path):
        logger.warning(f"Users file does not exist at: {path}")
        return {}

    # Case 2: Try loading JSON
    try:
        with open(path, 'r') as f:
            data = json.load(f)
    except json.JSONDecodeError as e:
        logger.error(f"Failed to decode users file: {path} — {e}")
        return None
    except Exception as e:
        logger.exception(f"Unexpected error reading users file: {path}")
        return None

    # Case 3: Validate top-level structure
    if not isinstance(data, dict):
        logger.warning(f"Invalid users format: expected dict at top level — got {type(data).__name__}")
        return None

    # Case 4: Validate user records
    for username, record in data.items():
        if not isinstance(record, dict):
            logger.warning(f"User '{username}' has invalid data type: expected dict, got {type(record).__name__}")
            return None
        
        if not REQUIRED_USER_KEYS.issubset(record.keys()):
            missing = REQUIRED_USER_KEYS - record.keys()
            logger.warning(f"User '{username}' is missing required fields: {', '.join(missing)}")
            return None

        for key in REQUIRED_USER_KEYS:
            val = record.get(key)
            expected_len = EXPECTED_LENGTHS[key]
            if not is_valid_base64(val, expected_len):
                logger.warning(f"User '{username}' has invalid base64 format in field '{key}'")
                return None

    return data

def save_users(users):
    logger.debug(f"Saving users to {src.constants.get_users()}: {json.dumps(users, indent=2)}")
    with open(src.constants.get_users(), 'w') as f:
        json.dump(users, f, indent=4)

def load_vault():
    if os.path.exists(src.constants.get_vault()):
        with open(src.constants.get_vault(), 'r') as f:
            try:
                return json.load(f)
            except json.JSONDecodeError:
                return {}
    return {}

def save_vault(data):
    with open(src.constants.get_vault(), 'w') as f:
        json.dump(data, f, indent=4)

def backup_vault():
    vault_path = src.constants.get_vault()
    if not os.path.exists(vault_path):
        return None
    backup_dir = os.path.dirname(vault_path)
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    backup_filename = os.path.join(backup_dir, f"vault_backup_{timestamp}.json")
    shutil.copy2(vault_path, backup_filename)
    logger.info(f"Creating backup for '{backup_filename}' (backup saved as '{backup_filename}').")
    print(f"Created backup: {backup_filename}")
