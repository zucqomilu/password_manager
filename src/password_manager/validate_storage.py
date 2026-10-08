import base64
from .logger import logger

REQUIRED_USER_KEYS = {"auth_salt", "enc_salt", "password"}

DECODED_LENGTH_MIN = 16

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

def validate_users(data) -> bool:
    if not isinstance(data, dict):
        logger.error(f"Invalid users format: expected dict at top level — got {type(data).__name__}.")
        return False

    for username, record in data.items():
        if not isinstance(record, dict):
            logger.error(f"User '{username}' has invalid data type: expected dict, got {type(record).__name__}.")
            return False
        
        record_keys = set(record.keys())
        if record_keys != REQUIRED_USER_KEYS:
            missing = REQUIRED_USER_KEYS - record_keys
            extra = record_keys - REQUIRED_USER_KEYS
            if missing:
                logger.error(f"User '{username}' is missing required fields: {', '.join(missing)}.")
            if extra:
                logger.error(f"User '{username}' has unexpected fields: {', '.join(extra)}.")
            return False
        
        for key in REQUIRED_USER_KEYS:
            val = record[key]
            expected_len = EXPECTED_LENGTHS[key]
            if not is_valid_base64(val, expected_decoded_len=expected_len):
                logger.error(f"User '{username}' field '{key}' has invalid base64 format.")
                return False
    return True

def validate_vault(data) -> bool:
    if not isinstance(data, dict):
        logger.error(f"Vault should be a top-level dictionary, got {type(data).__name__}.")
        return False

    for username, labels in data.items():
        if not isinstance(labels, dict):
            logger.error(f"Vault entry for user '{username}' must be a dict, got {type(labels).__name__}.")
            return False
        
        for label, entry in labels.items():
            if not isinstance(entry, dict):
                logger.error(f"Vault entry '{username}:{label}' must be a dict, got {type(entry).__name__}.")
                return False

            if "password" not in entry:
                logger.error(f"Vault entry '{username}:{label}' is missing required 'password' field.")
                return False

            if not is_valid_base64(entry["password"]):
                logger.error(f"Vault entry '{username}:{label}' has invalid base64 password.")
                return False

            if "login" in entry and not is_valid_base64(entry["login"]):
                logger.error(f"Vault entry '{username}:{label}' has invalid base64 login.")
                return False

            if "tags" in entry:
                if not isinstance(entry["tags"], list) or not all(
                        isinstance(tag, str) for tag in entry["tags"]
                ):
                    logger.error(f"Vault entry '{username}:{label}' has invalid tags format.")
                    return False

    return True
