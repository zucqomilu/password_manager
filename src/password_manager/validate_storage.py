import base64
from .logger import logger

REQUIRED_USER_KEYS = {"auth_salt", "enc_salt", "password"}

REQUIRED_V2_USER_KEYS = {"version", "kdf", "wrapped_key"}

# A rotation in progress adds the new data key, wrapped under the same kdf, next to the old one
OPTIONAL_V2_USER_KEYS = {"pending_wrapped_key"}

KDF_PARAMS = {"salt", "time_cost", "memory_cost", "parallelism"}

# nonce (12) + AES-GCM encrypted Fernet key (44) + GCM tag (16)
WRAPPED_KEY_LENGTH = 72

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

# Strict standard base64 (as written by crypto.py); urlsafe_b64decode would silently drop '+' and '/'
def is_strict_base64(value, expected_decoded_len):
    try:
        return isinstance(value, str) and len(base64.b64decode(value, validate=True)) == expected_decoded_len
    except ValueError:
        return False

# bool is an int subclass, so exclude it explicitly
def is_positive_int(value):
    return isinstance(value, int) and not isinstance(value, bool) and value > 0

# Names of Argon2id parameters that are missing, unexpected, or invalid (16-byte salt, positive int costs)
def invalid_kdf_params(kdf):
    return sorted((kdf.keys() ^ KDF_PARAMS) | {
        name for name in kdf.keys() & KDF_PARAMS
        if not (is_strict_base64(kdf[name], 16) if name == "salt" else is_positive_int(kdf[name]))
    })

# A v2 record holds Argon2id parameters and the data key wrapped under the master password
def validate_v2_user(username, record) -> bool:
    if set(record.keys()) - OPTIONAL_V2_USER_KEYS != REQUIRED_V2_USER_KEYS:
        logger.error(f"User '{username}' v2 record must have exactly the fields: {', '.join(sorted(REQUIRED_V2_USER_KEYS))}.")
        return False
    if not isinstance(record["kdf"], dict):
        logger.error(f"User '{username}' field 'kdf' must be a dict.")
        return False
    if invalid_kdf_params(record["kdf"]):
        logger.error(f"User '{username}' field 'kdf' is missing or invalid: {', '.join(invalid_kdf_params(record['kdf']))}.")
        return False
    if not is_strict_base64(record["wrapped_key"], WRAPPED_KEY_LENGTH):
        logger.error(f"User '{username}' field 'wrapped_key' has invalid base64 format.")
        return False
    if "pending_wrapped_key" in record and not is_strict_base64(record["pending_wrapped_key"], WRAPPED_KEY_LENGTH):
        logger.error(f"User '{username}' field 'pending_wrapped_key' has invalid base64 format.")
        return False
    return True

def validate_users(data) -> bool:
    if not isinstance(data, dict):
        logger.error(f"Invalid users format: expected dict at top level — got {type(data).__name__}.")
        return False

    for username, record in data.items():
        if not isinstance(record, dict):
            logger.error(f"User '{username}' has invalid data type: expected dict, got {type(record).__name__}.")
            return False

        if record.get("version") == 2:
            if not validate_v2_user(username, record):
                return False
            continue

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
