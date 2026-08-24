import os

# Base directory: one level up from src/
BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))

# Allow environment variable overrides for testability; fallback to project paths
def get_vault():
    return os.environ.get("VAULT_FILE", os.path.join(BASE_DIR, "vault.json"))

def get_users():
    return os.environ.get("USERS_FILE", os.path.join(BASE_DIR, "users.json"))

def get_log():
    return os.path.join(BASE_DIR, "vault.log")

# Keyring
KEYRING_SERVICE = "password_manager"
KEYRING_ACCOUNT = "session"

SESSION_TTL = 15 * 60
