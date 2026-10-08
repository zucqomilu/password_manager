import os

# Base directory: the repo root, two levels up from src/password_manager/
BASE_DIR = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

def get_data_home():
    xdg_data_home = os.environ.get("XDG_DATA_HOME", "")
    return xdg_data_home if os.path.isabs(xdg_data_home) else os.path.expanduser("~/.local/share")

def get_data_dir():
    return os.environ.get("PM_DATA_DIR") or os.path.join(get_data_home(), "password_manager")

# Allow environment variable overrides for testability; fallback to default paths
def get_vault():
    return os.environ.get("VAULT_FILE", os.path.join(get_data_dir(), "vault.json"))

def get_users():
    return os.environ.get("USERS_FILE", os.path.join(BASE_DIR, "users.json"))

def get_log():
    return os.path.join(BASE_DIR, "vault.log")

# Keyring
KEYRING_SERVICE = "password_manager"
KEYRING_ACCOUNT = "session"

SESSION_TTL = 15 * 60
