import os

def get_data_home():
    xdg_data_home = os.environ.get("XDG_DATA_HOME", "")
    return xdg_data_home if os.path.isabs(xdg_data_home) else os.path.expanduser("~/.local/share")

def get_data_dir():
    return os.environ.get("PM_DATA_DIR") or os.path.join(get_data_home(), "password_manager")

def ensure_data_dir():
    os.makedirs(get_data_dir(), mode=0o700, exist_ok=True)
    os.chmod(get_data_dir(), 0o700)

# Allow environment variable overrides for testability; fallback to default paths
def get_vault():
    return os.environ.get("VAULT_FILE", os.path.join(get_data_dir(), "vault.json"))

def get_users():
    return os.environ.get("USERS_FILE", os.path.join(get_data_dir(), "users.json"))

def get_log():
    return os.path.join(get_data_dir(), "vault.log")

# Keyring
KEYRING_SERVICE = "password_manager"
KEYRING_ACCOUNT = "session"

SESSION_TTL = 15 * 60

# Argon2id costs for new v2 records (RFC 9106 low-memory profile); memory_cost is in KiB.
# Each record stores its own copy, so raising these later never breaks existing users.
ARGON2_PARAMS = {"time_cost": 3, "memory_cost": 64 * 1024, "parallelism": 4}
