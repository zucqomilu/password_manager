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

# Dir for the agent socket: the per-user runtime dir (owned by the user, 0700, on tmpfs and wiped at logout)
# when it is absolute, else the 0700 data dir. Never a relative path, which would land in the cwd.
def get_runtime_dir():
    xdg_runtime_dir = os.environ.get("XDG_RUNTIME_DIR", "")
    return os.path.join(xdg_runtime_dir, "password_manager") if os.path.isabs(xdg_runtime_dir) else get_data_dir()

# PM_AGENT_SOCKET lets tests and manual runs against a data copy use their own agent, never the real one
def get_socket_path():
    return os.environ.get("PM_AGENT_SOCKET") or os.path.join(get_runtime_dir(), "agent.sock")

# Longest socket path the kernel accepts, in bytes: Linux's sun_path holds 108, including the closing NUL
MAX_SOCKET_PATH = 107

# pm's own database over the local socket: no host and no password, so peer authentication admits the logged-in user
def get_database_url():
    return "postgresql:///password_manager"

# Keyring
KEYRING_SERVICE = "password_manager"
KEYRING_ACCOUNT = "session"

SESSION_TTL = 15 * 60

# Largest agent socket message in bytes; far above any password, login or Fernet token
MAX_MESSAGE_SIZE = 64 * 1024

# Seconds the agent waits for a connected peer's request; pm sends it right after connecting
CONNECTION_TIMEOUT = 5

# Argon2id costs for new v2 records (RFC 9106 low-memory profile); memory_cost is in KiB.
# Each record stores its own copy, so raising these later never breaks existing users.
ARGON2_PARAMS = {"time_cost": 3, "memory_cost": 64 * 1024, "parallelism": 4}
