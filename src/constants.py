import os

# Base directory: one level up from src/
BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))

# Allow environment variable overrides for testability; fallback to project paths
def get_db_file():
    return os.environ.get("DB_FILE", os.path.join(BASE_DIR, "vault.json"))

def get_users_file():
    return os.environ.get("USERS_FILE", os.path.join(BASE_DIR, "users.json"))

def get_session_file():
    return os.environ.get("SESSION_FILE", os.path.join(BASE_DIR, "session.json"))

def get_log_file():
    return os.path.join(BASE_DIR, "vault.log")
