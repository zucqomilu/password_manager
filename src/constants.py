import os
import tempfile

# Base directory: one level up from src/
BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))

# Absolute paths to project-level files
DB_FILE = os.path.join(BASE_DIR, "vault.json")
USERS_FILE = os.path.join(BASE_DIR, "users.json")
LOG_FILE = os.path.join(BASE_DIR, "vault.log")
SESSION_FILE = os.path.join(tempfile.gettempdir(), "session.json")
