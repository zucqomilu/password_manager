import os
import json
import shutil
from datetime import datetime
from .logger import logger

DB_FILE = "vault.json"
USERS_FILE = "users.json"

def load_vault():
    if os.path.exists(DB_FILE):
        with open(DB_FILE, 'r') as f:
            try:
                return json.load(f)
            except json.JSONDecodeError:
                return {}
    return {}

def save_vault(data):
    with open(DB_FILE, 'w') as f:
        json.dump(data, f, indent=4)

def load_users():
    if os.path.exists(USERS_FILE):
        with open(USERS_FILE, 'r') as f:
            return json.load(f)
    return {}

def save_users(users):
    with open(USERS_FILE, 'w') as f:
        json.dump(users, f, indent=4)

def backup_vault():
    if not os.path.exists(DB_FILE):
        return
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    backup_filename = f"vault_backup_{timestamp}.json"
    shutil.copy2(DB_FILE, backup_filename)
    logger.info(f"Creating backup for '{backup_filename}' (backup saved as '{backup_filename}').")
    print(f"Created backup: {backup_filename}")
