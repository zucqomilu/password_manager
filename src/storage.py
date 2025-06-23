import os
import json
import shutil
from datetime import datetime
from .logger import logger
import src.constants

def load_vault():
    if os.path.exists(src.constants.get_db_file()):
        with open(src.constants.get_db_file(), 'r') as f:
            try:
                return json.load(f)
            except json.JSONDecodeError:
                return {}
    return {}

def save_vault(data):
    with open(src.constants.get_db_file(), 'w') as f:
        json.dump(data, f, indent=4)

def load_users():
    if os.path.exists(src.constants.get_users_file()):
        with open(src.constants.get_users_file(), 'r') as f:
            try:
                return json.load(f)
            except json.JSONDecodeError:
                return {}
    return {}

def save_users(users):
    with open(src.constants.get_users_file(), 'w') as f:
        json.dump(users, f, indent=4)

def backup_vault():
    if not os.path.exists(src.constants.get_db_file()):
        return None
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    backup_filename = f"vault_backup_{timestamp}.json"
    shutil.copy2(src.constants.get_db_file(), backup_filename)
    logger.info(f"Creating backup for '{backup_filename}' (backup saved as '{backup_filename}').")
    print(f"Created backup: {backup_filename}")
