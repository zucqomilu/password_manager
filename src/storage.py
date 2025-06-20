import os
import secrets
import shutil
import logging
from datetime import datetime

SALT_FILE = "salt.bin"

def __create_vault_backup():
    if not os.path.exists(DB_FILE):
        return
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    backup_filename = f"vault_backup_{timestamp}.json"
    shutil.copy2(DB_FILE, backup_filename)
    logging.info(f"Creating backup for '{backup_filename}' (backup saved as '{backup_filename}').")
    print(f"Created backup: {backup_filename}")


def generate_salt():
    return secrets.token_bytes(16)

def load_salt():
    if not os.path.exists(SALT_FILE):
        salt = generate_salt()
        with open(SALT_FILE, 'wb') as f:
            f.write(salt)
    else:
        with open(SALT_FILE, 'rb') as f:
            salt = f.read()
    return salt

def load_user_salt(username):
    users = load_users()
    if username in users:
        return base64.b64decode(users[username]['salt'])
    else:
        raise ValueError(f"User '{username}' not found.")
