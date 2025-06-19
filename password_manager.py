#Would you like this to be extended with a menu-based UI, SQLite storage.
#TOTP integration Time-Based One Time Password
#Mask the copied value when displaying it
#Let me know if you'd like adding encryption for usernames or labels. Once you're ready, we can proceed to things like optional logout, session tokens, or improved CLI prompts.
#Delete password functionality.
#Password export/import (per-user).
#Later, we can add commands like logout, whoami, or implement session timeouts
#Implement session persistence across commands (e.g. by storing a session token or encrypted key on disk temporarily)
#Let me know if you'd like to also make the session more robust by including automatic logout, session expiration, or per-user session files.
#you should encrypt the session file, or store the session key only in memory (e.g., via an agent), or use OS-level secure storage (e.g., keyrings, credential manager)

import argparse
import secrets
import string
import json
import os
import base64
import getpass
import shutil
import logging
import pyperclip
import tempfile

from datetime import datetime
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.backends import default_backend

DB_FILE = "vault.json"
SALT_FILE = "salt.bin"
LOG_FILE = "vault.log"
USERS_FILE = "users.json"
SESSION_FILE = os.path.join(tempfile.gettempdir(), "session.json")

logging.basicConfig(
    filename=LOG_FILE,
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s",
    datefmt="%Y-%m-%d %H:%M:%S"
)

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

def save_session(username: str, key: bytes):
    session_data = {
        "username": username,
        "fernet_key": base64.urlsafe_b64encode(key).decode()
    }

    with open(SESSION_FILE, "w") as f:
        json.dump(session_data, f)

def load_session() -> tuple[str, Fernet] | None:
    if not os.path.exists(SESSION_FILE):
        return None

    with open(SESSION_FILE, "r") as f:
        try:
            session_data = json.load(f)
            username = session_data["username"]
            key = base64.urlsafe_b64decode(session_data["fernet_key"])
            return username, Fernet(key)
        except Exception as e:
            print(f"Error loading session: {e}")
            return None

def clear_session():
    if os.path.exists(SESSION_FILE):
        os.remove(SESSION_FILE)
        print("Session cleared.")

def __create_vault_backup():
    if not os.path.exists(DB_FILE):
        return
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    backup_filename = f"vault_backup_{timestamp}.json"
    shutil.copy2(DB_FILE, backup_filename)
    logging.info(f"Creating backup for '{backup_filename}' (backup saved as '{backup_filename}').")
    print(f"Created backup: {backup_filename}")

def authenticate_user(username: str, password: str) -> bytes:
    if not os.path.exists(USERS_FILE):
        raise ValueError("No users registered.")

    with open(USERS_FILE, 'r') as f:
        users = json.load(f)

    if username not in users:
        raise ValueError("User does not exist.")

    user_data = users[username]
    auth_salt = base64.b64decode(user_data["auth_salt"])
    enc_salt = base64.b64decode(user_data["enc_salt"])
    
    stored_key = user_data["password"]
    derived_auth_key = derive_key(password, auth_salt).decode()

    if derived_auth_key != stored_key:
        raise ValueError("Incorrect password.")

    # Use a different key for Fernet encryption
    fernet_key = derive_key(password + ":fernet", enc_salt)
    return fernet_key

def load_users():
    if os.path.exists(USERS_FILE):
        with open(USERS_FILE, 'r') as f:
            return json.load(f)
    return {}

def save_users(users):
    with open(USERS_FILE, 'w') as f:
        json.dump(users, f, indent=4)

def derive_key(password: str, salt: bytes) -> bytes:
    """Derive a 32-byte key from the password and salt."""
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=100_000,
        backend=default_backend()
    )
    return base64.urlsafe_b64encode(kdf.derive(password.encode()))

def register_user(username: str, master_password: str) -> bool:
    users = load_users()
    if username in users:
        print(f"User '{username}' already exists.")
        return False

    auth_salt = secrets.token_bytes(16)
    enc_salt = secrets.token_bytes(16)

    # Key for authentication
    auth_key = derive_key(master_password, auth_salt)
    users[username] = {
        "auth_salt": base64.b64encode(auth_salt).decode(),
        "enc_salt": base64.b64encode(enc_salt).decode(),
        "password": auth_key.decode()
    }
    
    save_users(users)
    print(f"User '{username}' registered successfully.")
    return True

def generate_password(length=16):
    chars = string.ascii_letters + string.digits + string.punctuation
    return ''.join(secrets.choice(chars) for _ in range(length))

def save_password(username, label, password, fernet):
    logging.info(f"Attempting to save password for '{label}'.")

    # Load existing data
    data = {}
    if os.path.exists(DB_FILE):
        with open(DB_FILE, 'r') as f:
            try:
                data = json.load(f)
            except json.JSONDecodeError:
                data = {}  # File is empty or invalid JSON
    
    # Ensure user exists in vault
    if username not in data:
        data[username] = {}
        
    user_data = data.get(username, {})
    
    if label in user_data:
        confirm = input(f"A password for '{label}' already exists. Overwrite? (y/N): ").strip().lower()
        if confirm != 'y':
            logging.info(f"User cancelled overwrite for '{label}'.")
            print("Operation cancelled.")
            return False

        try:
            # Try to decrypt existing to verify correct master password
            old_password = fernet.decrypt(user_data[label].encode())

            # Versioning: Save old password under label__vN
            version = 1
            while f"{label}__v{version}" in user_data:
                version += 1
            versioned_label = f"{label}__v{version}"
            user_data[versioned_label] = fernet.encrypt(old_password.encode()).decode()
            logging.info(f"Overwriting password for '{label}' (backup saved as '{versioned_label}').")
            print(f"Backed up previous password to '{versioned_label}'.")

            # Backup entire vault
            __create_vault_backup()

        except:
            logging.warning(f"Failed to overwrite '{label}' due to incorrect master password.")
            print(f"Error: A password already exists for '{label}', and the provided master password does not match.")
            return False
        
    encrypted = fernet.encrypt(password.encode()).decode()
    user_data[label] = encrypted
    data[username] = user_data

    with open(DB_FILE, 'w') as f:
        json.dump(data, f, indent=4)
        
    logging.info(f"Password saved for '{label}'.")
    print(f"Saved password for '{label}'.")
    return True

def get_password(username, label, fernet, show=False):
    logging.info(f"Attempting to retrieve password for '{label}'.")
    
    if not os.path.exists(DB_FILE):
        print("No passwords saved yet.")
        return

    with open(DB_FILE, 'r') as f:
        try:
            data = json.load(f)
        except json.JSONDecodeError:
            print("Vault is corrupted or empty.")
            return
        
    user_data = data.get(username, {})
    encrypted = user_data.get(label)
    
    if encrypted:
        try:
            decrypted = fernet.decrypt(encrypted.encode()).decode()
            logging.info(f"Password retrieved for '{label}'.")
            pyperclip.copy(decrypted)
            print(f"Password for '{label}' has been copied to the clipboard.")
            if show:
                print(f"Password: {decrypted}")
        except:
            logging.warning(f"Failed to decrypt password for '{label}' — possible wrong master password or corrupted data.")
            print("Incorrect master password or data corrupted.")
    else:
        logging.info(f"Label '{label}' not found in vault.")
        print(f"No password found for '{label}'.")

def list_labels(username, fernet):
    logging.info("Listing all stored password labels.")
    
    if not os.path.exists(DB_FILE):
        print("No passwords saved yet.")
        return

    with open(DB_FILE, 'r') as f:
        try:
            data = json.load(f)
        except json.JSONDecodeError:
            print("Vault is corrupted or empty.")
            return

    user_data = data.get(username, {})
    if not user_data:
        print("No passwords found for this user.")
        return

    print("Stored labels:")
    for label in user_data:
        try:
            fernet.decrypt(user_data[label].encode())  # Validate decryption
            print(f"- {label}")
        except:
            continue  # Skip labels that can't be decrypted with this password
        
def main():
    parser = argparse.ArgumentParser(description="Password Manager CLI")
    subparsers = parser.add_subparsers(dest='command')

    # Add command parsers
    subparsers.add_parser('register', help='Register a new user')
    parser_login = subparsers.add_parser('login', help='Login as an existing user')
    parser_logout = subparsers.add_parser('logout', help='Log out and clear session')

    gen_parser = subparsers.add_parser('generate', help='Generate and store a password')
    gen_parser.add_argument('label', help='Label for the password')
    gen_parser.add_argument('--length', type=int, default=16, help='Password length')

    get_parser = subparsers.add_parser('get', help='Get a password by label')
    get_parser.add_argument('label')
    get_parser.add_argument('--show', action='store_true', help='Show password in terminal')

    list_parser = subparsers.add_parser('list', help='List all saved password labels')

    # Parse args first
    args = parser.parse_args()

    # === REGISTER USER ===
    if args.command == 'register':
        username = input("Choose a username: ").strip()
        password = getpass.getpass("Choose a master password: ")
        if register_user(username, password):
            print("Registration successful.")
        return

    # === LOGIN USER ===
    if args.command == 'login' or args.command is None:
        username = input("Username: ").strip()
        password = getpass.getpass("Master password: ")
        try:
            # Authenticate and get Fernet instance (for session storage)
            fernet_key = authenticate_user(username, password)
            save_session(username, fernet_key)
            print(f"Login successful. Welcome, {username}!")
        except ValueError as e:
            print(f"Login failed: {e}")
            return

    # === LOGOUT USER ===
    if args.command == "logout":
        clear_session()
        return

    # === LOAD SESSION ===
    username, fernet = load_session()
    if not username or not fernet:
        print("You are not logged in. Please run `login` first.")
        return

    # === HANDLE USER COMMANDS ===
    if args.command == 'generate':
        pwd = generate_password(args.length)
        if save_password(username, args.label, pwd, fernet):
            logging.info(f"Generated new password for '{args.label}' with length {args.length}.")
            print(f"Generated password: {pwd}")
    elif args.command == 'get':
        get_password(username, args.label, fernet, show=args.show)
    elif args.command == 'list':
        list_labels(username, fernet)
    else:
        parser.print_help()

if __name__ == '__main__':
    main()
