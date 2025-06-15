#Would you like this to be extended with a menu-based UI, SQLite storage.
#TOTP integration Time-Based One Time Password
#Mask the copied value when displaying it
#Let me know if you'd like adding encryption for usernames or labels. Once you're ready, we can proceed to things like optional logout, session tokens, or improved CLI prompts.

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

from datetime import datetime
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.backends import default_backend

DB_FILE = "vault.json"
SALT_FILE = "salt.bin"
LOG_FILE = "vault.log"
USERS_FILE = "users.json"

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

def get_key_from_password(password: str, salt: bytes) -> bytes:
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=100_000,
        backend=default_backend()
    )
    return base64.urlsafe_b64encode(kdf.derive(password.encode()))

def get_fernet(master_password):
    salt = load_salt()
    key = get_key_from_password(master_password, salt)
    return Fernet(key)

def __create_vault_backup():
    if not os.path.exists(DB_FILE):
        return
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    backup_filename = f"vault_backup_{timestamp}.json"
    shutil.copy2(DB_FILE, backup_filename)
    logging.info(f"Creating backup for '{backup_filename}' (backup saved as '{backup_filename}').")
    print(f"Created backup: {backup_filename}")

def load_users():
    if os.path.exists(USERS_FILE):
        with open(USERS_FILE, 'r') as f:
            return json.load(f)
    return {}

def save_users(users):
    with open(USERS_FILE, 'w') as f:
        json.dump(users, f, indent=4)

def hash_master_password(password: str, salt: bytes) -> str:
    key = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=100_000,
        backend=default_backend()
    ).derive(password.encode())
    return base64.urlsafe_b64encode(key).decode()

def register_user(username: str, master_password: str) -> bool:
    users = load_users()
    if username in users:
        print(f"User '{username}' already exists.")
        return False
    salt = secrets.token_bytes(16)
    hashed_password = hash_master_password(master_password, salt)
    users[username] = {
        "salt": base64.b64encode(salt).decode(),
        "password": hashed_password
    }
    save_users(users)
    print(f"User '{username}' registered successfully.")
    return True

def login_user(username: str, master_password: str) -> bool:
    users = load_users()
    if username not in users:
        print(f"User '{username}' not found.")
        return False
    salt = base64.b64decode(users[username]["salt"])
    hashed_input = hash_master_password(master_password, salt)
    if hashed_input == users[username]["password"]:
        return True
    else:
        print("Incorrect master password.")
        return False

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
        try:
            # Try to decrypt existing to verify correct master password
            fernet.decrypt(user_data[label].encode())
            
            confirm = input(f"A password for '{label}' already exists. Overwrite? (y/N): ").strip().lower()
            if confirm != 'y':
                logging.info(f"User cancelled overwrite for '{label}'.")
                print("Operation cancelled.")
                return False

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

    # Command options (after login)
    gen_parser = subparsers.add_parser('generate', help='Generate and store a password')
    gen_parser.add_argument('label', help='Label for the password')
    gen_parser.add_argument('--length', type=int, default=16, help='Password length')

    get_parser = subparsers.add_parser('get', help='Get a password by label')
    get_parser.add_argument('label')
    get_parser.add_argument('--show', action='store_true', help='Show password in terminal')

    list_parser = subparsers.add_parser('list', help='List all saved password labels')

    # Parse args first
    args = parser.parse_args()

    if not args.command:
        parser.print_help()
        return

    # --- LOGIN / REGISTER flow ---
    print("Welcome to the Password Manager!")
    while True:
        action = input("Do you want to (l)ogin or (r)egister? ").strip().lower()
        if action not in ('l', 'r'):
            print("Please type 'l' to login or 'r' to register.")
            continue

        username = input("Username: ").strip()
        master_password = getpass.getpass("Master password: ").strip()

        if action == 'r':
            if register_user(username, master_password):
                break
        elif action == 'l':
            if login_user(username, master_password):
                break
        print("Try again.")
        
    # Derive Fernet key from the user's master password and salt
    users = load_users()
    salt = base64.b64decode(users[username]["salt"])
    fernet = get_fernet(master_password)

    # Command execution (user is now authenticated)
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
