import os
import string
import secrets
import json
import pyperclip
from .logger import logger
from .storage import backup_vault
from .constants import DB_FILE

def generate_password(length=16):
    chars = string.ascii_letters + string.digits + string.punctuation
    return ''.join(secrets.choice(chars) for _ in range(length))

def save_password(username, label, password, fernet):
    logger.info(f"Attempting to save password for '{label}'.")

    # Load existing data
    data = {}
    if os.path.exists(DB_FILE):
        with open(DB_FILE, 'r') as f:
            try:
                data = json.load(f)
            except json.JSONDecodeError:
                logger.error("File is empty or invalid JSON")
                data = {}
    
    # Ensure user exists in vault
    if username not in data:
        data[username] = {}
        
    user_data = data.get(username, {})
    if label in user_data:
        confirm = input(f"A password for '{label}' already exists. Overwrite? (y/N): ").strip().lower()
        if confirm != 'y':
            logger.info(f"User cancelled overwrite for '{label}'.")
            print("Operation cancelled.")
            return False

        try:
            # Try to decrypt existing to verify correct master password
            old_password = fernet.decrypt(user_data[label].encode())

            version = 1
            while f"{label}__v{version}" in user_data:
                version += 1
            versioned_label = f"{label}__v{version}"
            user_data[versioned_label] = fernet.encrypt(old_password).decode()
            logger.info(f"Overwriting password for '{label}' (backup saved as '{versioned_label}').")
            print(f"Backed up previous password to '{versioned_label}'.")

            # Backup entire vault
            backup_vault()

        except:
            logger.error(f"Failed to overwrite '{label}' due to incorrect master password.")
            print(f"Error: A password already exists for '{label}', and the provided master password does not match.")
            return False
        
    encrypted = fernet.encrypt(password.encode()).decode()
    user_data[label] = encrypted
    data[username] = user_data

    with open(DB_FILE, 'w') as f:
        json.dump(data, f, indent=4)
        
    logger.info(f"Password saved for '{label}'.")
    print(f"Saved password for '{label}'.")
    return True

def get_password(username, label, fernet, show=False):
    logger.info(f"Attempting to retrieve password for '{label}'.")
    
    if not os.path.exists(DB_FILE):
        logger.warning("No passwords saved yet.")
        print("No passwords saved yet.")
        return

    with open(DB_FILE, 'r') as f:
        try:
            data = json.load(f)
        except json.JSONDecodeError:
            logger.error("Vault is corrupted or empty.")
            print("Vault is corrupted or empty.")
            return
        
    user_data = data.get(username, {})
    encrypted = user_data.get(label)
    
    if encrypted:
        try:
            decrypted = fernet.decrypt(encrypted.encode()).decode()
            pyperclip.copy(decrypted)
            logger.info(f"Password for '{label}' has been copied to the clipboard.")
            print(f"Password for '{label}' has been copied to the clipboard.")
            if show:
                print(f"Password: {decrypted}")
        except:
            logger.warning(f"Failed to decrypt password for '{label}' — possible wrong master password or corrupted data.")
            print("Incorrect master password or data corrupted.")
    else:
        logger.info(f"Label '{label}' not found in vault.")
        print(f"No password found for '{label}'.")

def list_labels(username, fernet):
    logger.info("Listing all stored password labels.")
    
    if not os.path.exists(DB_FILE):
        logger.warning("No passwords saved yet.")
        print("No passwords saved yet.")
        return

    with open(DB_FILE, 'r') as f:
        try:
            data = json.load(f)
        except json.JSONDecodeError:
            logger.error("Vault is corrupted or empty.")
            print("Vault is corrupted or empty.")
            return

    user_data = data.get(username, {})
    if not user_data:
        logger.warning("No passwords found for this user.")
        print("No passwords found for this user.")
        return

    print("Stored labels:")
    for label in user_data:
        try:
            fernet.decrypt(user_data[label].encode())  # Validate decryption
            print(f"- {label}")
        except:
            continue  # Skip labels that can't be decrypted with this password
