import re
import string
import secrets
import pyperclip
from .logger import logger
from .storage import load_vault, backup_vault, save_vault


def is_versioned_backup(label):
    return re.search(r"__v\d+$", label) is not None


def generate_password(length=16):
    chars = string.ascii_letters + string.digits + string.punctuation
    return ''.join(secrets.choice(chars) for _ in range(length))


def save_password(username, label, fernet, password=None, login=None, tags=None):
    logger.info(f"Attempting to save password for '{label}'.")

    vault = load_vault()
    if vault is None:
        print("Failed to load password vault. The vault may be corrupted or unreadable.")
        logger.error("Vault loading failed: returned None.")
        return
    
    if username not in vault:
        vault[username] = {}
        
    vault_data = vault[username]
    existing_entry = vault_data.get(label)

    if not existing_entry:
        if not password:
            print(f"Error: Cannot create label '{label}' without a password.")
            logger.warning(f"Attempted to create label '{label}' without a password.")
            return False
        existing_entry = {}

    if "password" in existing_entry and password:
        confirm = input(f"A password for '{label}' already exists. Overwrite? (y/N): ").strip().lower()
        if confirm != 'y':
            logger.info(f"User cancelled overwrite for '{label}'.")
            print("Operation cancelled.")
            return False

        try:
            old_password = fernet.decrypt(vault_data[label]["password"].encode())
            version = 1
            while f"{label}__v{version}" in vault_data:
                version += 1
            versioned_label = f"{label}__v{version}"
            vault_data[versioned_label] = { "password": fernet.encrypt(old_password).decode(),
                                            **({"login": existing_entry["login"]} if "login" in existing_entry else {}) }
            logger.info(f"Overwriting password for '{label}' (backup saved as '{versioned_label}').")
            print(f"Backed up previous password to '{versioned_label}'.")

            backup_vault()

        except:
            logger.error(f"Failed to overwrite '{label}' due to incorrect master password.")
            print(f"Error: A password already exists for '{label}', and the provided master password does not match.")
            return False

    if password:
        existing_entry["password"] = fernet.encrypt(password.encode()).decode()
        
    if login:
        existing_entry["login"] = fernet.encrypt(login.encode()).decode()

    if tags:
        existing_entry.setdefault("tags", [])
        existing_entry["tags"].extend(tags)

    vault_data[label] = existing_entry
    save_vault(vault)
    
    logger.info(f"Credentials saved for '{label}'.")
    print(f"Saved credentials for '{label}'.")
    
    return True


def get_password(username, label, fernet, show=False):
    logger.info(f"Attempting to retrieve password for '{label}'.")
    
    vault = load_vault()
    if vault is None:
        print("Failed to load password vault. The vault may be corrupted or unreadable.")
        logger.error("Vault loading failed: returned None.")
        return
    
    vault_data = vault.get(username, {})
    entry = vault_data.get(label)
    
    if entry:
        try:
            decrypted_pw = fernet.decrypt(entry["password"].encode()).decode()
            pyperclip.copy(decrypted_pw)
            logger.info(f"Password for '{label}' has been copied to the clipboard.")
            print(f"Password for '{label}' has been copied to the clipboard.")
            
            if "login" in entry:
                login = fernet.decrypt(entry["login"].encode()).decode()
                print(f"Login: {login}")
                
            if show:
                print(f"Password: {decrypted_pw}")
        except:
            logger.warning(f"Failed to decrypt password for '{label}' — possible wrong master password or corrupted data.")
            print("Incorrect master password or data corrupted.")
    else:
        logger.info(f"Label '{label}' not found in vault.")
        print(f"No password found for '{label}'.")


def list_labels(username, fernet):
    logger.info("Listing all stored password labels.")
    
    vault = load_vault()
    if vault is None:
        print("Failed to load password vault. The vault may be corrupted or unreadable.")
        logger.error("Vault loading failed: returned None.")
        return
    
    vault_user = vault.get(username, {})
    if not vault_user:
        logger.warning("No passwords found for this user.")
        print("No passwords found for this user.")
        return

    print("Stored labels:")
    for label, entry in vault_user.items():
        if is_versioned_backup(label):
            continue

        try:
            has_login = "login" in entry
            suffix = " (with login)" if has_login else ""
            fernet.decrypt(entry["password"].encode())
            print(f"- {label}{suffix}")
        except:
            continue
