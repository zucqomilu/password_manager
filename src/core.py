import string
import secrets
import pyperclip
from .logger import logger
from .storage import load_vault, backup_vault, save_vault

def generate_password(length=16):
    chars = string.ascii_letters + string.digits + string.punctuation
    return ''.join(secrets.choice(chars) for _ in range(length))

def save_password(username, label, password, fernet):
    logger.info(f"Attempting to save password for '{label}'.")

    vault = load_vault()
    
    if username not in vault:
        vault[username] = {}
        
    vault_user = vault[username]
    if label in vault_user:
        confirm = input(f"A password for '{label}' already exists. Overwrite? (y/N): ").strip().lower()
        if confirm != 'y':
            logger.info(f"User cancelled overwrite for '{label}'.")
            print("Operation cancelled.")
            return False

        try:
            old_password = fernet.decrypt(vault_user[label].encode())
            version = 1
            while f"{label}__v{version}" in vault_user:
                version += 1
            versioned_label = f"{label}__v{version}"
            vault_user[versioned_label] = fernet.encrypt(old_password).decode()
            logger.info(f"Overwriting password for '{label}' (backup saved as '{versioned_label}').")
            print(f"Backed up previous password to '{versioned_label}'.")

            backup_vault()

        except:
            logger.error(f"Failed to overwrite '{label}' due to incorrect master password.")
            print(f"Error: A password already exists for '{label}', and the provided master password does not match.")
            return False
    
    vault_user[label] = fernet.encrypt(password.encode()).decode()
    vault[username] = vault_user
    save_vault(vault)
        
    logger.info(f"Password saved for '{label}'.")
    print(f"Saved password for '{label}'.")
    return True

def get_password(username, label, fernet, show=False):
    logger.info(f"Attempting to retrieve password for '{label}'.")
    
    vault = load_vault()
    vault_user = vault.get(username, {})
    encrypted_hash = vault_user.get(label)
    
    if encrypted_hash:
        try:
            decrypted_hash = fernet.decrypt(encrypted_hash.encode()).decode()
            pyperclip.copy(decrypted_hash)
            logger.info(f"Password for '{label}' has been copied to the clipboard.")
            print(f"Password for '{label}' has been copied to the clipboard.")
            if show:
                print(f"Password: {decrypted_hash}")
        except:
            logger.warning(f"Failed to decrypt password for '{label}' — possible wrong master password or corrupted data.")
            print("Incorrect master password or data corrupted.")
    else:
        logger.info(f"Label '{label}' not found in vault.")
        print(f"No password found for '{label}'.")

def list_labels(username, fernet):
    logger.info("Listing all stored password labels.")
    
    vault = load_vault()
    vault_user = vault.get(username, {})
    if not vault_user:
        logger.warning("No passwords found for this user.")
        print("No passwords found for this user.")
        return

    print("Stored labels:")
    for label in vault_user:
        try:
            fernet.decrypt(vault_user[label].encode())
            print(f"- {label}")
        except:
            continue
