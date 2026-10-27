import re
import string
import secrets
import pyperclip
from cryptography.fernet import InvalidToken
from .logger import logger
from .storage import Storage, load_vault, backup_vault, save_vault


def is_versioned_backup(label):
    return re.search(r"__v\d+$", label) is not None


def generate_password(length=16):
    chars = string.ascii_letters + string.digits + string.punctuation
    return ''.join(secrets.choice(chars) for _ in range(length))


# The JSON storage, built from this module's own names at call time so patches of core.load_vault and the others apply
def json_storage():
    return Storage(load_vault=load_vault, save_vault=save_vault, backup_vault=backup_vault)


def save_password(username, label, fernet, password=None, login=None, tags=None, storage=None):
    logger.info(f"Attempting to save password for '{label}'.")

    store = storage or json_storage()
    vault = store.load_vault()
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

            store.backup_vault()

        # Only an old password that will not decrypt is reported as a wrong master password;
        # SessionLocked and a failed backup propagate, and either way nothing is saved
        except InvalidToken:
            logger.error(f"Failed to overwrite '{label}' due to incorrect master password.")
            print(f"Error: A password already exists for '{label}', and the provided master password does not match.")
            return False

    if password:
        existing_entry["password"] = fernet.encrypt(password.encode()).decode()
        
    if login:
        existing_entry["login"] = fernet.encrypt(login.encode()).decode()

    if tags:
        existing_entry.setdefault("tags", [])

        for tag in tags:
            if tag not in existing_entry["tags"]:
                existing_entry["tags"].append(tag)

    vault_data[label] = existing_entry
    store.save_vault(vault)
    
    logger.info(f"Credentials saved for '{label}'.")
    print(f"Saved credentials for '{label}'.")
    
    return True


# A missing clipboard tool must not hide the password: report it and carry on, so --login and --show still print.
# The exception is never printed or logged.
def copy_to_clipboard(label, password):
    try:
        pyperclip.copy(password)
        logger.info(f"Password for '{label}' has been copied to the clipboard.")
        print(f"Password for '{label}' has been copied to the clipboard.")
    except pyperclip.PyperclipException:
        logger.warning(f"Could not copy the password for '{label}' to the clipboard.")
        print(f"Could not copy the password for '{label}' to the clipboard.")


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
            copy_to_clipboard(label, decrypted_pw)
            
            if "login" in entry:
                login = fernet.decrypt(entry["login"].encode()).decode()
                print(f"Login: {login}")
                
            if show:
                print(f"Password: {decrypted_pw}")
        # Only a damaged entry is reported as such: SessionLocked must reach main() and ask for login
        except InvalidToken:
            logger.warning(f"Failed to decrypt password for '{label}' — possible wrong master password or corrupted data.")
            print("Incorrect master password or data corrupted.")
    else:
        logger.info(f"Label '{label}' not found in vault.")
        print(f"No password found for '{label}'.")


def list_labels(username, fernet, tags=None):
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

    found = False

    print("Stored labels:")

    for label, entry in vault_user.items():
        if is_versioned_backup(label):
            continue

        if tags and not all(tag in entry.get("tags", []) for tag in tags):
            continue

        try:
            has_login = "login" in entry
            suffix = " (with login)" if has_login else ""
            fernet.decrypt(entry["password"].encode())
            print(f"- {label}{suffix}")
            found = True
        # Only a damaged entry is left out: SessionLocked must reach main(), never shorten the list
        except InvalidToken:
            continue

    if tags is not None and not found:
        if len(tags) == 1:
            print(f"No passwords found with tag '{tags[0]}'.")
        else:
            print(f"No passwords found with tags: {', '.join(tags)}.")


def remove_tags(username, label, tags):
    vault = load_vault()

    if vault is None:
        print("Failed to load password vault. The vault may be corrupted or unreadable.")
        logger.error("Vault loading failed: returned None.")
        return

    if label not in vault[username]:
        print(f"Password label '{label}' not found.")
        logger.warning("Password label '%s' not found.", label)
        return

    entry = vault[username][label]
    existing_tags = entry.get("tags", [])
    removed = False

    for tag in tags:
        if tag in existing_tags:
            existing_tags.remove(tag)
            removed = True

    if not removed:
        return

    if not existing_tags:
        entry.pop("tags", None)

    save_vault(vault)


def decrypts(fernet, token):
    try:
        fernet.decrypt(token.encode())
        return True
    except InvalidToken:
        return False


# Check every entry, versioned backups included, without ever returning or logging a decrypted value
def verify_vault(username, fernet):
    vault = load_vault()
    if vault is None:
        return None
    entries = vault.get(username, {})
    bad_password = [label for label, entry in entries.items() if not decrypts(fernet, entry["password"])]
    bad_login = [label for label, entry in entries.items() if "login" in entry and not decrypts(fernet, entry["login"])]
    return {"ok": len(entries.keys() - {*bad_password, *bad_login}), "bad_password": bad_password, "bad_login": bad_login}


def delete_label(username, label):
    vault = load_vault()
    if vault is None:
        print("Failed to load password vault. The vault may be corrupted or unreadable.")
        logger.error("Vault loading failed: returned None.")
        return
    if label not in vault.get(username, {}):
        print(f"Password label '{label}' not found.")
        return
    if input(f"Delete '{label}'? A backup is made first. (y/N): ").strip().lower() != 'y':
        print("Operation cancelled.")
        return
    backup_vault()
    save_vault({**vault, username: {name: entry for name, entry in vault[username].items() if name != label}})
