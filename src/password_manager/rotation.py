# Every password and login of username, decrypted with old and encrypted with new; tags and other users unchanged.
# Pure: the caller decides whether to save, so a failure here leaves nothing written.
def reencrypt_vault(vault, username, old, new):
    return {user: {label: reencrypt_entry(entry, old, new) for label, entry in entries.items()} if user == username else entries
            for user, entries in vault.items()}


def reencrypt_entry(entry, old, new):
    return {field: new.encrypt(old.decrypt(value.encode())).decode() if field in ("password", "login") else value
            for field, value in entry.items()}
