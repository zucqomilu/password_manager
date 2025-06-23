import base64
from .crypto import derive_key, generate_salt
from .storage import save_users, load_users
from .logger import logger

def register_user(username: str, master_password: str) -> bool:
    users = load_users()
    if username in users:
        print(f"User '{username}' already exists.")
        logger.warning(f"User '{username}' already exists.")
        return False

    auth_salt = generate_salt()
    enc_salt = generate_salt()

    # Key for authentication
    auth_key = derive_key(master_password, auth_salt)
    users[username] = {
        "auth_salt": base64.b64encode(auth_salt).decode(),
        "enc_salt": base64.b64encode(enc_salt).decode(),
        "password": auth_key.decode()
    }
    
    save_users(users)
    print(f"User '{username}' registered successfully.")
    logger.info(f"User '{username}' registered successfully.")
    return True

def authenticate_user(username: str, password: str) -> bytes:
    users = load_users()
    if username not in users:
        logger.error("User does not exist.")
        raise ValueError("User does not exist.")

    user_data = users[username]
    auth_salt = base64.b64decode(user_data["auth_salt"])
    enc_salt = base64.b64decode(user_data["enc_salt"])
    
    stored_key = user_data["password"]
    derived_auth_key = derive_key(password, auth_salt).decode()

    if derived_auth_key != stored_key:
        logger.error("Incorrect password.")
        raise ValueError("Incorrect password.")

    # Use a different key for Fernet encryption
    fernet_key = derive_key(password + ":fernet", enc_salt)
    logger.info(f"User '{username}' authenticated successfully.")
    return fernet_key
