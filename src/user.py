import os
import json
import base64
import secrets
from crypto import derive_key

USERS_FILE = "users.json"

def load_users():
    if os.path.exists(USERS_FILE):
        with open(USERS_FILE, 'r') as f:
            return json.load(f)
    return {}

def save_users(users):
    with open(USERS_FILE, 'w') as f:
        json.dump(users, f, indent=4)

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
