import base64
import secrets
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.backends import default_backend
from .user import load_users

def generate_salt():
    return secrets.token_bytes(16)

def load_user_salt(username):
    users = load_users()
    if username in users:
        return base64.b64decode(users[username]['salt'])
    else:
        raise ValueError(f"User '{username}' not found.")

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
