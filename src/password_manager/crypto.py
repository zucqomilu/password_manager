import base64
import secrets
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives.kdf.argon2 import Argon2id
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.backends import default_backend

def generate_salt(len=16):
    return secrets.token_bytes(len)

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

# Derive the 32-byte key-encryption key from the master password with the user's stored Argon2id parameters.
# The parameters (salt, costs) are public; the returned key is never stored or logged.
def derive_master_key(password: str, params: dict) -> bytes:
    return Argon2id(
        salt=base64.b64decode(params["salt"]),
        length=32,
        iterations=params["time_cost"],
        lanes=params["parallelism"],
        memory_cost=params["memory_cost"],
    ).derive(password.encode())
