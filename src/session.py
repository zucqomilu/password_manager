import json
import base64
import time

import keyring
from keyring.errors import PasswordDeleteError
from cryptography.fernet import Fernet

from .constants import KEYRING_ACCOUNT, KEYRING_SERVICE
from .logger import logger


def save_session(username: str, key: bytes):
    session_data = {
        "username": username,
        "fernet_key": base64.urlsafe_b64encode(key).decode(),
        "last_activity": time.time()
    }

    keyring.set_password(
        KEYRING_SERVICE,
        KEYRING_ACCOUNT,
        json.dumps(session_data),
    )

    logger.info(f"Session saved for user: {username}")

def load_session() -> tuple[str, Fernet] | None:
    try:
        stored_data = keyring.get_password(
            KEYRING_SERVICE,
            KEYRING_ACCOUNT,
        )

        if stored_data is None:
            logger.info("No session found.")
            return None

        session_data = json.loads(stored_data)

        username = session_data["username"]
        key = base64.urlsafe_b64decode(session_data["fernet_key"])

        return username, Fernet(key)

    except Exception as e:
        logger.error(f"Error loading session: {e}")
        print(f"Error loading session: {e}")
        return None

def clear_session():
    try:
        keyring.delete_password(
            KEYRING_SERVICE,
            KEYRING_ACCOUNT,
        )
        logger.info("Session cleared.")
        print("Session cleared.")

    except PasswordDeleteError:
        logger.warning("No session to clear.")
        print("No session to clear.")
