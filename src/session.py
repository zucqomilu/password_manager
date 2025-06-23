import os
import json
import base64
from cryptography.fernet import Fernet
from .logger import logger
import src.constants

def save_session(username: str, key: bytes):
    session_data = {
        "username": username,
        "fernet_key": base64.urlsafe_b64encode(key).decode()
    }

    with open(src.constants.get_session_file(), "w") as f:
        json.dump(session_data, f)
        logger.info(f"Session saved for user: {username}")

def load_session() -> tuple[str, Fernet] | None:
    if not os.path.exists(src.constants.get_session_file()):
        logger.info("No session found.")
        return None

    with open(src.constants.get_session_file(), "r") as f:
        try:
            session_data = json.load(f)
            username = session_data["username"]
            key = base64.urlsafe_b64decode(session_data["fernet_key"])
            return username, Fernet(key)
        except Exception as e:
            logger.error(f"Error loading session: {e}")
            print(f"Error loading session: {e}")
            return None

def clear_session():
    if os.path.exists(src.constants.get_session_file()):
        os.remove(src.constants.get_session_file())
        logger.info("Session cleared.")
        print("Session cleared.")
