import os
import json
import base64
import tempfile
from cryptography.fernet import Fernet
from .logger import logger

SESSION_FILE = os.path.join(tempfile.gettempdir(), "session.json")

def save_session(username: str, key: bytes):
    session_data = {
        "username": username,
        "fernet_key": base64.urlsafe_b64encode(key).decode()
    }

    with open(SESSION_FILE, "w") as f:
        json.dump(session_data, f)
        logger.info(f"Session saved for user: {username}")

def load_session() -> tuple[str, Fernet] | None:
    if not os.path.exists(SESSION_FILE):
        logger.info("No session found.")
        return None

    with open(SESSION_FILE, "r") as f:
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
    if os.path.exists(SESSION_FILE):
        os.remove(SESSION_FILE)
        logger.info("Session cleared.")
        print("Session cleared.")
