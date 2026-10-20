import json
import base64
import time
from collections.abc import Callable
from dataclasses import dataclass
from functools import partial

import keyring
from keyring.errors import PasswordDeleteError
from cryptography.fernet import InvalidToken

from . import agent
from .constants import KEYRING_ACCOUNT, KEYRING_SERVICE, get_socket_path
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

    # The key reaches the agent only over its 0600, peer-checked socket: never argv, the environment or the log.
    # The keyring entry above is written first, so it keeps pm usable if the agent cannot be started.
    agent.start_agent(get_socket_path())
    agent.send_request(get_socket_path(), {"cmd": "UNLOCK", "username": username, "key": key.decode()})

    logger.info(f"Session saved for user: {username}")


# Data only: core.py calls .encrypt() and .decrypt() as on a Fernet, but both go to the agent,
# so after login the key never enters a pm process again
@dataclass(frozen=True)
class AgentCipher:
    encrypt: Callable[[bytes], bytes]
    decrypt: Callable[[bytes], bytes]


# Raised when the agent no longer holds the key (locked, expired or exited); carries no message or data
class SessionLocked(Exception):
    pass


# The cipher's one route to the agent: a missing agent or a "locked" answer becomes SessionLocked, never InvalidToken,
# so an expired session is never mistaken for a damaged vault entry
def agent_response(path: str, request: dict) -> dict:
    response = agent.send_request(path, request)
    if response is None or response.get("error") == "locked":
        raise SessionLocked
    return response


def agent_encrypt(path: str, data: bytes) -> bytes:
    return agent_response(path, {"cmd": "ENCRYPT", "plaintext": data.decode()})["token"].encode()


# A token the agent cannot decrypt raises InvalidToken, as Fernet would, so core.py can still report a damaged entry
def agent_decrypt(path: str, token: bytes) -> bytes:
    response = agent_response(path, {"cmd": "DECRYPT", "token": token.decode()})
    if response.get("error") == "invalid token":
        raise InvalidToken
    return response["plaintext"].encode()


def load_session() -> tuple[str, AgentCipher] | None:
    try:
        status = agent.send_request(get_socket_path(), {"cmd": "STATUS"})

        # Locked or expired: the agent enforces the TTL, and STATUS never extends it
        if not status["ok"]:
            logger.info("No session found.")
            return None

        return status["username"], AgentCipher(
            encrypt=partial(agent_encrypt, get_socket_path()),
            decrypt=partial(agent_decrypt, get_socket_path()),
        )

    except Exception as e:
        logger.error(f"Error loading session: {e}")
        print(f"Error loading session: {e}")
        return None


def refresh_session() -> bool:
    stored_data = keyring.get_password(
        KEYRING_SERVICE,
        KEYRING_ACCOUNT,
    )

    if stored_data is None:
        logger.info("No session found to refresh.")
        return False

    try:
        session_data = json.loads(stored_data)

        session_data["last_activity"] = time.time()

        keyring.set_password(
            KEYRING_SERVICE,
            KEYRING_ACCOUNT,
            json.dumps(session_data),
        )

        logger.info(
            f"Session activity refreshed for user: "
            f"{session_data['username']}"
        )

        return True

    except Exception as e:
        logger.error(f"Error refreshing session: {e}")
        return False


def clear_session():
    # Sent before the keyring delete, so the key leaves the agent's memory even if that delete fails.
    # With no agent running, send_request() returns None and nothing is started.
    agent.send_request(get_socket_path(), {"cmd": "LOCK"})
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
