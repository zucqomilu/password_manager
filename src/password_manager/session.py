import os
from collections.abc import Callable
from dataclasses import dataclass
from functools import partial

import keyring
from keyring.errors import KeyringError, PasswordDeleteError
from cryptography.fernet import InvalidToken

from . import agent
from .constants import KEYRING_ACCOUNT, KEYRING_SERVICE, MAX_SOCKET_PATH, get_socket_path
from .logger import logger


# True once a running agent has taken the key. Socket errors (a taken path, a permission problem, a timeout)
# count as not reached; they are not shown, since only save_session()'s fixed message is.
# The key reaches the agent only over its 0600, peer-checked socket: never argv, the environment or the log.
def unlock_agent(username: str, key: bytes) -> bool:
    try:
        agent.start_agent(get_socket_path())
        return agent.send_request(get_socket_path(), {"cmd": "UNLOCK", "username": username, "key": key.decode()}) is not None
    except OSError:
        return False


# Older pm versions kept the raw key in the OS keyring between commands. Login removes that entry, so after the
# upgrade the key lives only in the agent's memory. No entry (already removed, or never written) is fine.
# A keyring that cannot be reached must never block login: the removal is retried at every login, and only a
# warning without the error's details goes to the log.
def delete_legacy_session():
    try:
        keyring.delete_password(KEYRING_SERVICE, KEYRING_ACCOUNT)
    except PasswordDeleteError:
        pass
    except KeyringError:
        logger.warning("Could not reach the keyring to remove the legacy session entry.")


# A path the kernel would reject fails with the reason and the fix, before any socket call. Measured in bytes, as
# the kernel does, so a non-ASCII directory name counts at its encoded length.
def check_socket_path(path: str):
    size = len(os.fsencode(path))
    if size > MAX_SOCKET_PATH:
        raise ValueError(f"the session agent socket path is too long ({size} bytes, at most {MAX_SOCKET_PATH}); set a shorter PM_AGENT_SOCKET")


# The legacy entry goes first, so even a login that then fails removes it. A bad socket path stops the login
# before any agent is started or sent the key.
def save_session(username: str, key: bytes):
    delete_legacy_session()
    check_socket_path(get_socket_path())

    # Login only succeeds once the agent holds the key. Raised as ValueError, so main() prints "Login failed: ..."
    # through its existing handler instead of a traceback or a false "Login successful".
    if not unlock_agent(username, key):
        raise ValueError("could not start the session agent")

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

        # No agent (never started, logged out or exited at the TTL), or locked or expired: either way not logged in.
        # The agent enforces the TTL, and STATUS never extends it.
        if status is None or not status["ok"]:
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


# LOCK is sent whatever STATUS says, so the key always leaves the agent's memory; STATUS only picks the message.
# With no agent running, both requests return None and nothing is started. The legacy entry goes through
# delete_legacy_session(), so an unreachable keyring cannot break logout either.
def clear_session():
    status = agent.send_request(get_socket_path(), {"cmd": "STATUS"})
    agent.send_request(get_socket_path(), {"cmd": "LOCK"})
    delete_legacy_session()

    if status is not None and status["ok"]:
        logger.info("Session cleared.")
        print("Session cleared.")
    else:
        logger.warning("No session to clear.")
        print("No session to clear.")
