from dataclasses import dataclass, field, replace

from cryptography.fernet import Fernet, InvalidToken

from .constants import SESSION_TTL


# What the agent holds between requests. All None means locked.
# repr=False keeps the key out of any log line, print or traceback that shows the state.
@dataclass(frozen=True)
class AgentState:
    username: str | None = None
    key: bytes | None = field(default=None, repr=False)
    last_activity: float | None = None


# A tampered, corrupt or foreign token never yields plaintext; the error carries no token, plaintext or key
def decrypt_response(key: bytes, token: str) -> dict:
    try:
        return {"ok": True, "plaintext": Fernet(key).decrypt(token.encode()).decode()}
    except InvalidToken:
        return {"ok": False, "error": "invalid token"}


# Drop the key once it has been idle for SESSION_TTL (same >= boundary as the keyring session)
def expire(state: AgentState, now: float) -> AgentState:
    return AgentState() if state.key is not None and now - state.last_activity >= SESSION_TTL else state


# Only a successful use of the key counts as activity; failed or locked requests never extend the session
def touch(state: AgentState, response: dict, now: float) -> tuple[AgentState, dict]:
    return (replace(state, last_activity=now) if response["ok"] else state), response


# Pure core of the session agent: takes the current state, one request and the current time,
# and returns the new state plus the response to send back. The key is never put in a response.
def handle_request(state: AgentState, request: dict, now: float) -> tuple[AgentState, dict]:
    return dispatch(expire(state, now), request, now)


def dispatch(state: AgentState, request: dict, now: float) -> tuple[AgentState, dict]:
    if request["cmd"] == "UNLOCK":
        return AgentState(username=request["username"], key=request["key"].encode(), last_activity=now), {"ok": True}
    # Drops the key whatever the state; shutdown tells the server loop to reply, close the socket and exit
    if request["cmd"] == "LOCK":
        return AgentState(), {"ok": True, "shutdown": True}
    # Checked before any Fernet call or TTL arithmetic, so a locked agent answers cleanly instead of
    # failing on a missing key, and never says which user was logged in
    if request["cmd"] in ("ENCRYPT", "DECRYPT", "STATUS") and state.key is None:
        return state, {"ok": False, "error": "locked"}
    # Not passed through touch(): checking the status must never keep the key alive
    if request["cmd"] == "STATUS":
        return state, {"ok": True, "username": state.username, "remaining_ttl": SESSION_TTL - (now - state.last_activity)}
    if request["cmd"] == "ENCRYPT":
        return touch(state, {"ok": True, "token": Fernet(state.key).encrypt(request["plaintext"].encode()).decode()}, now)
    if request["cmd"] == "DECRYPT":
        return touch(state, decrypt_response(state.key, request["token"]), now)
    # Fixed error that never echoes the command back, and never extends the session
    return state, {"ok": False, "error": "unknown command"}
