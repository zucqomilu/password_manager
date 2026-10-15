from dataclasses import dataclass, field

from cryptography.fernet import Fernet, InvalidToken


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


# Pure core of the session agent: takes the current state, one request and the current time,
# and returns the new state plus the response to send back. The key is never put in a response.
def handle_request(state: AgentState, request: dict, now: float) -> tuple[AgentState, dict]:
    if request["cmd"] == "UNLOCK":
        return AgentState(username=request["username"], key=request["key"].encode(), last_activity=now), {"ok": True}
    # Checked before any Fernet call, so a locked agent answers cleanly instead of failing on a missing key
    if request["cmd"] in ("ENCRYPT", "DECRYPT") and state.key is None:
        return state, {"ok": False, "error": "locked"}
    if request["cmd"] == "ENCRYPT":
        return state, {"ok": True, "token": Fernet(state.key).encrypt(request["plaintext"].encode()).decode()}
    if request["cmd"] == "DECRYPT":
        return state, decrypt_response(state.key, request["token"])
