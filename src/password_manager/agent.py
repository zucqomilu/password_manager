from dataclasses import dataclass, field

from cryptography.fernet import Fernet


# What the agent holds between requests. All None means locked.
# repr=False keeps the key out of any log line, print or traceback that shows the state.
@dataclass(frozen=True)
class AgentState:
    username: str | None = None
    key: bytes | None = field(default=None, repr=False)
    last_activity: float | None = None


# Pure core of the session agent: takes the current state, one request and the current time,
# and returns the new state plus the response to send back. The key is never put in a response.
def handle_request(state: AgentState, request: dict, now: float) -> tuple[AgentState, dict]:
    if request["cmd"] == "UNLOCK":
        return AgentState(username=request["username"], key=request["key"].encode(), last_activity=now), {"ok": True}
    if request["cmd"] == "ENCRYPT":
        return state, {"ok": True, "token": Fernet(state.key).encrypt(request["plaintext"].encode()).decode()}
