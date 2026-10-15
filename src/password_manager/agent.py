from dataclasses import dataclass


# What the agent holds between requests. All None means locked.
@dataclass(frozen=True)
class AgentState:
    username: str | None = None
    key: bytes | None = None
    last_activity: float | None = None


# Pure core of the session agent: takes the current state, one request and the current time,
# and returns the new state plus the response to send back. The key is never put in a response.
def handle_request(state: AgentState, request: dict, now: float) -> tuple[AgentState, dict]:
    if request["cmd"] == "UNLOCK":
        return AgentState(username=request["username"], key=request["key"].encode(), last_activity=now), {"ok": True}
