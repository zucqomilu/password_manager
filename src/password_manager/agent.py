import json
import os
import socket
import stat
import struct
import time
from dataclasses import dataclass, field, replace

from cryptography.fernet import Fernet, InvalidToken

from .constants import CONNECTION_TIMEOUT, MAX_MESSAGE_SIZE, SESSION_TTL


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


# Seconds until the held key expires; the server loop uses it as its timeout so an idle agent exits on time
def remaining_ttl(state: AgentState, now: float) -> float:
    return SESSION_TTL - (now - state.last_activity)


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
        return state, {"ok": True, "username": state.username, "remaining_ttl": remaining_ttl(state, now)}
    if request["cmd"] == "ENCRYPT":
        return touch(state, {"ok": True, "token": Fernet(state.key).encrypt(request["plaintext"].encode()).decode()}, now)
    if request["cmd"] == "DECRYPT":
        return touch(state, decrypt_response(state.key, request["token"]), now)
    # Fixed error that never echoes the command back, and never extends the session
    return state, {"ok": False, "error": "unknown command"}


# Wire format: one UTF-8 JSON object per line. Plain JSON, never pickle, so decoding a message can never run code.
def encode_message(message: dict) -> bytes:
    return json.dumps(message).encode() + b"\n"


# One message per connection: stops at the first newline and never returns more than MAX_MESSAGE_SIZE + 1 bytes,
# however much the peer sends; the extra byte lets decode_message reject an oversized message. Anything after the
# newline is dropped with the stream, so no second request can hide behind the first. The socket itself stays open.
def read_message(conn: socket.socket) -> bytes:
    with conn.makefile("rb") as stream:
        return stream.readline(MAX_MESSAGE_SIZE + 1)


# Size is checked before parsing, so an oversized payload is never parsed. Raises ValueError like malformed JSON does.
def decode_message(data: bytes) -> dict:
    if len(data) > MAX_MESSAGE_SIZE:
        raise ValueError("message too large")
    return json.loads(data)


# Sends the response half of handle_request()'s (state, response) result and passes the result on.
# A handled request counts whether or not the client hears the answer: if the send fails, a LOCK must still drop
# the key. The failure is not logged, because the response can hold a decrypted password.
def respond(conn: socket.socket, result: tuple[AgentState, dict]) -> tuple[AgentState, dict]:
    try:
        conn.sendall(encode_message(result[1]))
    except OSError:
        pass
    return result


# A request that is not JSON, not UTF-8, too large or the wrong shape gets one fixed error and never crashes the
# agent. The exception is never sent or logged: a JSONDecodeError carries the raw input, which can hold a key or a
# password. expire() still runs, so garbage requests cannot keep an expired key alive.
def handle_data(state: AgentState, data: bytes, now: float) -> tuple[AgentState, dict]:
    try:
        return handle_request(state, decode_message(data), now)
    except (ValueError, KeyError, TypeError, AttributeError):
        return expire(state, now), {"ok": False, "error": "malformed request"}


# One request per connection, read through the size-limited read_message(). Only handle_request()'s response
# is sent back, and that core never puts the key in a response.
# The peer is checked before a single byte is read: an unauthorized peer gets no reply, only a closed connection,
# and its result has no shutdown, so it can neither use nor stop the agent.
# A peer that sends nothing is dropped after CONNECTION_TIMEOUT, so it cannot block the loop and keep the key past
# its TTL. Only the read is covered: a handled request's new state (a LOCK, say) must never be thrown away.
def serve_connection(state: AgentState, conn: socket.socket, now: float) -> tuple[AgentState, dict]:
    if not is_authorized_peer(conn):
        conn.shutdown(socket.SHUT_RDWR)
        return state, {"ok": False, "error": "unauthorized"}
    conn.settimeout(CONNECTION_TIMEOUT)
    try:
        data = read_message(conn)
    except TimeoutError:
        return expire(state, now), {"ok": False, "error": "timeout"}
    return respond(conn, handle_data(state, data, now))


# The kernel records the peer's struct ucred (int pid, unsigned uid, unsigned gid) at connect time, so a client cannot fake it.
# Only processes running as the same user may talk to the agent, the same rule as ssh-agent.
def is_authorized_peer(conn: socket.socket) -> bool:
    return struct.unpack("iII", conn.getsockopt(socket.SOL_SOCKET, socket.SO_PEERCRED, struct.calcsize("iII")))[1] == os.getuid()


# A refused connect means nobody is listening; a successful one means an agent is running there
def is_live_socket(path: str) -> bool:
    with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as probe:
        try:
            probe.connect(path)
            return True
        except ConnectionRefusedError:
            return False


# Only a socket file (lstat: a symlink is never followed) that no agent answers on is stale.
# The S_ISSOCK check matters: connect() to a regular file is also refused, and that file must never be removed.
def is_stale_socket(path: str) -> bool:
    try:
        return stat.S_ISSOCK(os.lstat(path).st_mode) and not is_live_socket(path)
    except FileNotFoundError:
        return False


# The dir is forced to 0700 before bind, so no other user can reach the socket even before its own chmod to 0600.
# chmod on a dir owned by someone else raises, so the agent never listens in a dir others control.
def create_listener(path: str) -> socket.socket:
    os.makedirs(os.path.dirname(path), mode=0o700, exist_ok=True)
    os.chmod(os.path.dirname(path), 0o700)
    # A dead agent's leftover socket would make bind fail and block every login until removed by hand
    if is_stale_socket(path):
        os.unlink(path)
    listener = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    listener.bind(path)
    os.chmod(path, 0o600)
    listener.listen()
    return listener


# The agent's accept loop: one connection at a time, the state carried from each request to the next, until a
# response signals shutdown. A while loop that rebinds result, against the no-reassignment convention on purpose:
# recursion (one call per request) would hit Python's recursion limit after about 1000 requests and kill the session.
# The finally removes the socket even if something raises, so a crashed agent never leaves a stale socket behind.
def run_agent(listener: socket.socket) -> None:
    try:
        result = (AgentState(), {})
        while not result[1].get("shutdown"):
            with listener.accept()[0] as conn:
                result = serve_connection(result[0], conn, time.time())
    finally:
        os.unlink(listener.getsockname())
        listener.close()
