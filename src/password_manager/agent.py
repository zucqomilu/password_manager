import errno
import json
import os
import socket
import stat
import struct
import subprocess
import sys
import time
from dataclasses import dataclass, field, replace

from cryptography.fernet import Fernet, InvalidToken

from .constants import CONNECTION_TIMEOUT, MAX_MESSAGE_SIZE, SESSION_TTL
from .memory import harden_process, lock_buffer, wipe


# What the agent holds between requests. All None means locked.
# repr=False keeps the key out of any log line, print or traceback that shows the state. A bytearray, not bytes, so the
# agent can zero it in place when the key is dropped.
@dataclass(frozen=True)
class AgentState:
    username: str | None = None
    key: bytearray | None = field(default=None, repr=False)
    last_activity: float | None = None


# A tampered, corrupt or foreign token never yields plaintext; the error carries no token, plaintext or key
def decrypt_response(key: bytes, token: str) -> dict:
    try:
        return {"ok": True, "plaintext": Fernet(key).decrypt(token.encode()).decode()}
    except InvalidToken:
        return {"ok": False, "error": "invalid token"}


# Drop the key once it has been idle for SESSION_TTL (same >= boundary as the keyring session).
# Zeroed in place first, as on LOCK: every request (also a malformed one, or a silent peer) passes through here.
def expire(state: AgentState, now: float) -> AgentState:
    if state.key is not None and now - state.last_activity >= SESSION_TTL:
        wipe(state.key)
        return AgentState()
    return state


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


# Zeroes the key the state holds, if any: for the branches that replace or drop it
def wipe_key(state: AgentState) -> None:
    if state.key is not None:
        wipe(state.key)


def dispatch(state: AgentState, request: dict, now: float) -> tuple[AgentState, dict]:
    # The request's str and the bytes from encode() are copies no code can zero; only the bytearray is wipeable.
    # Locked into RAM at once, so the held copy is never swapped; a refusal only logs a warning, the login still works.
    # A key already held (a second login, maybe another user's) is zeroed, but only after every field of the request
    # has been read: a malformed UNLOCK raises before the wipe, so the agent keeps its current key intact and usable.
    if request["cmd"] == "UNLOCK":
        username, key = request["username"], bytearray(request["key"].encode())
        wipe_key(state)
        lock_buffer(key)
        return AgentState(username=username, key=key, last_activity=now), {"ok": True}
    # Drops the key whatever the state; shutdown tells the server loop to reply, close the socket and exit.
    # The old buffer is zeroed first, on purpose a side effect in this otherwise pure core: dropping it would leave
    # the key in memory until the garbage collector reuses it. One request at a time, so nothing else is using it.
    if request["cmd"] == "LOCK":
        wipe_key(state)
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


# How long the agent waits for the next connection before exiting. With a key held, only until that key expires:
# a fresh full TTL after every connection would let STATUS checks or stray connections keep the key in memory
# forever. Floored at 0 because settimeout() rejects negative values. Locked, it waits SESSION_TTL for an UNLOCK,
# so an agent spawned by a login that never sent one does not linger forever.
def accept_timeout(state: AgentState, now: float) -> float:
    return max(0.0, remaining_ttl(state, now)) if state.key is not None else SESSION_TTL


# The agent's accept loop: one connection at a time, the state carried from each request to the next, until a
# response signals shutdown. A while loop that rebinds result, against the no-reassignment convention on purpose:
# recursion (one call per request) would hit Python's recursion limit after about 1000 requests and kill the session.
# The finally removes the socket even if something raises, so a crashed agent never leaves a stale socket behind.
# Only accept() is covered by the timeout handling: serve_connection() handles its own timeouts.
def run_agent(listener: socket.socket) -> None:
    try:
        result = (AgentState(), {})
        while not result[1].get("shutdown"):
            listener.settimeout(accept_timeout(result[0], time.time()))
            try:
                conn = listener.accept()[0]
            # A zero timeout makes the socket non-blocking, so an expired key ends the wait with BlockingIOError
            except (TimeoutError, BlockingIOError):
                return
            with conn:
                result = serve_connection(result[0], conn, time.time())
    finally:
        os.unlink(listener.getsockname())
        listener.close()


# The client side, used by session.py. None means no agent is reachable: no socket file (never started, or exited
# cleanly) or a stale one (a dead agent). pm treats that as logged out and asks for login, never as a crash.
# Any other error, such as PermissionError on a socket owned by someone else, still raises.
# The reply goes through the same size-limited read_message(), and the timeout keeps a stuck agent from freezing pm.
def send_request(path: str, request: dict) -> dict | None:
    with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as client:
        try:
            client.connect(path)
        except (FileNotFoundError, ConnectionRefusedError):
            return None
        client.settimeout(CONNECTION_TIMEOUT)
        client.sendall(encode_message(request))
        return decode_message(read_message(client))


# The listener is created here, in the parent, and handed to the child as its only inherited fd: the socket is bound
# with its 0700/0600 permissions and listening before the child exists, so pm can send UNLOCK at once, with no wait
# and no window for another process to take the path. The key never goes through argv or the environment (both are
# readable via /proc); the child starts locked and gets it over the socket. A new session keeps closing the terminal
# or Ctrl-C from killing it, cwd="/" keeps it from holding a directory busy, and DEVNULL keeps it from ever writing
# to the terminal.
# Returns the daemon's pid; SO_PEERCRED cannot tell it, because the kernel records whoever called listen(), the parent.
# An agent that already answers, locked or not, is reused (None): it is never replaced or killed here, and its key
# only changes through save_session()'s UNLOCK. STATUS is the probe because it never refreshes the session.
def start_agent(path: str) -> int | None:
    if send_request(path, {"cmd": "STATUS"}) is not None:
        return None
    # Another pm may have started an agent since the probe: create_listener() then refuses to touch its socket, and
    # if that agent answers now it is reused. Any other error, or EADDRINUSE with nobody answering, still raises.
    try:
        listener = create_listener(path)
    except OSError as error:
        if error.errno == errno.EADDRINUSE and send_request(path, {"cmd": "STATUS"}) is not None:
            return None
        raise
    with listener:
        return subprocess.Popen(
            [sys.executable, "-m", "password_manager.agent", str(listener.fileno())],
            pass_fds=(listener.fileno(),), start_new_session=True, cwd="/",
            stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
        ).pid


# The daemon's startup: hardened before the first connection, so the key it only ever gets over the socket never
# enters a process that can be dumped or read by other processes of the user. Kept apart from run_agent(), which
# tests also run in a thread of the pytest process, so that process is never hardened.
def run_daemon(listener: socket.socket) -> None:
    harden_process()
    run_agent(listener)


# Entry point of the spawned daemon: rebuild the listener from the fd start_agent() passed down.
# It only runs in the child; the start_agent() integration tests exercise it.
if __name__ == "__main__":
    run_daemon(socket.socket(fileno=int(sys.argv[1])))
