import os
import socket
import time
from dataclasses import replace
from unittest.mock import Mock, call

import pytest
from cryptography.fernet import Fernet

from password_manager.agent import (
    AgentState, decode_message, encode_message, handle_request, is_authorized_peer, read_message, remaining_ttl,
    run_daemon, serve_connection,
)
from password_manager.constants import MAX_MESSAGE_SIZE, SESSION_TTL


@pytest.mark.unit
def test_handle_request_unlock_stores_the_username_and_key_in_the_returned_state():
    key = Fernet.generate_key()
    state, response = handle_request(AgentState(), {"cmd": "UNLOCK", "username": "alice", "key": key.decode()}, now=1000.0)
    assert response == {"ok": True}
    assert state == AgentState(username="alice", key=key, last_activity=1000.0)


@pytest.mark.unit
def test_agent_state_repr_never_shows_the_key():
    key = Fernet.generate_key()
    assert key.decode() not in repr(AgentState(username="alice", key=key, last_activity=1000.0))


@pytest.mark.unit
def test_handle_request_encrypt_returns_ciphertext_the_held_key_can_decrypt():
    key = Fernet.generate_key()
    _, response = handle_request(AgentState(username="alice", key=key, last_activity=1000.0), {"cmd": "ENCRYPT", "plaintext": "test-only-pass-1"}, now=1001.0)
    assert response["ok"] is True
    assert Fernet(key).decrypt(response["token"].encode()) == b"test-only-pass-1"


@pytest.mark.unit
def test_handle_request_decrypt_returns_plaintext_for_a_valid_token():
    key = Fernet.generate_key()
    token = Fernet(key).encrypt(b"test-only-pass-1").decode()
    _, response = handle_request(AgentState(username="alice", key=key, last_activity=1000.0), {"cmd": "DECRYPT", "token": token}, now=1001.0)
    assert response == {"ok": True, "plaintext": "test-only-pass-1"}


@pytest.mark.unit
@pytest.mark.parametrize("token", [
    Fernet(Fernet.generate_key()).encrypt(b"test-only-pass-1").decode(),
    "not-a-token",
], ids=["token from another key", "garbage"])
def test_handle_request_decrypt_returns_an_error_for_an_invalid_token(token):
    state = AgentState(username="alice", key=bytearray(Fernet.generate_key()), last_activity=1000.0)
    assert handle_request(state, {"cmd": "DECRYPT", "token": token}, now=1001.0) == (state, {"ok": False, "error": "invalid token"})


@pytest.mark.unit
@pytest.mark.parametrize("request_", [
    {"cmd": "ENCRYPT", "plaintext": "test-only-pass-1"},
    {"cmd": "DECRYPT", "token": Fernet(Fernet.generate_key()).encrypt(b"test-only-pass-1").decode()},
], ids=["ENCRYPT", "DECRYPT"])
def test_handle_request_returns_locked_for_encrypt_and_decrypt_when_no_key_is_held(request_):
    assert handle_request(AgentState(), request_, now=1000.0) == (AgentState(), {"ok": False, "error": "locked"})


@pytest.mark.unit
def test_handle_request_locks_when_idle_time_exceeds_session_ttl():
    state = AgentState(username="alice", key=bytearray(Fernet.generate_key()), last_activity=1000.0)
    assert handle_request(state, {"cmd": "ENCRYPT", "plaintext": "test-only-pass-1"}, now=1000.0 + SESSION_TTL) == (
        AgentState(), {"ok": False, "error": "locked"},
    )


@pytest.mark.unit
@pytest.mark.parametrize("cmd", ["ENCRYPT", "DECRYPT"])
def test_handle_request_refreshes_last_activity_after_a_successful_operation(cmd):
    key = Fernet.generate_key()
    state = AgentState(username="alice", key=key, last_activity=1000.0)
    request_ = {"cmd": "ENCRYPT", "plaintext": "test-only-pass-1"} if cmd == "ENCRYPT" else {"cmd": "DECRYPT", "token": Fernet(key).encrypt(b"test-only-pass-1").decode()}
    new_state, response = handle_request(state, request_, now=1100.0)
    assert response["ok"] is True
    assert new_state == replace(state, last_activity=1100.0)


@pytest.mark.unit
def test_handle_request_lock_clears_the_key_and_signals_shutdown():
    state = AgentState(username="alice", key=bytearray(Fernet.generate_key()), last_activity=1000.0)
    assert handle_request(state, {"cmd": "LOCK"}, now=1001.0) == (AgentState(), {"ok": True, "shutdown": True})


@pytest.mark.unit
def test_handle_request_status_reports_the_user_and_remaining_ttl_without_the_key():
    state = AgentState(username="alice", key=bytearray(Fernet.generate_key()), last_activity=1000.0)
    assert handle_request(state, {"cmd": "STATUS"}, now=1100.0) == (
        state, {"ok": True, "username": "alice", "remaining_ttl": SESSION_TTL - 100.0},
    )


@pytest.mark.unit
def test_handle_request_status_reports_locked_when_no_key_is_held():
    assert handle_request(AgentState(), {"cmd": "STATUS"}, now=1000.0) == (AgentState(), {"ok": False, "error": "locked"})


@pytest.mark.unit
@pytest.mark.parametrize("cmd", ["FOO", "unlock", ""])
def test_handle_request_rejects_unknown_commands(cmd):
    state = AgentState(username="alice", key=bytearray(Fernet.generate_key()), last_activity=1000.0)
    assert handle_request(state, {"cmd": cmd}, now=1100.0) == (state, {"ok": False, "error": "unknown command"})


@pytest.mark.unit
def test_remaining_ttl_returns_the_seconds_until_expiry():
    state = AgentState(username="alice", key=bytearray(Fernet.generate_key()), last_activity=1000.0)
    assert remaining_ttl(state, now=1100.0) == SESSION_TTL - 100.0


@pytest.mark.unit
def test_encode_message_and_decode_message_round_trip_a_request():
    request_ = {"cmd": "UNLOCK", "username": "alice", "key": Fernet.generate_key().decode()}
    assert decode_message(encode_message(request_)) == request_


@pytest.mark.unit
def test_decode_message_rejects_messages_over_the_size_limit():
    # Valid JSON, so only the size can be the reason for the rejection
    with pytest.raises(ValueError, match="too large"):
        decode_message(encode_message({"cmd": "ENCRYPT", "plaintext": "x" * MAX_MESSAGE_SIZE}))


@pytest.mark.unit
def test_is_authorized_peer_accepts_a_peer_with_the_same_uid():
    # socketpair() gives real kernel peer credentials without touching the filesystem
    server, client = socket.socketpair()
    with server, client:
        assert is_authorized_peer(server) is True


@pytest.mark.unit
def test_is_authorized_peer_rejects_a_peer_with_a_different_uid(monkeypatch):
    # A real second user would need root, so the agent pretends to run as another uid instead
    other_uid = os.getuid() + 1
    server, client = socket.socketpair()
    with server, client:
        monkeypatch.setattr("password_manager.agent.os.getuid", lambda: other_uid)
        assert is_authorized_peer(server) is False


@pytest.mark.unit
def test_read_message_reads_one_newline_terminated_message_from_a_connection():
    message = encode_message({"cmd": "STATUS"})
    server, client = socket.socketpair()
    with server, client:
        # The client stays open, so this only returns if read_message stops at the newline; the timeout
        # makes a version that waits for EOF fail instead of hanging the suite
        server.settimeout(1)
        client.sendall(message)
        assert read_message(server) == message


@pytest.mark.unit
def test_read_message_stops_reading_after_max_message_size_plus_one_bytes():
    server, client = socket.socketpair()
    with server, client:
        # No newline and the client stays open: only the size limit can end this read
        server.settimeout(1)
        client.sendall(b"x" * (MAX_MESSAGE_SIZE + 100))
        assert len(read_message(server)) == MAX_MESSAGE_SIZE + 1


@pytest.mark.unit
def test_serve_connection_answers_a_request_with_handle_requests_response():
    request_ = {"cmd": "UNLOCK", "username": "alice", "key": Fernet.generate_key().decode()}
    server, client = socket.socketpair()
    with server, client:
        server.settimeout(1)
        client.settimeout(1)
        client.sendall(encode_message(request_))
        assert serve_connection(AgentState(), server, now=1000.0) == handle_request(AgentState(), request_, now=1000.0)
        assert decode_message(read_message(client)) == {"ok": True}


def fail_if_called(*args):
    raise AssertionError("must not be called")


@pytest.mark.unit
def test_serve_connection_closes_an_unauthorized_peers_connection_without_reading_its_request(monkeypatch):
    state = AgentState(username="alice", key=bytearray(Fernet.generate_key()), last_activity=1000.0)
    other_uid = os.getuid() + 1
    server, client = socket.socketpair()
    with server, client:
        client.settimeout(1)
        client.sendall(encode_message({"cmd": "LOCK"}))
        monkeypatch.setattr("password_manager.agent.os.getuid", lambda: other_uid)
        monkeypatch.setattr("password_manager.agent.read_message", fail_if_called)
        assert serve_connection(state, server, now=1001.0) == (state, {"ok": False, "error": "unauthorized"})
        # The peer gets no reply at all, just the closed connection
        assert client.recv(1) == b""


@pytest.mark.unit
@pytest.mark.parametrize("data", [
    b"not json\n",
    b"\xff\xfe\n",
    b'["cmd"]\n',
    b'{"username": "alice"}\n',
    b'{"cmd": "UNLOCK", "username": "alice"}\n',
    b'{"cmd": "ENCRYPT", "plaintext": 5}\n',
    b'{"cmd": "DECRYPT", "token": null}\n',
    encode_message({"cmd": "ENCRYPT", "plaintext": "x" * MAX_MESSAGE_SIZE}),
], ids=["not json", "not utf-8", "not an object", "no cmd", "unlock without key", "plaintext not a string",
        "token not a string", "too large"])
def test_serve_connection_answers_a_malformed_request_with_an_error_and_keeps_the_state(data):
    state = AgentState(username="alice", key=bytearray(Fernet.generate_key()), last_activity=1000.0)
    server, client = socket.socketpair()
    with server, client:
        server.settimeout(1)
        client.settimeout(1)
        client.sendall(data)
        assert serve_connection(state, server, now=1001.0) == (state, {"ok": False, "error": "malformed request"})
        assert decode_message(read_message(client)) == {"ok": False, "error": "malformed request"}


@pytest.mark.unit
def test_serve_connection_gives_up_on_a_peer_that_sends_nothing_within_a_short_timeout(monkeypatch):
    monkeypatch.setattr("password_manager.agent.CONNECTION_TIMEOUT", 0.1)
    state = AgentState(username="alice", key=bytearray(Fernet.generate_key()), last_activity=1000.0)
    server, client = socket.socketpair()
    with server, client:
        # Only a guard against hanging the suite; the elapsed check proves CONNECTION_TIMEOUT ended the wait
        server.settimeout(5)
        started = time.monotonic()
        assert serve_connection(state, server, now=1001.0) == (state, {"ok": False, "error": "timeout"})
        assert time.monotonic() - started < 1


@pytest.mark.unit
def test_serve_connection_keeps_the_new_state_when_the_reply_cannot_be_sent():
    state = AgentState(username="alice", key=bytearray(Fernet.generate_key()), last_activity=1000.0)
    server, client = socket.socketpair()
    with server, client:
        server.settimeout(1)
        # The client logs out and goes away before reading the reply, so sending it fails
        client.sendall(encode_message({"cmd": "LOCK"}))
        client.close()
        assert serve_connection(state, server, now=1001.0) == (AgentState(), {"ok": True, "shutdown": True})


# Both are faked: the real harden_process() would harden the pytest process, and the listener is never served.
# One parent mock records the order, which is the point: hardening must be in place before the first connection,
# so the key, which only ever arrives over the socket, never sits in a dumpable process.
@pytest.mark.unit
def test_the_agent_calls_harden_process_at_startup(monkeypatch):
    calls = Mock()
    monkeypatch.setattr("password_manager.agent.harden_process", calls.harden_process)
    monkeypatch.setattr("password_manager.agent.run_agent", calls.run_agent)
    listener = object()

    run_daemon(listener)

    assert calls.mock_calls == [call.harden_process(), call.run_agent(listener)]


# Through UNLOCK, as in the real agent: the test only passes if the key the agent holds is a buffer it can zero
@pytest.mark.unit
def test_the_agent_wipes_its_key_on_lock():
    state, _ = handle_request(AgentState(), {"cmd": "UNLOCK", "username": "alice", "key": Fernet.generate_key().decode()}, now=1000.0)
    key_buffer = state.key

    handle_request(state, {"cmd": "LOCK"}, now=1001.0)

    # The buffer the old state held is zeroed in place, not merely dropped for the garbage collector to free later
    assert key_buffer == bytearray(44)
