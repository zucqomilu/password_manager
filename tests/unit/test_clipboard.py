import hashlib
import io
import logging
from unittest.mock import patch

import pyperclip
import pytest

from password_manager.clipboard import clear_if_unchanged, run_clearer

# A made-up value, never a real password
COPIED = "not-a-real-password-1"


# The clearer knows only a SHA-256 digest of the copied password: it reads the clipboard, and empties it only when the
# clipboard still hashes to that digest
@pytest.mark.unit
def test_clear_if_unchanged_clears_clipboard_still_holding_copied_password():
    with patch("password_manager.clipboard.pyperclip.paste", return_value=COPIED), \
         patch("password_manager.clipboard.pyperclip.copy") as mock_copy:
        clear_if_unchanged(hashlib.sha256(COPIED.encode()).hexdigest())
    mock_copy.assert_called_once_with("")


# Something copied after pm get (a URL, a different password) belongs to the user: the clearer never empties it
@pytest.mark.unit
def test_clear_if_unchanged_leaves_clipboard_alone_when_it_changed():
    with patch("password_manager.clipboard.pyperclip.paste", return_value="copied-later-by-the-user"), \
         patch("password_manager.clipboard.pyperclip.copy") as mock_copy:
        clear_if_unchanged(hashlib.sha256(COPIED.encode()).hexdigest())
    mock_copy.assert_not_called()


# The clearer runs detached with no terminal: a clipboard it cannot read (no xclip/wl-paste, the graphical session ended)
# is left alone and noted in vault.log, never a traceback. The log line names no password, digest or clipboard content.
@pytest.mark.unit
def test_clear_if_unchanged_leaves_clipboard_alone_and_logs_warning_when_it_cannot_be_read(caplog):
    with patch("password_manager.clipboard.pyperclip.paste", side_effect=pyperclip.PyperclipException("no clipboard")), \
         patch("password_manager.clipboard.pyperclip.copy") as mock_copy, \
         caplog.at_level(logging.WARNING):
        clear_if_unchanged(hashlib.sha256(COPIED.encode()).hexdigest())
    mock_copy.assert_not_called()
    assert "Could not read the clipboard to clear the copied password." in caplog.text


# A clipboard that still holds the password but cannot be written is the one case where the password stays copied:
# the clearer says so in vault.log instead of dying silently. The log line names no password, digest or clipboard content.
@pytest.mark.unit
def test_clear_if_unchanged_logs_warning_when_clipboard_cannot_be_cleared(caplog):
    with patch("password_manager.clipboard.pyperclip.paste", return_value=COPIED), \
         patch("password_manager.clipboard.pyperclip.copy", side_effect=pyperclip.PyperclipException("no clipboard")), \
         caplog.at_level(logging.WARNING):
        clear_if_unchanged(hashlib.sha256(COPIED.encode()).hexdigest())
    assert "Could not clear the copied password from the clipboard." in caplog.text


# The clearer's own main: it makes itself non-dumpable before it reads anything (the clipboard it is about to read may
# hold the password), takes the digest from stdin, sleeps the timeout and only then checks and clears the clipboard.
# harden_process is faked: the real one would harden the pytest process itself.
@pytest.mark.unit
def test_run_clearer_hardens_reads_digest_from_stdin_waits_timeout_then_clears():
    digest = hashlib.sha256(COPIED.encode()).hexdigest()
    calls = []
    with patch("password_manager.clipboard.harden_process", side_effect=lambda: calls.append("harden")), \
         patch("password_manager.clipboard.sleep", side_effect=lambda seconds: calls.append(("sleep", seconds))), \
         patch("password_manager.clipboard.clear_if_unchanged", side_effect=lambda d: calls.append(("clear", d))):
        run_clearer(30, io.StringIO(digest + "\n"))
    assert calls == ["harden", ("sleep", 30), ("clear", digest)]
