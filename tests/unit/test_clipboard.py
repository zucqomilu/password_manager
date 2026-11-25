import hashlib
from unittest.mock import patch

import pytest

from password_manager.clipboard import clear_if_unchanged

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
