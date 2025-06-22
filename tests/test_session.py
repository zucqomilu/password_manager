import json
import base64
from unittest.mock import mock_open, patch
from cryptography.fernet import Fernet
from src.session import save_session, load_session, clear_session, SESSION_FILE

def test_save_session_writes_correct_json():
    username = "testuser"
    key = Fernet.generate_key()
    encoded_key = base64.urlsafe_b64encode(key).decode()

    with patch("builtins.open", mock_open()), patch("json.dump") as dump:
        save_session(username, key)
        dump.assert_called_once()
        written_data = dump.call_args[0][0]
        assert written_data["username"] == username
        assert written_data["fernet_key"] == encoded_key

def test_load_session_reads_and_returns_fernet():
    key = Fernet.generate_key()
    encoded_key = base64.urlsafe_b64encode(key).decode()
    mock_data = {
        "username": "testuser",
        "fernet_key": encoded_key
    }

    with patch("os.path.exists", return_value=True), \
         patch("builtins.open", mock_open(read_data=json.dumps(mock_data))):
        result = load_session()
        assert result is not None
        username, fernet = result
        assert username == "testuser"
        assert isinstance(fernet, Fernet)

def test_load_session_returns_none_if_file_missing():
    with patch("os.path.exists", return_value=False):
        assert load_session() is None

def test_load_session_failure_json_error():
    mock_file = mock_open(read_data='{"username": "testuser", "fernet_key": "invalid=="')
    with patch("os.path.exists", return_value=True), \
         patch("builtins.open", mock_file), \
         patch("json.load", side_effect=ValueError("Invalid JSON")):
        
        result = load_session()
        assert result is None
        
def test_clear_session_removes_file():
    with patch("os.path.exists", return_value=True), \
         patch("os.remove") as mock_remove:
        clear_session()
        mock_remove.assert_called_once_with(SESSION_FILE)

def test_clear_session_does_nothing_if_no_file():
    with patch("os.path.exists", return_value=False), \
         patch("os.remove") as mock_remove:
        clear_session()
        mock_remove.assert_not_called()
