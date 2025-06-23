import json
from unittest.mock import patch, mock_open
from src.storage import load_vault, save_vault, load_users, save_users, backup_vault

def test_load_vault_valid_json():
    mock_json = '{"site": {"label": "secret"}}'
    with patch("os.path.exists", return_value=True), \
         patch("builtins.open", mock_open(read_data=mock_json)):
        data = load_vault()
        assert data["site"]["label"] == "secret"

def test_load_vault_invalid_json():
    bad_json = "{this is not valid json"
    with patch("os.path.exists", return_value=True), \
         patch("builtins.open", mock_open(read_data=bad_json)), \
         patch("json.load", side_effect=json.JSONDecodeError("Expecting value", "doc", 0)):
        result = load_vault()
        assert result == {}

def test_load_vault_file_missing():
    with patch("os.path.exists", return_value=False):
        data = load_vault()
        assert data == {}

def test_save_vault_writes_data():
    data = {"github": {"pw": "123"}}
    m = mock_open()
    with patch("builtins.open", m):
        save_vault(data)
        handle = m()
        written = ''.join(call.args[0] for call in handle.write.call_args_list)
        assert json.loads(written) == data        

def test_load_users_returns_data():
    users_json = '{"alice": {"password": "pw"}}'
    with patch("os.path.exists", return_value=True), \
         patch("builtins.open", mock_open(read_data=users_json)):
        users = load_users()
        assert users["alice"]["password"] == "pw"

def test_load_users_invalid_json():
    bad_json = "{this is not valid json"
    with patch("os.path.exists", return_value=True), \
         patch("builtins.open", mock_open(read_data=bad_json)), \
         patch("json.load", side_effect=json.JSONDecodeError("Expecting value", "doc", 0)):
        result = load_users()
        assert result == {}

def test_load_users_file_missing():
    with patch("os.path.exists", return_value=False):
        data = load_users()
        assert data == {}        

def test_save_users_writes_json():
    users = {"bob": {"password": "hunter2"}}
    m = mock_open()
    with patch("builtins.open", m):
        save_users(users)
        handle = m()
        written = ''.join(call.args[0] for call in handle.write.call_args_list)
        assert json.loads(written) == users

def test_backup_vault_creates_backup():
    with patch("src.constants.get_db_file", return_value="/fake/dir/vault.json"), \
         patch("os.path.exists", return_value=True), \
         patch("shutil.copy2") as mock_copy, \
         patch("src.storage.logger") as mock_logger:
        backup_vault()
        assert mock_copy.called
        assert mock_logger.info.called

def test_backup_vault_file_missing():
    with patch("os.path.exists", return_value=False):
        data = backup_vault()
        assert data == None
