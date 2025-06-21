import json
from unittest.mock import patch, mock_open
from src.storage import load_vault, save_vault, load_users, save_users, backup_vault

def test_load_vault_valid_json():
    mock_json = '{"site": {"label": "secret"}}'
    with patch("builtins.open", mock_open(read_data=mock_json)):
        with patch("os.path.exists", return_value=True):
            data = load_vault()
            assert data["site"]["label"] == "secret"

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
    with patch("builtins.open", mock_open(read_data=users_json)):
        with patch("os.path.exists", return_value=True):
            users = load_users()
            assert users["alice"]["password"] == "pw"
        
def test_save_users_writes_json():
    users = {"bob": {"password": "hunter2"}}
    m = mock_open()
    with patch("builtins.open", m):
        save_users(users)
        handle = m()
        written = ''.join(call.args[0] for call in handle.write.call_args_list)
        assert json.loads(written) == users

def test_backup_vault_creates_backup(tmp_path):
    test_file = tmp_path / "vault.json"
    test_file.write_text('{"sample": "data"}')

    with patch("src.storage.DB_FILE", str(test_file)):
        with patch("shutil.copy2") as mock_copy, patch("src.storage.logger") as mock_logger:
            backup_vault()
            assert mock_copy.called
            assert mock_logger.info.called
