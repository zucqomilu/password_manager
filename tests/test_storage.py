import json, base64, logging
from unittest.mock import patch, mock_open
from src.storage import load_vault, save_vault, load_users, save_users, backup_vault

# === Helpers ===
def valid_b64_string(length):
    return base64.urlsafe_b64encode(b"x" * length).decode()

# === load_users ===
def test_load_users_valid(valid_user_json):
    with patch("os.path.exists", return_value=True), \
         patch("builtins.open", mock_open(read_data=valid_user_json)):
        users = load_users()
        assert users
        assert isinstance(users, dict)
        assert "alice" in users
        assert "auth_salt" in users["alice"]
        assert "enc_salt" in users["alice"]
        assert "password" in users["alice"]

def test_load_users_multiple_users(valid_users):
    with patch("os.path.exists", return_value=True), \
         patch("builtins.open", mock_open(read_data=json.dumps(valid_users))):
        users = load_users()
        assert users
        assert isinstance(users, dict)
        assert "alice" in users and "bob" in users

def test_load_users_file_missing(caplog):
    with patch("os.path.exists", return_value=False), \
         caplog.at_level(logging.WARNING):
        users = load_users()
        assert isinstance(users, dict)
        assert users == {}
        assert "Users file does not exist" in caplog.text

def test_load_users_empty_object():
    with patch("os.path.exists", return_value=True), \
         patch("builtins.open", mock_open(read_data="{}")):
        users = load_users()
        assert isinstance(users, dict)
        assert users == {}

def test_load_users_empty_file(caplog):
    with patch("os.path.exists", return_value=True), \
         patch("builtins.open", mock_open(read_data="")), \
         caplog.at_level(logging.ERROR):
        users = load_users()
        assert users == None
        assert "Failed to decode users file" in caplog.text

def test_load_users_corrupted_json(caplog, corrupted_json):
    with patch("os.path.exists", return_value=True), \
         patch("builtins.open", mock_open(read_data=corrupted_json)), \
         caplog.at_level(logging.ERROR):
        result = load_users()
        assert result == None
        assert "Failed to decode users file" in caplog.text

def test_load_users_returns_none_on_invalid_format(caplog, not_dict):
    with patch("os.path.exists", return_value=True), \
         patch("builtins.open", mock_open(read_data=json.dumps(not_dict))), \
         caplog.at_level(logging.ERROR):
        assert load_users() is None
        assert "Loading failed: user validation failed." in caplog.text

@patch("src.storage.validate_users", return_value=False)
def test_load_users_calls_validate(mock_validate, caplog):
    with patch("os.path.exists", return_value=True), \
         patch("builtins.open", mock_open(read_data="{}")), \
         caplog.at_level(logging.ERROR):
        result = load_users()
        mock_validate.assert_called_once()
        assert result is None
        assert "Loading failed: user validation failed." in caplog.text

def test_load_users_unexpected_error(caplog):
    with patch("os.path.exists", return_value=True), \
         patch("builtins.open", side_effect=PermissionError("Permission denied")), \
         caplog.at_level(logging.ERROR):
        result = load_users()
        assert result is None
        assert "Unexpected error reading users file" in caplog.text

# === save_users ===
def test_save_users_writes_json(caplog, valid_user):
    m = mock_open()
    with patch("builtins.open", m), \
         patch("src.constants.get_users", return_value="fake_users.json"), \
         caplog.at_level(logging.DEBUG):
        save_users(valid_user)
        handle = m()
        written = ''.join(call.args[0] for call in handle.write.call_args_list)
        assert json.loads(written) == valid_user
        assert "Saving users to" in caplog.text

def test_save_users_empty_dict():
    m = mock_open()
    with patch("builtins.open", m), \
         patch("src.constants.get_users", return_value="fake_users.json"):
        save_users({})
        handle = m()
        written = ''.join(call.args[0] for call in handle.write.call_args_list)
        assert json.loads(written) == {}

def test_save_users_uses_correct_path(valid_user):
    m = mock_open()
    with patch("builtins.open", m) as mock_open_fn, \
         patch("src.constants.get_users", return_value="my_users.json"):
        save_users(valid_user)
        mock_open_fn.assert_called_once_with("my_users.json", "w")

def test_save_users_invalid_schema_does_not_write(caplog, valid_user):
    m = mock_open()
    valid_user["alice"]["password"] = "invalid"
    with patch("builtins.open", m), \
         patch("src.constants.get_users", return_value="fake_users.json"), \
         caplog.at_level(logging.ERROR):
        save_users(valid_user)
        m.assert_not_called()
        assert "Aborting save: user validation failed." in caplog.text

# === load_vault ===
def test_load_vault_valid(valid_vault_json, mock_json_file):
    with patch("os.path.exists", return_value=True), \
         mock_json_file(valid_vault_json):
        result = load_vault()
        assert isinstance(result, dict)
        assert "alice" in result

def test_load_vault_valid_multiple_entries(valid_vault_json, mock_json_file):
    with patch("os.path.exists", return_value=True), \
         mock_json_file(valid_vault_json):
        result = load_vault()
        assert isinstance(result, dict)
        assert "alice" in result
        assert "github" in result["alice"]

def test_load_vault_file_missing(caplog):
    with patch("os.path.exists", return_value=False), \
         caplog.at_level(logging.WARNING):
        assert load_vault() == {}
        assert "Vault file does not exist" in caplog.text
        
def test_load_vault_empty_object():
    with patch("os.path.exists", return_value=True), \
         patch("builtins.open", mock_open(read_data="{}")):
        assert load_vault() == {}

def test_load_vault_empty_file(caplog):
    with patch("os.path.exists", return_value=True), \
         patch("builtins.open", mock_open(read_data="")), \
         caplog.at_level(logging.ERROR):
        assert load_vault() == None
        assert "Failed to decode vault file" in caplog.text

def test_load_vault_returns_none_on_corrupted_json(caplog, corrupted_json):
    with patch("os.path.exists", return_value=True), \
         patch("builtins.open", mock_open(read_data=corrupted_json)), \
         caplog.at_level(logging.ERROR):
        assert load_vault() == None
        assert "Failed to decode vault file" in caplog.text

def test_load_vault_returns_none_on_invalid_format(caplog, invalid_json):
    with patch("os.path.exists", return_value=True), \
         patch("builtins.open", mock_open(read_data=invalid_json)), \
         caplog.at_level(logging.ERROR):
        assert load_vault() is None
        assert "Failed to decode vault file" in caplog.text

@patch("src.storage.validate_vault", return_value=False)
def test_load_vault_calls_validate(mock_validate, caplog):
    with patch("os.path.exists", return_value=True), \
         patch("builtins.open", mock_open(read_data="{}")), \
         caplog.at_level(logging.ERROR):
        result = load_vault()
        mock_validate.assert_called_once()
        assert result is None
        assert "Loading failed: vault validation failed." in caplog.text

def test_load_vault_unexpected_error(caplog):
    with patch("os.path.exists", return_value=True), \
         patch("builtins.open", side_effect=PermissionError("Permission denied")), \
         caplog.at_level(logging.ERROR):
        result = load_vault()
        assert result is None
        assert "Unexpected error reading vault file" in caplog.text

# === save_vault ===
def test_save_vault_valid_data_saved(caplog, valid_vault):
    m = mock_open()
    with patch("builtins.open", m), \
         caplog.at_level(logging.DEBUG):
        save_vault(valid_vault)
        handle = m()
        result = ''.join(call.args[0] for call in handle.write.call_args_list)
        assert json.loads(result) == valid_vault
        assert "Saving vault to" in caplog.text

def test_save_vault_invalid_data_not_saved(caplog, valid_vault):
    valid_vault["alice"]["email"] = "invalid"
    m = mock_open()
    with patch("builtins.open", m), \
         patch("src.constants.get_vault", return_value="vault.json"), \
         caplog.at_level(logging.ERROR):
        save_vault(valid_vault)
        m.assert_not_called()
        assert "Aborting save: vault validation failed" in caplog.text

def test_backup_vault_creates_backup():
    with patch("src.constants.get_vault", return_value="/fake/dir/vault.json"), \
         patch("os.path.exists", return_value=True), \
         patch("shutil.copy2") as mock_copy, \
         patch("src.storage.logger") as mock_logger:
        backup_vault()
        assert mock_copy.called
        assert mock_logger.info.called

def test_backup_vault_file_missing(caplog):
    with patch("os.path.exists", return_value=False), \
         caplog.at_level(logging.ERROR):
        data = backup_vault()
        assert data == None
        assert "Aborting backup: vault not found." in caplog.text
