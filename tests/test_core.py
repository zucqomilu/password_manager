import pytest, logging
from unittest.mock import patch
from src.core import generate_password, save_password, get_password, list_labels

@pytest.fixture
def fake_fernet():
    class DummyFernet:
        def encrypt(self, val):
            return b"encrypted:" + val

        def decrypt(self, val):
            if val.startswith(b"encrypted:"):
                return val[len(b"encrypted:"):]
            raise Exception("Decryption failed")

    return DummyFernet()

def test_generate_password_length():
    password = generate_password(20)
    assert isinstance(password, str)
    assert len(password) == 20

def test_save_password_new_label(fake_fernet):
    with patch("src.core.load_vault", return_value={}), \
         patch("src.core.save_vault") as mock_save, \
         patch("src.core.backup_vault"), \
         patch("src.core.input", return_value='y'):
        result = save_password("user1", "gmail", "pass123", fake_fernet)
        assert result is True
        mock_save.assert_called_once()

def test_save_password_logs_and_prints_on_vault_load_failure(capsys, caplog, fake_fernet):
    with patch("src.core.load_vault", return_value=None), \
         caplog.at_level(logging.ERROR):
        save_password("alice", "gmail", "securepw123", fake_fernet)
        out = capsys.readouterr().out
        assert "Failed to load password vault" in out
        assert "Vault loading failed: returned None." in caplog.text

def test_save_password_creates_correct_version_label(fake_fernet):
    with patch("src.core.load_vault", return_value=
               {"testuser": {"email": "encrypted:oldpass",
                             "email__v1": "encrypted:backup1",
                             "email__v2": "encrypted:backup2"}}), \
         patch("src.core.save_vault") as mock_save, \
         patch("src.core.backup_vault") as mock_backup, \
         patch("builtins.input", return_value="y"), \
         patch("builtins.print"):
        result = save_password("testuser", "email", "newpassword123", fake_fernet)
        assert result is True
        saved_data = mock_save.call_args[0][0]  # The vault dict passed to save_vault
        assert "email__v3" in saved_data["testuser"]  # Next available version
        mock_backup.assert_called_once()

def test_save_password_overwrite(fake_fernet):
    with patch("src.core.load_vault", return_value=
               {"user1": {"gmail": "encrypted:oldpass"}}), \
         patch("src.core.save_vault") as mock_save, \
         patch("src.core.backup_vault") as mock_backup, \
         patch("src.core.input", return_value='y'):
        result = save_password("user1", "gmail", "newpass", fake_fernet)
        assert result is True
        mock_backup.assert_called_once()
        mock_save.assert_called_once()

def test_save_password_user_declines_overwrite(fake_fernet):
    with patch("src.core.load_vault", return_value=
               {"user1": {"gmail": "encrypted:oldpass"}}), \
         patch("src.core.save_vault") as mock_save, \
         patch("src.core.input", return_value='n'), \
         patch("builtins.print") as mock_print:
        result = save_password("user1", "gmail", "newpass", fake_fernet)
        assert result is False
        mock_save.assert_not_called()
        mock_print.assert_any_call("Operation cancelled.")

def test_save_password_overwrite_fails_on_bad_decryption(fake_fernet):
    with patch("src.core.load_vault", return_value=
               {"testuser": {"email": "invalid_encrypted_data:newpassword"}}), \
         patch("src.core.save_vault") as mock_save, \
         patch("src.core.backup_vault") as mock_backup, \
         patch("builtins.input", return_value="y"), \
         patch("builtins.print") as mock_print:
        result = save_password("testuser", "email", "newpassword", fake_fernet)
        assert result is False
        mock_save.assert_not_called()
        mock_backup.assert_not_called()
        mock_print.assert_any_call("Error: A password already exists for 'email', and the provided master password does not match.")

def test_get_password_success(fake_fernet, capsys):
    with patch("src.core.load_vault", return_value=
               {"user1": {"gmail": "encrypted:secret123"}}), \
         patch("src.core.pyperclip.copy") as mock_clipboard:
        get_password("user1", "gmail", fake_fernet, show=True)
        captured = capsys.readouterr()
        assert "secret123" in captured.out
        mock_clipboard.assert_called_once()

def test_get_password_logs_and_prints_on_vault_load_failure(capsys, caplog, fake_fernet):
    with patch("src.core.load_vault", return_value=None), \
         caplog.at_level(logging.ERROR):
        get_password("alice", "gmail", fake_fernet)
        out = capsys.readouterr().out
        assert "Failed to load password vault" in out
        assert "Vault loading failed: returned None." in caplog.text

def test_get_password_invalid_decryption(fake_fernet, capsys):
    with patch("src.core.load_vault", return_value=
               {"user1": {"gmail": "invaliddata"}}):
        get_password("user1", "gmail", fake_fernet)
        captured = capsys.readouterr()
        assert "Incorrect master password" in captured.out

def test_get_password_label_not_found(fake_fernet):
    with patch("src.core.load_vault", return_value=
               {"testuser": {"otherlabel": fake_fernet.encrypt(b"secret").decode()}}), \
         patch("builtins.print") as mock_print:
        get_password("testuser", "nonexistent", fake_fernet)
        mock_print.assert_any_call("No password found for 'nonexistent'.")

def test_list_labels_filters_decryptable(fake_fernet, capsys):
    with patch("src.core.load_vault", return_value=
               {"user1": {"gmail": "encrypted:secret1","github": "invaliddata"}}):
        list_labels("user1", fake_fernet)
        captured = capsys.readouterr()
        assert "- gmail" in captured.out
        assert "- github" not in captured.out

def test_list_labels_empty_user_vault(fake_fernet):
    with patch("src.core.load_vault", return_value={"testuser": {}}), \
         patch("builtins.print") as mock_print:
        list_labels("testuser", fake_fernet)
        mock_print.assert_any_call("No passwords found for this user.")

def test_list_labels_logs_and_prints_on_vault_load_failure(capsys, caplog, fake_fernet):
    with patch("src.core.load_vault", return_value=None), \
         caplog.at_level(logging.ERROR):
        list_labels("alice", fake_fernet)
        out = capsys.readouterr().out
        assert "Failed to load password vault" in out
        assert "Vault loading failed: returned None." in caplog.text
