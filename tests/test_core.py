import logging
from unittest.mock import patch
from src.core import generate_password, save_password, get_password, list_labels

def test_generate_password():
    password = generate_password()
    assert isinstance(password, str)
    assert len(password) == 16

def test_generate_password_length():
    password = generate_password(20)
    assert isinstance(password, str)
    assert len(password) == 20

def test_save_password_without_login(fernet):
    with patch("src.core.load_vault", return_value={"alice": {}}), \
         patch("src.core.save_vault") as mock_save:
        result = save_password("alice", "github", fernet, "supersecret")
        assert result is True
        saved = mock_save.call_args[0][0]
        assert "password" in saved["alice"]["github"]

def test_save_password_with_login(fernet):
    with patch("src.core.load_vault", return_value={"alice": {}}), \
         patch("src.core.save_vault") as mock_save:
        result = save_password("alice", "github", fernet, "supersecret", login="user@example.com")
        assert result is True
        saved = mock_save.call_args[0][0]
        entry = saved["alice"]["github"]
        assert "password" in entry and "login" in entry

def test_save_password_overwrite_prompt_no(caplog, fernet, valid_vault):
    with patch("src.core.load_vault", return_value=valid_vault), \
         patch("src.core.input", return_value='n'), \
         caplog.at_level(logging.INFO):
        result = save_password("alice", "github", fernet, "newpass")
        assert result is False
        assert "User cancelled overwrite for 'github'." in caplog.text

def test_save_password_backup_decryption_fail(caplog, fernet, valid_vault):
    valid_vault["alice"]["github"]["password"] = "notbase64==="
    with patch("src.core.load_vault", return_value=valid_vault), \
         patch("src.core.input", return_value='y'), \
         caplog.at_level(logging.ERROR):
        result = save_password("alice", "github", fernet, "newpw")
        assert result is False
        assert "Failed to overwrite 'github' due to incorrect master password." in caplog.text

def test_save_password_new_label(fernet):
    with patch("src.core.load_vault", return_value={}), \
         patch("src.core.save_vault") as mock_save, \
         patch("src.core.backup_vault"), \
         patch("src.core.input", return_value='y'):
        result = save_password("user1", "gmail", fernet, "pass123")
        assert result is True
        mock_save.assert_called_once()

def test_save_password_logs_and_prints_on_vault_load_failure(capsys, caplog, fernet):
    with patch("src.core.load_vault", return_value=None), \
         caplog.at_level(logging.ERROR):
        save_password("alice", "gmail", fernet, "securepw123")
        out = capsys.readouterr().out
        assert "Failed to load password vault" in out
        assert "Vault loading failed: returned None." in caplog.text

def test_save_password_creates_correct_version_label(fernet, valid_vault):
    with patch("src.core.load_vault", return_value=valid_vault), \
         patch("src.core.save_vault") as mock_save, \
         patch("src.core.backup_vault") as mock_backup, \
         patch("builtins.input", return_value="y"), \
         patch("builtins.print"):
        result = save_password("alice", "twitter", fernet, "newtwitterpass12")
        assert result is True
        saved_data = mock_save.call_args[0][0]  # The vault dict passed to save_vault
        assert "twitter__v2" in saved_data["alice"]  # Next available version
        mock_backup.assert_called_once()

def test_save_password_overwrite(fernet, valid_vault):
    with patch("src.core.load_vault", return_value=valid_vault), \
         patch("src.core.save_vault") as mock_save, \
         patch("src.core.backup_vault") as mock_backup, \
         patch("src.core.input", return_value='y'):
        result = save_password("alice", "github", fernet, "newpass")
        assert result is True
        mock_backup.assert_called_once()
        mock_save.assert_called_once()

def test_save_password_user_declines_overwrite(fernet, valid_vault):
    with patch("src.core.load_vault", return_value=valid_vault), \
         patch("src.core.save_vault") as mock_save, \
         patch("src.core.input", return_value='n'), \
         patch("builtins.print") as mock_print:
        result = save_password("alice", "github", fernet, "newpass")
        assert result is False
        mock_save.assert_not_called()
        mock_print.assert_any_call("Operation cancelled.")

def test_save_password_overwrite_fails_on_bad_decryption(fernet, valid_vault):
    valid_vault["alice"]["github"]["password"] = "invalid_encrypted_data:newpassword"
    with patch("src.core.load_vault", return_value=valid_vault), \
         patch("src.core.save_vault") as mock_save, \
         patch("src.core.backup_vault") as mock_backup, \
         patch("builtins.input", return_value="y"), \
         patch("builtins.print") as mock_print:
        assert not save_password("alice", "github", fernet, "newpassword")
        mock_save.assert_not_called()
        mock_backup.assert_not_called()
        mock_print.assert_any_call("Error: A password already exists for 'github', and the provided master password does not match.")

def test_set_login_only(fernet):
    with patch("src.core.load_vault", return_value={"bob": {}}), \
         patch("src.core.save_vault") as mock_save, \
         patch("builtins.print") as mock_print:
        assert not save_password("bob", "gitlab", login="bob@example.com", fernet=fernet)
        mock_save.assert_not_called()
        mock_print.assert_any_call("Error: Cannot create label 'gitlab' without a password.")

def test_set_password_only(fernet):
    with patch("src.core.load_vault", return_value={"bob": {}}), \
         patch("src.core.save_vault") as mock_save:
        assert save_password("bob", "gitlab", password="mysecretpassword", fernet=fernet)
        saved_data = mock_save.call_args[0][0]
        password_encrypted = saved_data["bob"]["gitlab"]["password"]
        assert isinstance(password_encrypted, str)
        assert fernet.decrypt(password_encrypted.encode()).decode() == "mysecretpassword"

def test_set_password_and_login(fernet):
    with patch("src.core.load_vault", return_value={"bob": {}}), \
         patch("src.core.save_vault") as mock_save:
        assert save_password("bob", "gitlab", password="mysecretpassword", login="bob@example.com", fernet=fernet)
        saved_data = mock_save.call_args[0][0]
        password_encrypted = saved_data["bob"]["gitlab"]["password"]
        login_encrypted = saved_data["bob"]["gitlab"]["login"]
        assert isinstance(password_encrypted, str)
        assert fernet.decrypt(password_encrypted.encode()).decode() == "mysecretpassword"
        assert isinstance(login_encrypted, str)
        assert fernet.decrypt(login_encrypted.encode()).decode() == "bob@example.com"

def test_get_password_success(fernet, capsys, valid_vault):
    with patch("src.core.load_vault", return_value=valid_vault), \
         patch("src.core.pyperclip.copy") as mock_clipboard:
        get_password("alice", "github", fernet, show=True)
        captured = capsys.readouterr()
        assert "supersecurepass1" in captured.out
        mock_clipboard.assert_called_once()

def test_get_password_logs_and_prints_on_vault_load_failure(capsys, caplog, fernet):
    with patch("src.core.load_vault", return_value=None), \
         caplog.at_level(logging.ERROR):
        get_password("alice", "gmail", fernet)
        out = capsys.readouterr().out
        assert "Failed to load password vault" in out
        assert "Vault loading failed: returned None." in caplog.text

def test_get_password_invalid_decryption(fernet, capsys, valid_vault):
    valid_vault["alice"]["github"]["password"] = "invaliddata"
    with patch("src.core.load_vault", return_value=valid_vault):
        get_password("alice", "github", fernet)
        captured = capsys.readouterr()
        assert "Incorrect master password" in captured.out

def test_get_password_label_not_found(fernet, valid_vault):
    with patch("src.core.load_vault", return_value=valid_vault), \
         patch("builtins.print") as mock_print:
        get_password("alice", "nonexistent", fernet)
        mock_print.assert_any_call("No password found for 'nonexistent'.")

def test_list_labels_filters_decryptable(fernet, capsys, valid_vault):
    valid_vault["alice"]["github"]["password"] = "invaliddata"
    with patch("src.core.load_vault", return_value=valid_vault):
        list_labels("alice", fernet)
        captured = capsys.readouterr()
        assert "- twitter" in captured.out
        assert "- github" not in captured.out

def test_list_labels_empty_user_vault(fernet):
    with patch("src.core.load_vault", return_value={"testuser": {}}), \
         patch("builtins.print") as mock_print:
        list_labels("testuser", fernet)
        mock_print.assert_any_call("No passwords found for this user.")

def test_list_labels_logs_and_prints_on_vault_load_failure(capsys, caplog, fernet):
    with patch("src.core.load_vault", return_value=None), \
         caplog.at_level(logging.ERROR):
        list_labels("alice", fernet)
        out = capsys.readouterr().out
        assert "Failed to load password vault" in out
        assert "Vault loading failed: returned None." in caplog.text
