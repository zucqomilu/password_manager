import pytest
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

def test_get_password_invalid_decryption(fake_fernet, capsys):
    with patch("src.core.load_vault", return_value=
               {"user1": {"gmail": "invaliddata"}}):
        get_password("user1", "gmail", fake_fernet)
        captured = capsys.readouterr()
        assert "Incorrect master password" in captured.out

def test_get_password_success(fake_fernet, capsys):
    with patch("src.core.load_vault", return_value=
               {"user1": {"gmail": "encrypted:secret123"}}), \
         patch("src.core.pyperclip.copy") as mock_clipboard:
        get_password("user1", "gmail", fake_fernet, show=True)
        captured = capsys.readouterr()
        assert "secret123" in captured.out
        mock_clipboard.assert_called_once()

def test_list_labels_filters_decryptable(fake_fernet, capsys):
    with patch("src.core.load_vault", return_value=
               {"user1": {"gmail": "encrypted:secret1","github": "invaliddata"}}):
        list_labels("user1", fake_fernet)
        captured = capsys.readouterr()
        assert "- gmail" in captured.out
        assert "- github" not in captured.out
