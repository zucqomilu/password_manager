import pytest
import base64
from src.user import register_user, authenticate_user
from src.crypto import derive_key
from unittest.mock import patch

@pytest.fixture
def fake_user_data():
    password = "securepassword"
    auth_salt = b"1234567890123456"
    enc_salt = b"abcdef1234567890"
    auth_key = derive_key(password, auth_salt).decode()

    return {
        "testuser": {
            "auth_salt": base64.b64encode(auth_salt).decode(),
            "enc_salt": base64.b64encode(enc_salt).decode(),
            "password": auth_key
        }
    }

def test_register_user_success():
    with patch("src.user.load_users", return_value={}), \
         patch("src.user.save_users") as mock_save:

        result = register_user("newuser", "newpassword")
        assert result is True
        mock_save.assert_called_once()

def test_register_user_user_exists():
    with patch("src.user.load_users", return_value={"existinguser": {}}), \
         patch("src.user.save_users"):

        result = register_user("existinguser", "irrelevant")
        assert result is False

def test_authenticate_user_success(fake_user_data):
    with patch("src.user.load_users", return_value=fake_user_data):
        key = authenticate_user("testuser", "securepassword")
        assert isinstance(key, bytes)
        assert len(key) == 44  # base64 encoded Fernet key

def test_authenticate_user_incorrect_password(fake_user_data):
    with patch("src.user.load_users", return_value=fake_user_data):
        with pytest.raises(ValueError, match="Incorrect password"):
            authenticate_user("testuser", "wrongpassword")

def test_authenticate_user_not_found():
    with patch("src.user.load_users", return_value={}):
        with pytest.raises(ValueError, match="User does not exist"):
            authenticate_user("nosuchuser", "anypassword")
