import pytest
from src.user import register_user, authenticate_user
from unittest.mock import patch

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

def test_authenticate_user_success(make_user):
    with patch("src.user.load_users", return_value=make_user()):
        key = authenticate_user("alice", "alice_wonderland")
        assert isinstance(key, bytes)
        assert len(key) == 44  # base64 encoded Fernet key

def test_authenticate_user_incorrect_password(valid_user):
    with patch("src.user.load_users", return_value=valid_user):
        with pytest.raises(ValueError, match="Incorrect password"):
            authenticate_user("alice", "wrongpassword")

def test_authenticate_user_not_found():
    with patch("src.user.load_users", return_value={}):
        with pytest.raises(ValueError, match="User does not exist"):
            authenticate_user("nosuchuser", "anypassword")

def test_authenticate_user_corrupted_users_file():
    with patch("src.user.load_users", return_value=None):
        with pytest.raises(ValueError, match="User database is corrupted."):
            authenticate_user("nosuchuser", "anypassword")
