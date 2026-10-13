import pytest
from password_manager.user import register_user, authenticate_user
from unittest.mock import patch
from cryptography.fernet import Fernet

@pytest.mark.unit
def test_register_user_success():
    with patch("password_manager.user.load_users", return_value={}), \
         patch("password_manager.user.save_users") as mock_save:
        result = register_user("newuser", "newpassword")
        assert result is True
        mock_save.assert_called_once()

@pytest.mark.unit
def test_register_user_user_exists():
    with patch("password_manager.user.load_users", return_value={"existinguser": {}}), \
         patch("password_manager.user.save_users"):
        result = register_user("existinguser", "irrelevant")
        assert result is False

@pytest.mark.unit
def test_authenticate_user_success(make_user):
    with patch("password_manager.user.load_users", return_value=make_user()):
        key = authenticate_user("alice", "alice_wonderland")
        assert isinstance(key, bytes)
        assert len(key) == 44  # base64 encoded Fernet key

@pytest.mark.unit
def test_authenticate_user_returns_the_data_key_for_a_v2_user(make_v2_user):
    data_key = Fernet.generate_key()
    with patch("password_manager.user.load_users", return_value=make_v2_user(data_key=data_key)):
        assert authenticate_user("alice", "alice_wonderland") == data_key

@pytest.mark.unit
def test_authenticate_user_incorrect_password(valid_user):
    with patch("password_manager.user.load_users", return_value=valid_user):
        with pytest.raises(ValueError, match="Incorrect password"):
            authenticate_user("alice", "wrongpassword")

@pytest.mark.unit
def test_authenticate_user_not_found():
    with patch("password_manager.user.load_users", return_value={}):
        with pytest.raises(ValueError, match="User does not exist"):
            authenticate_user("nosuchuser", "anypassword")

@pytest.mark.unit
def test_authenticate_user_corrupted_users_file():
    with patch("password_manager.user.load_users", return_value=None):
        with pytest.raises(ValueError, match="User database is corrupted."):
            authenticate_user("nosuchuser", "anypassword")
