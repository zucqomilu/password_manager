import logging
import pytest
from password_manager.user import register_user, authenticate_user
from unittest.mock import patch
from cryptography.fernet import Fernet
from password_manager.crypto import unwrap_data_key
from password_manager.validate_storage import validate_users

@pytest.mark.unit
def test_register_user_success():
    with patch("password_manager.user.load_users", return_value={}), \
         patch("password_manager.user.save_users") as mock_save:
        result = register_user("newuser", "newpassword")
        assert result is True
        mock_save.assert_called_once()

@pytest.mark.unit
def test_register_user_creates_a_v2_record_with_argon2id_params_and_a_wrapped_random_data_key():
    with patch("password_manager.user.load_users", return_value={}), \
         patch("password_manager.user.save_users") as mock_save:
        assert register_user("alice", "same_password") and register_user("bob", "same_password")
    alice, bob = mock_save.call_args_list[0].args[0]["alice"], mock_save.call_args_list[1].args[0]["bob"]
    assert validate_users({"alice": alice, "bob": bob}) is True
    assert (alice["version"], {k: v for k, v in alice["kdf"].items() if k != "salt"}) == (
        2, {"time_cost": 3, "memory_cost": 65536, "parallelism": 4},
    )
    data_keys = [unwrap_data_key(record["wrapped_key"], "same_password", record["kdf"]) for record in (alice, bob)]
    assert all(Fernet(key) for key in data_keys)
    assert data_keys[0] != data_keys[1]  # random, not derived from the password

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
def test_authenticate_user_rejects_a_wrong_password_for_a_v2_user(caplog, make_v2_user):
    with patch("password_manager.user.load_users", return_value=make_v2_user()), \
         caplog.at_level(logging.ERROR), \
         pytest.raises(ValueError, match="Incorrect password."):
        authenticate_user("alice", "wrongpassword")
    assert "Incorrect password." in caplog.text

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
