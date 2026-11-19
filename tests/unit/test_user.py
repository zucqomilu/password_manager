import logging
import pytest
from password_manager.user import register_user, authenticate_user, upgrade_user_record
from unittest.mock import Mock, patch
from cryptography.fernet import Fernet
from password_manager.crypto import derive_key, unwrap_data_key, wrap_data_key
from password_manager.storage import Storage
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
    with patch("password_manager.user.load_users", return_value=make_user()), \
         patch("password_manager.user.backup_users"), \
         patch("password_manager.user.save_users"):
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

# A rotation interrupted after the vault was saved under the new key leaves users.json with both keys. Login keeps the
# one the vault decrypts with: it returns the pending key and makes it the only one, so the next login needs no vault.
# The vault, users.json and their saves are stand-ins, so nothing touches the disk.
@pytest.mark.unit
def test_authenticate_user_finishes_an_interrupted_rotation_when_the_vault_decrypts_with_the_pending_key(make_v2_user):
    old_key, new_key = Fernet.generate_key(), Fernet.generate_key()
    record = make_v2_user(data_key=old_key)["alice"]
    pending = wrap_data_key(new_key, "alice_wonderland", record["kdf"])
    vault = {"alice": {"github": {"password": Fernet(new_key).encrypt(b"pw-1").decode()}}}
    with patch("password_manager.user.load_users", return_value={"alice": {**record, "pending_wrapped_key": pending}}), \
         patch("password_manager.user.get_storage", return_value=Storage(load_vault=lambda: vault, save_vault=Mock(), backup_vault=Mock())), \
         patch("password_manager.user.save_users") as mock_save:
        assert authenticate_user("alice", "alice_wonderland") == new_key

    mock_save.assert_called_once_with({"alice": {**record, "wrapped_key": pending}})

# A vault that still decrypts with the old key does not prove the pending key unused: users.json is shared by both
# backends, so this may be a vault.json frozen at pm db import while the Postgres vault is already under the pending
# key. Login returns the old key and saves nothing; the pending key stays until a login finishes the rotation or the
# next rotation replaces it. The vault, users.json and their saves are stand-ins, so nothing touches the disk.
@pytest.mark.unit
def test_authenticate_user_keeps_the_pending_key_when_the_vault_still_decrypts_with_the_old_key(make_v2_user):
    old_key, new_key = Fernet.generate_key(), Fernet.generate_key()
    record = make_v2_user(data_key=old_key)["alice"]
    pending = wrap_data_key(new_key, "alice_wonderland", record["kdf"])
    vault = {"alice": {"github": {"password": Fernet(old_key).encrypt(b"pw-1").decode()}}}
    with patch("password_manager.user.load_users", return_value={"alice": {**record, "pending_wrapped_key": pending}}), \
         patch("password_manager.user.get_storage", return_value=Storage(load_vault=lambda: vault, save_vault=Mock(), backup_vault=Mock())), \
         patch("password_manager.user.save_users") as mock_save:
        assert authenticate_user("alice", "alice_wonderland") == old_key

    mock_save.assert_not_called()

# A vault that decrypts with neither key (here one entry under a stray key, as after a damaged or mixed-up restore)
# proves neither key unused, so login returns the old key, as it would without a rotation, and saves nothing: both
# keys stay in users.json until the vault is whole again. Stand-ins only, so nothing touches the disk.
@pytest.mark.unit
def test_authenticate_user_keeps_both_keys_when_the_vault_decrypts_with_neither(make_v2_user):
    old_key, new_key = Fernet.generate_key(), Fernet.generate_key()
    record = make_v2_user(data_key=old_key)["alice"]
    pending = wrap_data_key(new_key, "alice_wonderland", record["kdf"])
    vault = {"alice": {"github": {"password": Fernet(old_key).encrypt(b"pw-1").decode()},
                       "gitlab": {"password": Fernet(Fernet.generate_key()).encrypt(b"pw-2").decode()}}}
    with patch("password_manager.user.load_users", return_value={"alice": {**record, "pending_wrapped_key": pending}}), \
         patch("password_manager.user.get_storage", return_value=Storage(load_vault=lambda: vault, save_vault=Mock(), backup_vault=Mock())), \
         patch("password_manager.user.save_users") as mock_save:
        assert authenticate_user("alice", "alice_wonderland") == old_key

    mock_save.assert_not_called()

# With a key pending, login can only tell which key the vault is under by reading it. A vault that cannot be read
# (load_vault() returns None for a corrupt or invalid one) gives no answer, so login refuses with what to do rather
# than guess, and saves nothing: both keys stay until the vault is readable again. Stand-ins only, no disk.
@pytest.mark.unit
def test_authenticate_user_refuses_to_log_in_while_the_vault_cannot_be_read_to_resolve_a_pending_key(make_v2_user):
    record = make_v2_user()["alice"]
    pending = wrap_data_key(Fernet.generate_key(), "alice_wonderland", record["kdf"])
    with patch("password_manager.user.load_users", return_value={"alice": {**record, "pending_wrapped_key": pending}}), \
         patch("password_manager.user.get_storage", return_value=Storage(load_vault=lambda: None, save_vault=Mock(), backup_vault=Mock())), \
         patch("password_manager.user.save_users") as mock_save, \
         pytest.raises(ValueError, match=r"^A key rotation is unfinished and the vault cannot be read; restore the vault from a vault_backup_\*\.json file, then log in again\.$"):
        authenticate_user("alice", "alice_wonderland")

    mock_save.assert_not_called()

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

@pytest.mark.unit
def test_upgrade_user_record_wraps_the_existing_v1_fernet_key_in_a_v2_record(make_user):
    v1_users = make_user()
    with patch("password_manager.user.load_users", return_value=v1_users):
        v1_fernet_key = authenticate_user("alice", "alice_wonderland")
    v2_record = upgrade_user_record(v1_users["alice"], "alice_wonderland")
    assert validate_users({"alice": v2_record}) is True
    assert v2_record["version"] == 2
    assert unwrap_data_key(v2_record["wrapped_key"], "alice_wonderland", v2_record["kdf"]) == v1_fernet_key

@pytest.mark.unit
def test_upgrade_user_record_raises_value_error_for_a_wrong_v1_password(make_user):
    with pytest.raises(ValueError, match="Incorrect password."):
        upgrade_user_record(make_user()["alice"], "wrongpassword")

@pytest.mark.unit
def test_authenticate_user_upgrades_a_v1_user_to_v2_on_successful_login(make_user, make_v2_user):
    users = {**make_user(username="alice"), **make_v2_user(username="bob")}
    with patch("password_manager.user.load_users", return_value=users), \
         patch("password_manager.user.backup_users", return_value="users_backup.json"), \
         patch("password_manager.user.save_users") as mock_save:
        fernet_key = authenticate_user("alice", "alice_wonderland")
    saved = mock_save.call_args.args[0]
    assert saved["alice"]["version"] == 2
    assert unwrap_data_key(saved["alice"]["wrapped_key"], "alice_wonderland", saved["alice"]["kdf"]) == fernet_key
    assert saved["bob"] == users["bob"]

@pytest.mark.unit
def test_authenticate_user_backs_up_users_json_before_upgrading_a_v1_record(make_user):
    storage = Mock()
    with patch("password_manager.user.load_users", return_value=make_user()), \
         patch("password_manager.user.backup_users", storage.backup_users), \
         patch("password_manager.user.save_users", storage.save_users):
        authenticate_user("alice", "alice_wonderland")
    assert [name for name, *_ in storage.mock_calls] == ["backup_users", "save_users"]

@pytest.mark.unit
def test_authenticate_user_skips_the_upgrade_when_the_users_json_backup_fails(make_user):
    with patch("password_manager.user.load_users", return_value=make_user(enc_salt=b"abcdefghijklmnop")), \
         patch("password_manager.user.backup_users", return_value=None), \
         patch("password_manager.user.save_users") as mock_save:
        assert authenticate_user("alice", "alice_wonderland") == derive_key("alice_wonderland:fernet", b"abcdefghijklmnop")
    mock_save.assert_not_called()

@pytest.mark.unit
@pytest.mark.parametrize("failing", ["backup_users", "save_users"])
def test_authenticate_user_still_logs_in_with_the_v1_key_when_saving_the_upgrade_fails(caplog, make_user, failing):
    with patch("password_manager.user.load_users", return_value=make_user(enc_salt=b"abcdefghijklmnop")), \
         patch("password_manager.user.backup_users", return_value="users_backup.json"), \
         patch("password_manager.user.save_users"), \
         patch(f"password_manager.user.{failing}", side_effect=OSError("No space left on device")), \
         caplog.at_level(logging.ERROR):
        assert authenticate_user("alice", "alice_wonderland") == derive_key("alice_wonderland:fernet", b"abcdefghijklmnop")
    assert "Could not save the v2 upgrade; staying on v1 for now." in caplog.text

@pytest.mark.unit
def test_authenticate_user_leaves_a_v1_record_untouched_on_a_wrong_password(make_user):
    with patch("password_manager.user.load_users", return_value=make_user()), \
         patch("password_manager.user.backup_users") as mock_backup, \
         patch("password_manager.user.save_users") as mock_save, \
         pytest.raises(ValueError, match="Incorrect password."):
        authenticate_user("alice", "wrongpassword")
    mock_backup.assert_not_called()
    mock_save.assert_not_called()
