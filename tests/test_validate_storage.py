import pytest, logging
from .conftest import b64
from src.validate_storage import validate_users, validate_vault, is_valid_base64

# === is_valid_base64 ===

# --- Valid base64 without length check ---
def test_is_valid_base64_valid_string():
    assert is_valid_base64(b64(b"hello world"))

# --- Valid base64 with correct expected length ---
def test_is_valid_base64_with_correct_length():
    encoded_data = b64(b"1234567890abcdef")
    assert is_valid_base64(encoded_data, expected_decoded_len=16)

# --- Valid base64 but wrong expected length ---
def test_is_valid_base64_with_incorrect_length():
    encoded = b64(b"short")
    assert not is_valid_base64(encoded, expected_decoded_len=32)

# --- Invalid base64 string ---
def test_is_valid_base64_invalid_string():
    assert not is_valid_base64("this is not base64!!")

# --- Value is not a string ---
@pytest.mark.parametrize("bad_type", [None, 12345, [], {}, b"bytes"])
def test_is_valid_base64_wrong_type(bad_type):
    assert not is_valid_base64(bad_type)

# --- Valid base64 with padding ---
def test_is_valid_base64_with_padding():
    padded = b64(b"padme")  # 5 bytes with padding
    assert is_valid_base64(padded)

# --- Empty string ---
def test_is_valid_base64_empty_string():
    assert is_valid_base64("")

# --- Valid base64 but invalid characters (manipulated) ---
def test_is_valid_base64_with_invalid_chars():
    corrupted = b64(b"valid")[:-2] + "!@"  # introduce invalid characters
    assert not is_valid_base64(corrupted)

# === validate_users ===

# --- Valid Case ---
def test_validate_users_valid(valid_user):
    assert validate_users(valid_user) is True

# --- Multiple users, one invalid ---
def test_validate_users_one_user_invalid(caplog, valid_users):
    valid_users["bob"]["enc_salt"] = "notbase64"
    with caplog.at_level(logging.ERROR):
        assert validate_users(valid_users) is False
        assert "User 'bob' field 'enc_salt' has invalid base64 format." in caplog.text

# --- Top-level structure ---
def test_validate_users_not_dict(caplog, not_dict):
    with caplog.at_level(logging.ERROR):
        assert validate_users(not_dict) is False
        assert "Invalid users format: expected dict at top level — got list." in caplog.text

# --- User entry not a dict ---
def test_validate_users_user_entry_not_dict(caplog, value_not_dict):
    with caplog.at_level(logging.ERROR):
        assert validate_users(value_not_dict) is False
        assert "User 'alice' has invalid data type: expected dict, got str." in caplog.text

# --- Missing required keys ---
@pytest.mark.parametrize("missing_key", ["auth_salt", "enc_salt", "password"])
def test_validate_users_missing_required_key(caplog, valid_user, missing_key):
    del valid_user["alice"][missing_key]
    with caplog.at_level(logging.ERROR):
        assert validate_users(valid_user) is False
        assert f"User 'alice' is missing required fields: {missing_key}." in caplog.text

# --- Extra key ---
def test_validate_users_with_extra_key(caplog, valid_user):
    valid_user["alice"]["extra"] = "something"
    with caplog.at_level(logging.ERROR):
        assert validate_users(valid_user) is False
        assert "User 'alice' has unexpected fields: extra." in caplog.text

# --- Invalid base64 format ---
def test_validate_users_invalid_base64(caplog, make_user):
    with caplog.at_level(logging.ERROR):
        assert validate_users(make_user(auth_salt=b"!!not-base64!!")) is False
        assert "User 'alice' field 'auth_salt' has invalid base64 format." in caplog.text

# --- Valid base64 but wrong decoded length ---
@pytest.mark.parametrize("val", ["auth_salt", "enc_salt", "password"])
def test_validate_users_wrong_decoded_length(caplog, valid_user, val):
    # auth_salt, enc_slat should decode to 16 bytes and password to 32 bytes
    with caplog.at_level(logging.ERROR):
        valid_user["alice"][val] = b64(b"short")
        assert validate_users(valid_user) is False
        assert f"User 'alice' field '{val}' has invalid base64 format." in caplog.text
        valid_user["alice"][val] = b64(b"ThisKeyIsWayTooLong1234567890123456")
        assert validate_users(valid_user) is False
        assert f"User 'alice' field '{val}' has invalid base64 format." in caplog.text

# === validate_vault ===

# --- Valid Case ---
def test_validate_vault_valid(valid_vault):
    assert validate_vault(valid_vault) is True

# --- Multiple users, one invalid ---
def test_validate_vault_multiple_users_one_invalid(caplog, valid_vault_multiple_users):
    valid_vault_multiple_users["bob"]["github"] = { "password": "this is not base64!"}
    with caplog.at_level(logging.ERROR):
        assert validate_vault(valid_vault_multiple_users) is False
        assert "Vault entry 'bob:github' has invalid base64 password." in caplog.text
        
# --- Top-level not dict ---
def test_validate_vault_not_dict(caplog, not_dict):
    with caplog.at_level(logging.ERROR):
        assert validate_vault(not_dict) is False
        assert "Vault should be a top-level dictionary, got list." in caplog.text

# --- User entry not dict ---
def test_validate_vault_user_entry_not_dict(caplog, value_not_dict):
    with caplog.at_level(logging.ERROR):
        assert validate_vault(value_not_dict) is False
        assert "Vault entry for user 'alice' must be a dict, got str" in caplog.text

# --- Label value not a string ---
def test_validate_vault_label_password_value_not_string(caplog, valid_vault):
    valid_vault["alice"]["twitter"]["password"] = 12345
    with caplog.at_level(logging.ERROR):
        assert validate_vault(valid_vault) is False
        assert "Vault entry 'alice:twitter' has invalid base64 password." in caplog.text

# --- Label value not valid base64 ---
def test_validate_vault_label_login_value_not_base64(caplog, valid_vault):
    valid_vault["alice"]["github"]["login"] = "!!not-base64!!" 
    with caplog.at_level(logging.ERROR):
        assert validate_vault(valid_vault) is False
        assert "Vault entry 'alice:github' has invalid base64 login." in caplog.text

# --- Valid base64 but wrong type at label level ---
def test_validate_vault_label_is_dict(caplog, valid_vault):
    valid_vault["alice"]["github"] = b64(b"nested")
    with caplog.at_level(logging.ERROR):
        assert validate_vault(valid_vault) is False
        assert "Vault entry 'alice:github' must be a dict, got str." in caplog.text

# --- Valid base64 but wrong decoded length ---
def test_validate_vault_missing_password(caplog, valid_vault):
    # password should decode to 16 bytes
    with caplog.at_level(logging.ERROR):
        valid_vault["alice"]["github"] = { "login": b64(b"alice_login_name") }
        assert validate_vault(valid_vault) is False
        assert "Vault entry 'alice:github' is missing required 'password' field." in caplog.text
