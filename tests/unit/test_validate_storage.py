import pytest, logging, base64
from ..conftest import b64
from password_manager.validate_storage import validate_users, validate_vault, is_valid_base64


# === is_valid_base64 ===


# --- Valid base64 without length check ---
@pytest.mark.unit
def test_is_valid_base64_valid_string():
    assert is_valid_base64(b64(b"hello world"))


# --- Valid base64 with correct expected length ---
@pytest.mark.unit
def test_is_valid_base64_with_correct_length():
    encoded_data = b64(b"1234567890abcdef")
    assert is_valid_base64(encoded_data, expected_decoded_len=16)


# --- Valid base64 but wrong expected length ---
@pytest.mark.unit
def test_is_valid_base64_with_incorrect_length():
    encoded = b64(b"short")
    assert not is_valid_base64(encoded, expected_decoded_len=32)


# --- Invalid base64 string ---
@pytest.mark.unit
def test_is_valid_base64_invalid_string():
    assert not is_valid_base64("this is not base64!!")


# --- Value is not a string ---
@pytest.mark.unit
@pytest.mark.parametrize("bad_type", [None, 12345, [], {}, b"bytes"])
def test_is_valid_base64_wrong_type(bad_type):
    assert not is_valid_base64(bad_type)


# --- Valid base64 with padding ---
@pytest.mark.unit
def test_is_valid_base64_with_padding():
    padded = b64(b"padme")  # 5 bytes with padding
    assert is_valid_base64(padded)


# --- Empty string ---
@pytest.mark.unit
def test_is_valid_base64_empty_string():
    assert is_valid_base64("")


# --- Valid base64 but invalid characters (manipulated) ---
@pytest.mark.unit
def test_is_valid_base64_with_invalid_chars():
    corrupted = b64(b"valid")[:-2] + "!@"  # introduce invalid characters
    assert not is_valid_base64(corrupted)


# === validate_users ===


# --- Valid Case ---
@pytest.mark.unit
def test_validate_users_valid(valid_user):
    assert validate_users(valid_user) is True


# --- Valid v2 (Argon2id + wrapped data key) record ---
@pytest.mark.unit
def test_validate_users_accepts_v2_records(make_v2_user):
    assert validate_users(make_v2_user()) is True


# --- v1 records stay valid next to v2 records (mid-migration users.json) ---
@pytest.mark.unit
def test_validate_users_still_accepts_v1_records(make_user, make_v2_user):
    assert validate_users({**make_user(username="alice"), **make_v2_user(username="bob")}) is True


# --- v2 record missing one of its Argon2id parameters ---
@pytest.mark.unit
@pytest.mark.parametrize("param", ["salt", "time_cost", "memory_cost", "parallelism"])
def test_validate_users_rejects_v2_record_missing_kdf_param(caplog, make_v2_user, param):
    users = make_v2_user()
    del users["alice"]["kdf"][param]
    with caplog.at_level(logging.ERROR):
        assert validate_users(users) is False
        assert f"User 'alice' field 'kdf' is missing or invalid: {param}." in caplog.text


# --- v2 record with a present but invalid Argon2id parameter ---
@pytest.mark.unit
@pytest.mark.parametrize("param, value", [
    ("salt", base64.b64encode(b"short").decode()),
    ("salt", "not base64!"),
    ("time_cost", 0),
    ("memory_cost", -1),
    ("parallelism", True),
    ("time_cost", "3"),
    ("unexpected", 1),
])
def test_validate_users_rejects_v2_record_with_invalid_kdf_param_values(caplog, make_v2_user, param, value):
    users = make_v2_user()
    users["alice"]["kdf"][param] = value
    with caplog.at_level(logging.ERROR):
        assert validate_users(users) is False
        assert f"User 'alice' field 'kdf' is missing or invalid: {param}." in caplog.text


# --- v2 record with a missing or an extra top-level field ---
@pytest.mark.unit
@pytest.mark.parametrize("change", [
    lambda record: record.pop("wrapped_key"),
    lambda record: record.update(password="leftover-v1-field"),
], ids=["missing wrapped_key", "extra v1 password field"])
def test_validate_users_rejects_v2_record_with_missing_or_extra_top_level_fields(caplog, make_v2_user, change):
    users = make_v2_user()
    change(users["alice"])
    with caplog.at_level(logging.ERROR):
        assert validate_users(users) is False
        assert "User 'alice' v2 record must have exactly the fields: kdf, version, wrapped_key." in caplog.text


# --- Multiple users, one invalid ---
@pytest.mark.unit
def test_validate_users_one_user_invalid(caplog, valid_users):
    valid_users["bob"]["enc_salt"] = "notbase64"
    with caplog.at_level(logging.ERROR):
        assert validate_users(valid_users) is False
        assert "User 'bob' field 'enc_salt' has invalid base64 format." in caplog.text


# --- Top-level structure ---
@pytest.mark.unit
def test_validate_users_not_dict(caplog, not_dict):
    with caplog.at_level(logging.ERROR):
        assert validate_users(not_dict) is False
        assert "Invalid users format: expected dict at top level — got list." in caplog.text


# --- User entry not a dict ---
@pytest.mark.unit
def test_validate_users_user_entry_not_dict(caplog, value_not_dict):
    with caplog.at_level(logging.ERROR):
        assert validate_users(value_not_dict) is False
        assert "User 'alice' has invalid data type: expected dict, got str." in caplog.text


# --- Missing required keys ---
@pytest.mark.unit
@pytest.mark.parametrize("missing_key", ["auth_salt", "enc_salt", "password"])
def test_validate_users_missing_required_key(caplog, valid_user, missing_key):
    del valid_user["alice"][missing_key]
    with caplog.at_level(logging.ERROR):
        assert validate_users(valid_user) is False
        assert f"User 'alice' is missing required fields: {missing_key}." in caplog.text


# --- Extra key ---
@pytest.mark.unit
def test_validate_users_with_extra_key(caplog, valid_user):
    valid_user["alice"]["extra"] = "something"
    with caplog.at_level(logging.ERROR):
        assert validate_users(valid_user) is False
        assert "User 'alice' has unexpected fields: extra." in caplog.text


# --- Invalid base64 format ---
@pytest.mark.unit
def test_validate_users_invalid_base64(caplog, make_user):
    with caplog.at_level(logging.ERROR):
        assert validate_users(make_user(auth_salt=b"!!not-base64!!")) is False
        assert "User 'alice' field 'auth_salt' has invalid base64 format." in caplog.text


# --- Valid base64 but wrong decoded length ---
@pytest.mark.unit
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
@pytest.mark.unit
def test_validate_vault_valid(valid_vault):
    assert validate_vault(valid_vault) is True


# --- Multiple users, one invalid ---
@pytest.mark.unit
def test_validate_vault_multiple_users_one_invalid(caplog, valid_vault_multiple_users):
    valid_vault_multiple_users["bob"]["github"] = { "password": "this is not base64!"}
    with caplog.at_level(logging.ERROR):
        assert validate_vault(valid_vault_multiple_users) is False
        assert "Vault entry 'bob:github' has invalid base64 password." in caplog.text
        

# --- Top-level not dict ---
@pytest.mark.unit
def test_validate_vault_not_dict(caplog, not_dict):
    with caplog.at_level(logging.ERROR):
        assert validate_vault(not_dict) is False
        assert "Vault should be a top-level dictionary, got list." in caplog.text


# --- User entry not dict ---
@pytest.mark.unit
def test_validate_vault_user_entry_not_dict(caplog, value_not_dict):
    with caplog.at_level(logging.ERROR):
        assert validate_vault(value_not_dict) is False
        assert "Vault entry for user 'alice' must be a dict, got str" in caplog.text


# --- Label value not a string ---
@pytest.mark.unit
def test_validate_vault_label_password_value_not_string(caplog, valid_vault):
    valid_vault["alice"]["twitter"]["password"] = 12345
    with caplog.at_level(logging.ERROR):
        assert validate_vault(valid_vault) is False
        assert "Vault entry 'alice:twitter' has invalid base64 password." in caplog.text


# --- Label value not valid base64 ---
@pytest.mark.unit
def test_validate_vault_label_login_value_not_base64(caplog, valid_vault):
    valid_vault["alice"]["github"]["login"] = "!!not-base64!!" 
    with caplog.at_level(logging.ERROR):
        assert validate_vault(valid_vault) is False
        assert "Vault entry 'alice:github' has invalid base64 login." in caplog.text


# --- Valid base64 but wrong type at label level ---
@pytest.mark.unit
def test_validate_vault_label_is_dict(caplog, valid_vault):
    valid_vault["alice"]["github"] = b64(b"nested")
    with caplog.at_level(logging.ERROR):
        assert validate_vault(valid_vault) is False
        assert "Vault entry 'alice:github' must be a dict, got str." in caplog.text


# --- Valid base64 but wrong decoded length ---
@pytest.mark.unit
def test_validate_vault_missing_password(caplog, valid_vault):
    # password should decode to 16 bytes
    with caplog.at_level(logging.ERROR):
        valid_vault["alice"]["github"] = { "login": b64(b"alice_login_name") }
        assert validate_vault(valid_vault) is False
        assert "Vault entry 'alice:github' is missing required 'password' field." in caplog.text


@pytest.mark.unit
def test_validate_vault_with_tags(valid_vault):
    valid_vault["alice"]["github"]["tags"] = ["development", "droppshipping"]

    assert validate_vault(valid_vault) is True


@pytest.mark.unit
@pytest.mark.parametrize("invalid_tags", ["development", 123, {}, ("development",)])
def test_validate_vault_invalid_tags_type(caplog, valid_vault, invalid_tags):
    valid_vault["alice"]["github"]["tags"] = invalid_tags

    with caplog.at_level(logging.ERROR):
        assert validate_vault(valid_vault) is False
        assert (
            "Vault entry 'alice:github' has invalid tags format."
            in caplog.text
        )


@pytest.mark.unit
def test_validate_vault_tags_contain_non_string(caplog, valid_vault):
    valid_vault["alice"]["github"]["tags"] = ["development", 123]

    with caplog.at_level(logging.ERROR):
        assert validate_vault(valid_vault) is False
        assert (
            "Vault entry 'alice:github' has invalid tags format."
            in caplog.text
        )
