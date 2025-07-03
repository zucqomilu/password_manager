# tests/test_integration.py
import pytest
from pathlib import Path
from src.user import register_user, authenticate_user
from src.core import save_password, get_password
from src.session import save_session, load_session
from src.storage import load_vault
from cryptography.fernet import Fernet

def register_login_save_session_load_session(username: str, password: str) -> Fernet:
    assert register_user(username, password)
    key = authenticate_user(username, password)
    assert isinstance(key, bytes)
    save_session(username, key)
    session = load_session()
    assert session is not None
    user_loaded, fernet = session
    assert user_loaded == username
    assert isinstance(fernet, Fernet)

    return fernet

def get_vault_user_entry(username: str, set_test_env) -> dict:
    _ = set_test_env
    vault_data = load_vault()
    assert isinstance(vault_data, dict)
    vault_user_entry = vault_data.get(username)
    assert isinstance(vault_user_entry, dict)

    return vault_user_entry

def test_full_user_flow(capsys, set_test_env):
    username, password = "testuser", "secure123"
    fernet = register_login_save_session_load_session(username, password)

    label, pwd = "email", "p@ssW0rd!"
    assert save_password(username, label, pwd, fernet)

    vault_user_entry = get_vault_user_entry(username, set_test_env)
    assert label in vault_user_entry

    get_password(username, label, fernet, show=True)
    captured = capsys.readouterr()
    assert "Password: p@ssW0rd!" in captured.out

def test_overwrite_triggers_versioning_and_backup(set_test_env, monkeypatch):
    username, password = "testuser", "secret123"
    fernet = register_login_save_session_load_session(username, password)
    
    label, pwd1 = "email", "initial-pass"
    assert save_password(username, label, pwd1, fernet)
    
    monkeypatch.setattr("builtins.input", lambda _: "y")
    pwd2 = "new-pass"
    assert save_password(username, label, pwd2, fernet)

    vault_user_entry = get_vault_user_entry(username, set_test_env)
    assert label in vault_user_entry
    versioned_label = f"{label}__v1"
    assert versioned_label in vault_user_entry

    backups = [ f for f in Path(set_test_env).iterdir()
                if f.name.startswith("vault_backup_") and f.name.endswith(".json") ]
    assert len(backups) == 1

def test_cancel_overwrite_does_not_modify_vault(set_test_env, monkeypatch):
    username, password = "testuser", "secret123"
    fernet = register_login_save_session_load_session(username, password)

    label, original_pwd = "email", "initial-pass"
    assert save_password(username, label, original_pwd, fernet)

    monkeypatch.setattr("builtins.input", lambda _: "n")
    new_pwd = "new-pass"
    result = save_password(username, label, new_pwd, fernet)
    assert result is False

    vault_user_entry = get_vault_user_entry(username, set_test_env)
    assert label in vault_user_entry
    assert f"{label}__v1" not in vault_user_entry

    decrypted = fernet.decrypt(vault_user_entry[label]["password"].encode()).decode()
    assert decrypted == original_pwd

def test_login_with_wrong_password_fails(set_test_env):
    _ = set_test_env
    username, correct_password, wrong_password = "testuser", "rightpass", "wrongpass"
    assert register_user(username, correct_password)

    # Authentication with wrong password should raise ValueError
    with pytest.raises(ValueError, match="Incorrect password"):
        authenticate_user(username, wrong_password)

    session = load_session()
    assert session is None

def test_retrieve_previous_password_version(set_test_env, monkeypatch):
    username, password, label = "testuser", "master123", "email"
    old_pwd, new_pwd = "first-password", "second-password"
    fernet = register_login_save_session_load_session(username, password)

    assert save_password(username, label, old_pwd, fernet)

    monkeypatch.setattr("builtins.input", lambda _: "y")
    assert save_password(username, label, new_pwd, fernet)

    vault_user_entry = get_vault_user_entry(username, set_test_env)
    versioned_label = f"{label}__v1"
    assert versioned_label in vault_user_entry

    encrypted_old_pwd = vault_user_entry[versioned_label]["password"].encode()
    decrypted_old_pwd = fernet.decrypt(encrypted_old_pwd).decode()
    assert decrypted_old_pwd == old_pwd

def test_retrieve_nonexistent_label_returns_none(set_test_env):
    _ = set_test_env
    username, password, missing_label = "testuser", "secure123", "does_not_exist"
    fernet = register_login_save_session_load_session(username, password)

    result = get_password(username, missing_label, fernet)
    assert result is None

def test_save_and_get_login_password_pair(set_test_env, fernet):
    username, password, label = "alice", "master123", "email"
    fernet = register_login_save_session_load_session(username, password)

    login, pwd = "alice@example.com", "p@ssW0rd!"
    assert save_password(username, label, pwd, fernet, login=login)

    vault_user_entry = get_vault_user_entry(username, set_test_env)
    encrypted = vault_user_entry["email"]
    assert fernet.decrypt(encrypted["password"].encode()).decode() == pwd
    assert fernet.decrypt(encrypted["login"].encode()).decode() == login
