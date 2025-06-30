# tests/test_integration.py
import json
import pytest
import shutil
import src.constants
from src.user import register_user, authenticate_user
from src.core import save_password, get_password
from src.session import save_session, load_session
from src.storage import load_vault
from cryptography.fernet import Fernet

@pytest.fixture(autouse=True)
def isolate_files(monkeypatch, tmp_path):
    vault = tmp_path / "vault.json"
    users = tmp_path / "users.json"
    session = tmp_path / "session.json"

    monkeypatch.setattr(src.constants, "get_vault", lambda: str(vault))
    monkeypatch.setattr(src.constants, "get_users", lambda: str(users))
    monkeypatch.setattr(src.constants, "get_session", lambda: str(session))
    print("Mocked DB file path:", src.constants.get_vault())

    def patched_backup_vault():
        print("Inside patched backup vault!")
        from datetime import datetime
        backup_filename = tmp_path / f"vault_backup_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json"
        shutil.copy2(vault, backup_filename)
        print(f"Created backup: {backup_filename}")
    monkeypatch.setattr("src.core.backup_vault", patched_backup_vault)

    return tmp_path

def test_full_user_flow(capsys):
    # Step 1: Register user
    username = "testuser"
    password = "secure123"
    assert register_user(username, password)

    # Step 2: Authenticate
    key = authenticate_user(username, password)
    assert isinstance(key, bytes)

    # Step 3: Save session
    save_session(username, key)

    # Step 4: Load session
    loaded = load_session()
    assert loaded is not None
    user_loaded, fernet = loaded
    assert user_loaded == username
    assert isinstance(fernet, Fernet)

    # Step 5: Save a password
    label = "email"
    pwd = "p@ssW0rd!"
    assert save_password(username, label, pwd, fernet)

    # Step 6: Check vault file contents directly
    vault = load_vault()
    assert vault
    assert label in vault[username]

    # Step 7: Get the password and verify printed output
    get_password(username, label, fernet, show=True)
    captured = capsys.readouterr()
    assert "Password: p@ssW0rd!" in captured.out

def test_overwrite_triggers_versioning_and_backup(isolate_files, monkeypatch):
    # Register + authenticate
    username = "testuser"
    password = "secret123"
    assert register_user(username, password)
    key = authenticate_user(username, password)
    save_session(username, key)

    loaded = load_session()
    assert loaded is not None
    user_loaded, fernet_key = loaded
    assert isinstance(fernet_key, Fernet)
    assert user_loaded == username

    # Initial save
    label = "email"
    pwd1 = "initial-pass"
    assert save_password(username, label, pwd1, fernet_key)
    # Overwrite — simulate user input "y"
    monkeypatch.setattr("builtins.input", lambda _: "y")
    pwd2 = "new-pass"
    assert save_password(username, label, pwd2, fernet_key)

    tmp_path = isolate_files
    # Check vault file for versioned label
    with open(tmp_path / "vault.json", "r") as f:
        vault_data = json.load(f)

    user_vault = vault_data.get(username, {})
    assert label in user_vault
    versioned_label = f"{label}__v1"
    assert versioned_label in user_vault

    # Check that backup file exists
    backup_file = next(tmp_path.glob("vault_backup_*.json"), None)
    assert backup_file is not None

def test_cancel_overwrite_does_not_modify_vault(isolate_files, monkeypatch):
    username = "testuser"
    password = "secret123"
    assert register_user(username, password)
    key = authenticate_user(username, password)
    save_session(username, key)
    session = load_session()
    assert session is not None

    username2, fernet = session
    assert username2 == username

    # Initial save
    label = "email"
    original_pwd = "initial-pass"
    assert save_password(username, label, original_pwd, fernet)

    # Simulate user input 'n' to cancel overwrite
    monkeypatch.setattr("builtins.input", lambda _: "n")
    new_pwd = "new-pass"
    result = save_password(username, label, new_pwd, fernet)
    assert result is False

    # Load vault and assert nothing changed
    tmp_path = isolate_files
    with open(tmp_path / "vault.json", "r") as f:
        vault_data = json.load(f)

    user_vault = vault_data.get(username, {})
    assert label in user_vault
    assert f"{label}__v1" not in user_vault

    decrypted = fernet.decrypt(user_vault[label]["password"].encode()).decode()
    assert decrypted == original_pwd

def test_login_with_wrong_password_fails():
    username = "testuser"
    correct_password = "rightpass"
    wrong_password = "wrongpass"

    # Register the user
    assert register_user(username, correct_password)

    # Authentication with wrong password should raise ValueError
    with pytest.raises(ValueError, match="Incorrect password"):
        authenticate_user(username, wrong_password)

    # No session should be saved
    session = load_session()
    assert session is None

def test_retrieve_previous_password_version(monkeypatch):
    username = "testuser"
    password = "master123"
    label = "email"
    old_pwd = "first-password"
    new_pwd = "second-password"

    # Register, login, save session
    assert register_user(username, password)
    key = authenticate_user(username, password)
    save_session(username, key)
    session = load_session()
    assert session is not None
    username2, fernet = session
    assert username2 == username

    # Save initial password
    assert save_password(username, label, old_pwd, fernet)

    # Overwrite with new password, simulate confirmation
    monkeypatch.setattr("builtins.input", lambda _: "y")
    assert save_password(username, label, new_pwd, fernet)

    # Load vault and confirm previous version is present
    vault = load_vault()
    assert vault
    vault_user = vault[username]
    versioned_label = f"{label}__v1"
    assert versioned_label in vault_user

    # Confirm it decrypts to the original password
    encrypted_old_pwd = vault_user[versioned_label]["password"].encode()
    decrypted_old_pwd = fernet.decrypt(encrypted_old_pwd).decode()
    assert decrypted_old_pwd == old_pwd

def test_retrieve_nonexistent_label_returns_none():
    username = "testuser"
    password = "secure123"
    missing_label = "does_not_exist"

    # Register, login, save session
    assert register_user(username, password)
    key = authenticate_user(username, password)
    save_session(username, key)
    session = load_session()
    assert session is not None
    username2, fernet = session
    assert username2 == username

    # Attempt to retrieve a label that doesn't exist
    result = get_password(username, missing_label, fernet)

    # Should return None
    assert result is None
