import os, json, re
from pathlib import Path
from src.cli import main
from src.session import load_session
from unittest.mock import patch
from cryptography.fernet import Fernet

PROJECT_ROOT = Path(__file__).resolve().parent.parent
MAIN_PATH = PROJECT_ROOT / "main.py"

def get_session_data(username: str) -> tuple[str, Fernet]:
    session_data = load_session()
    assert isinstance(session_data, tuple)
    loaded_user, fernet = session_data
    assert loaded_user == username
    assert isinstance(fernet, Fernet)

    return session_data

def register_and_login(username: str, password: str, capsys, main_func):
    main_func(["register", "--username", username, "--password", password])
    out = capsys.readouterr().out
    assert "Registration successful" in out

    main_func(["login", "--username", username, "--password", password])
    out = capsys.readouterr().out
    assert "Login successful" in out

def generate_and_get(label, capsys, main_func, option=None):
    main_func(["generate", label])
    out = capsys.readouterr().out
    assert "Generated password:" in out
        
    with patch("pyperclip.copy") as mock_copy:
        if option: main_func(["get", label, option])
        else: main_func(["get", label])
        out = capsys.readouterr().out
        assert "has been copied to the clipboard" in out
        mock_copy.assert_called_once()
        if option == None:
            assert "Password:" not in out
        else:
            match = re.search(r"Password:\s(\S+)", out)
            assert match
            generated_password = match.group(1)
            assert generated_password in out

def generate_and_list_not_logged_in(label, capsys, main_func):
    main_func(["generate", label])
    out = capsys.readouterr().out
    assert "you are not logged in" in out.lower()

    main_func(["list"])
    out = capsys.readouterr().out
    assert "you are not logged in" in out.lower()

def generate_and_overwrite(label, overwrite, capsys, main_func):
    main_func(["generate", label])
    out1 = capsys.readouterr().out
    pw1_match = re.search(r"Generated password:\s(\S+)", out1)
    assert pw1_match
    pw1 = pw1_match.group(1)

    with patch("builtins.input", return_value=overwrite):
        main_func(["generate", label])
    out2 = capsys.readouterr().out
    pw2_match = re.search(r"Generated password:\s(\S+)", out2)
    if overwrite != "y":
        assert "Operation cancelled" in out2
        return pw1, None
    assert pw2_match
    pw2 = pw2_match.group(1)
    assert pw1 != pw2

    return pw1, pw2

def test_e2e_register_and_login(capsys, set_test_env):
    username, password, _ = "e2euser", "e2epas", set_test_env
    register_and_login(username, password, capsys, main)

    session_data = get_session_data(username)
    assert session_data[0] == username

def test_e2e_incorrect_login_fails(capsys, set_test_env):
    session_path = os.path.join(set_test_env, "session.json")
    username, correct_password, wrong_password = "wronguser", "correct", "incorrect"

    main(["register", "--username", username, "--password", correct_password])
    capsys.readouterr()

    # Try logging in with wrong password
    main(["login", "--username", username, "--password", wrong_password])
    out = capsys.readouterr().out
    assert "login failed" in out.lower()
    assert not os.path.exists(session_path)
        
def test_e2e_corrupted_users_file(capsys, set_test_env):
    # Corrupt the users file with invalid JSON
    with open(os.path.join(set_test_env, "users.json"), "w") as f:
        f.write("{ this is not valid JSON }")

    # Try to register or login (should handle failure)
    main(["register", "--username", "user1", "--password", "pass"])
    out = capsys.readouterr().out

    assert "Error: Failed to load users database." in out

def test_e2e_missing_users_file(capsys, set_test_env):
    users_file = os.path.join(set_test_env, "users.json")
    # Delete the users file
    if os.path.exists(users_file):
        os.remove(users_file)

    # Should recreate the file and succeed
    main(["register", "--username", "user2", "--password", "pass"])
    out = capsys.readouterr().out

    assert "Registration successful" in out
    assert os.path.exists(users_file)

def test_e2e_empty_users_file(capsys, set_test_env):
    # Create an empty users file (0 bytes)
    with open(os.path.join(set_test_env, "users.json"), "w"): pass

    # Try to register a new user — should handle gracefully
    main(["register", "--username", "user3", "--password", "pass"])
    out = capsys.readouterr().out

    assert "Failed to load users database." in out

def test_e2e_generate_and_get(capsys, set_test_env):
    _ = set_test_env
    username, password, label = "alice", "wonderland", "email"
    register_and_login(username, password, capsys, main)

    generate_and_get(label, capsys, main, "--show")

def test_e2e_get_without_show(capsys, set_test_env):
    _ = set_test_env
    username, password, label = "carol", "pass123", "social"
    register_and_login(username, password, capsys, main)

    generate_and_get(label, capsys, main)
        
def test_e2e_session_persistence(capsys, set_test_env):
    _ = set_test_env
    username, password, label = "persistuser", "stayloggedin", "github"
    register_and_login(username, password, capsys, main)

    generate_and_get(label, capsys, main)

    # Run 'get' to confirm password was saved and session is still active
    main(["get", label, "--show"])
    out = capsys.readouterr().out
    assert f"Password for '{label}'" in out or "Password:" in out

def test_e2e_no_session_requires_login(capsys, set_test_env):
    _ = set_test_env
    username, password, label = "ghost", "nopersist", "bank"

    # Register but do not log in
    main(["register", "--username", username, "--password", password])
    out = capsys.readouterr().out
    assert "registration successful" in out.lower()

    generate_and_list_not_logged_in(label, capsys, main)

def test_e2e_session_deleted_requires_login(capsys, set_test_env):
    username, password, label = "ghost", "nopersist", "bank"
    register_and_login(username, password, capsys, main)

    # Simulate session deletion
    session_path = os.path.join(set_test_env, "session.json")
    assert os.path.exists(session_path)
    os.remove(session_path)
    assert not os.path.exists(session_path)

    generate_and_list_not_logged_in(label, capsys, main)

def test_e2e_corrupted_session_file(capsys, set_test_env):
    username, password, label = "brokenuser", "pass123", "bank"
    register_and_login(username, password, capsys, main)

    # Corrupt the session file
    with open(os.path.join(set_test_env, "session.json"), "w") as f:
        f.write("this is not json")

    # Run a command that requires a valid session
    main(["generate", label])
    out = capsys.readouterr().out

    assert "You are not logged in" in out and "Please run `login` first" in out

def test_e2e_list_labels(capsys, set_test_env):
    _ = set_test_env
    username, password = "bob", "builder" 
    register_and_login(username, password, capsys, main)
    labels = ["github", "email", "bank"]

    # Generate passwords for all labels
    for label in labels:
        main(["generate", label])
        capsys.readouterr()  # Clear output

    # List saved labels
    main(["list"])
    out = capsys.readouterr().out
    
    # Ensure all labels appear in output
    for label in labels:
        assert label in out

def test_e2e_get_nonexistent_label(capsys, set_test_env):
    _ = set_test_env
    username, password, label = "missinguser", "hunter2", "nonexistent"
    register_and_login(username, password, capsys, main)
    
    # Attempt to get a non-existent label
    main(["get", label, "--show"])
    out = capsys.readouterr().out

    assert f"No password found for '{label}'" in out

def test_e2e_overwrite_creates_backup(capsys, set_test_env):
    username, password, label = "versionuser", "verpass", "social"
    register_and_login(username, password, capsys, main)

    generate_and_overwrite(label, "y", capsys, main)

    # Check that backup file was created
    backups = [ f for f in Path(set_test_env).iterdir()
                if f.name.startswith("vault_backup_") and f.name.endswith(".json") ]
    assert len(backups) == 1

def test_e2e_overwrite_creates_versions(capsys, set_test_env):
    _ = set_test_env
    username, password, label = "versionuser", "secure123", "github"
    register_and_login(username, password, capsys, main)

    pw1, pw2 = generate_and_overwrite(label, "y", capsys, main)

    # Check that the label with version 1 has the old password
    main(["get", f"{label}__v1", "--show"])
    out = capsys.readouterr().out
    assert f"Password: {pw1}" in out

    # Check that the label has the newly created password
    main(["get", label, "--show"])
    out = capsys.readouterr().out
    assert f"Password: {pw2}" in out

def test_e2e_cancel_overwrite_preserves_password(capsys, set_test_env):
    username, password, label = "canceluser", "refusepass", "bank"
    register_and_login(username, password, capsys, main)

    original_password, pw2 = generate_and_overwrite(label, "n", capsys, main)
    out = capsys.readouterr().out
    assert pw2 == None

    # Get password and verify it's still the original
    main(["get", label, "--show"])
    out = capsys.readouterr().out
    assert f"Password: {original_password}" in out

    # Check that no backup file has been created
    backup_files = [ name for name in os.listdir(set_test_env)
                     if name.startswith("vault_backup_") and name.endswith(".json") ]
    assert len(backup_files) == 0

def test_e2e_logout_clears_session(capsys, set_test_env):
    session_path = os.path.join(set_test_env, "session.json")
    username, password = "logoutuser", "logoutpass"
    register_and_login(username, password, capsys, main)

    # Ensure session file exists after login
    assert os.path.exists(session_path)

    # Run logout
    main(["logout"])
    capsys.readouterr()

    # Session should be cleared
    assert not os.path.exists(session_path)

    # Try to list passwords without logging in again
    main(["list"])
    out = capsys.readouterr().out
    assert "not logged in" in out

def test_e2e_single_active_session(capsys, set_test_env):
    _ = set_test_env
    register_and_login("alice", "wonderland", capsys, main)
    register_and_login("bob", "builder", capsys, main)

    # Try generating a password — it should be for Bob, not Alice
    label = "testlabel"
    main(["generate", label])
    capsys.readouterr()

    # Retrieve password
    main(["get", label, "--show"])
    out = capsys.readouterr().out
    assert "Password for 'testlabel'" in out
    assert "has been copied to the clipboard" in out

    # Now logout and try getting the password again (should fail)
    main(["logout"])
    capsys.readouterr()

    main(["get", label, "--show"])
    out = capsys.readouterr().out
    assert "not logged in" in out

def test_cli_generate_with_login(set_test_env, capsys):
    username, password = "alice", "wonderland"
    register_and_login(username, password, capsys, main)

    # Generate + save a password with login
    main(["generate", "github", "--login", "alice@example.com"])
    out = capsys.readouterr().out
    assert "Saved password for 'github'" in out
    assert "Generated password:" in out

    # Check vault content
    with open(os.path.join(set_test_env, "vault.json"), "r") as f:
        vault = json.load(f)

    assert isinstance(vault, dict)

    # Load Fernet key from session file
    session_data = get_session_data(username)
    assert isinstance(session_data, tuple)
    fernet = session_data[1]
    
    # Extract the encrypted fields
    encrypted_entry = vault[username]["github"]
    encrypted_pw = encrypted_entry["password"]
    encrypted_login = encrypted_entry["login"]

    # Decrypt and verify
    decrypted_pw = fernet.decrypt(encrypted_pw.encode()).decode()
    decrypted_login = fernet.decrypt(encrypted_login.encode()).decode()

    assert len(decrypted_pw) == 16  # Default password length
    assert decrypted_login == "alice@example.com"
