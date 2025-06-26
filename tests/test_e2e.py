import os, json, re, glob
import tempfile, pytest
from pathlib import Path
from src.cli import main
from unittest.mock import patch

PROJECT_ROOT = Path(__file__).resolve().parent.parent
MAIN_PATH = PROJECT_ROOT / "main.py"

@pytest.fixture
def set_test_env(monkeypatch):
    with tempfile.TemporaryDirectory() as tmpdir:
        monkeypatch.setenv("VAULT_FILE", os.path.join(tmpdir, "vault.json"))
        monkeypatch.setenv("USERS_FILE", os.path.join(tmpdir, "users.json"))
        monkeypatch.setenv("SESSION_FILE", os.path.join(tmpdir, "session.json"))
        yield tmpdir  # Optional: in case the test wants to inspect or write to this dir

def register_and_login(username: str, password: str, capsys, main_func):
    main_func(["register", "--username", username, "--password", password])
    out = capsys.readouterr().out
    assert "Registration successful" in out

    main_func(["login", "--username", username, "--password", password])
    out = capsys.readouterr().out
    assert "Login successful" in out

def generate_and_get(label, capsys, main_func, option=None):
    # Generate password
    main_func(["generate", label])
    out = capsys.readouterr().out
    assert "Generated password:" in out
        
    # Get password
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

def generate_and_list(label, capsys, main_func):
    # Try to generate a password — should fail due to missing session
    main_func(["generate", label])
    out = capsys.readouterr().out
    assert "you are not logged in" in out.lower()

    # Try to list passwords — should also fail
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
    _ = set_test_env
    username, password = "e2euser", "e2epas"
    register_and_login(username, password, capsys, main)
        
    # Check session file is created
    session_path = os.path.join(_, "session.json")
    assert os.path.exists(session_path)
    with open(session_path, "r") as f:
        session_data = json.load(f)
        assert session_data["username"] == username

def test_e2e_incorrect_login_fails(capsys, set_test_env):
    _ = set_test_env
    session_path = os.path.join(_, "session.json")
    username, correct_password, wrong_password = "wronguser", "correct", "incorrect"

    # Register with correct password
    main(["register", "--username", username, "--password", correct_password])
    capsys.readouterr()

    # Try logging in with wrong password
    main(["login", "--username", username, "--password", wrong_password])
    out = capsys.readouterr().out
    assert "login failed" in out.lower()
    assert not os.path.exists(session_path)
        
def test_e2e_corrupted_users_file(capsys, set_test_env):
    _ = set_test_env
    # Corrupt the users file with invalid JSON
    with open(os.path.join(_, "users.json"), "w") as f:
        f.write("{ this is not valid JSON }")

    # Try to register or login (should handle failure)
    main(["register", "--username", "user1", "--password", "pass"])
    out = capsys.readouterr().out

    assert "Error" in out or "failed" in out.lower() or "invalid" in out.lower()

def test_e2e_missing_users_file(capsys, set_test_env):
    _ = set_test_env
    users_file = os.path.join(_, "users.json")
    # Delete the users file
    if os.path.exists(users_file):
        os.remove(users_file)

    # Should recreate the file and succeed
    main(["register", "--username", "user2", "--password", "pass"])
    out = capsys.readouterr().out

    assert "Registration successful" in out
    assert os.path.exists(users_file)

def test_e2e_empty_users_file(capsys, set_test_env):
    _ = set_test_env
    # Create an empty users file (0 bytes)
    with open(os.path.join(_, "users.json"), "w"): pass

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

    generate_and_list(label, capsys, main)

def test_e2e_session_deleted_requires_login(capsys, set_test_env):
    _ = set_test_env
    username, password, label = "ghost", "nopersist", "bank"
    register_and_login(username, password, capsys, main)

    # Simulate session deletion
    session_path = os.path.join(_, "session.json")
    assert os.path.exists(session_path)
    os.remove(session_path)
    assert not os.path.exists(session_path)

    generate_and_list(label, capsys, main)

def test_e2e_corrupted_session_file(capsys, set_test_env):
    _ = set_test_env
    username, password, label = "brokenuser", "pass123", "bank"
    register_and_login(username, password, capsys, main)

    # Corrupt the session file
    with open(os.path.join(_, "session.json"), "w") as f:
        f.write("this is not json")

    # Run a command that requires a valid session
    main(["generate", label])
    out = capsys.readouterr().out

    assert "You are not logged in" in out or "Please run `login` first" in out

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
    _ = set_test_env
    username, password, label = "versionuser", "verpass", "social"
    register_and_login(username, password, capsys, main)

    generate_and_overwrite(label, "y", capsys, main)

    # Check that backup file was created
    vault_dir = os.path.join(_, "vault.json").rsplit("/", 1)[0]
    backups = list(glob.glob(os.path.join(vault_dir, "vault_backup_*.json")))
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
    _ = set_test_env
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
    backup_files = [
        name for name in os.listdir(_)
        if name.startswith("vault_backup_") and name.endswith(".json")
    ]
    assert len(backup_files) == 0, f"Expected no backups, but found: {backup_files}"

def test_e2e_logout_clears_session(capsys, set_test_env):
    _ = set_test_env
    session_path = os.path.join(_, "session.json")
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
    # Register both users
    register_and_login("alice", "wonderland", capsys, main)
    register_and_login("bob", "builder", capsys, main)

    # Try generating a password — it should be for Bob, not Alice
    label = "testlabel"
    main(["generate", label])
    capsys.readouterr()

    # Retrieve password
    main(["get", label, "--show"])
    out = capsys.readouterr().out

    # Confirm it says Bob is logged in
    assert "Password for 'testlabel'" in out
    assert "has been copied to the clipboard" in out

    # Now logout and try getting the password again (should fail)
    main(["logout"])
    capsys.readouterr()

    main(["get", label, "--show"])
    out = capsys.readouterr().out
    assert "not logged in" in out.lower()
