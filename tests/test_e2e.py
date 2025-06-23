import subprocess
import json
import os
import tempfile
import sys
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parent.parent
MAIN_PATH = PROJECT_ROOT / "main.py"

def run_cli(username, password, option, env):
    """Run the CLI with given arguments and optional input."""
    result = subprocess.run(
        [sys.executable, str(MAIN_PATH), option, "--username", username, "--password", password],
        text=True,
        capture_output=True,
        env=env
    )
    return result

def test_e2e_register_and_login():
    with tempfile.TemporaryDirectory() as tmpdir:
        # Create temp paths for test DB and session files
        vault = os.path.join(tmpdir, "vault.json")
        users = os.path.join(tmpdir, "users.json")
        session = os.path.join(tmpdir, "session.json")

        # Patch environment variables to point to temp files
        env = os.environ.copy()
        env["DB_FILE"] = vault
        env["USERS_FILE"] = users
        env["SESSION_FILE"] = session
        
        username = "e2euser"
        password = "e2epass"
        
        # Create a dummy main.py entrypoint in tmpdir (symlink or copy if needed)
        # but for now assume main.py is at the project root

        # Register user
        result = run_cli(username, password, "register", env)
        print(result.stdout)
        assert result.returncode == 0
        assert "registered successfully" in result.stdout.lower()
        
        # Login user
        result = run_cli(username, password, "login", env)
        print(result.stdout)
        assert result.returncode == 0
        assert "login successful" in result.stdout.lower()
        
        # Check session file is created
        assert os.path.exists(session)
        with open(session, "r") as f:
            session_data = json.load(f)
            assert session_data["username"] == username
