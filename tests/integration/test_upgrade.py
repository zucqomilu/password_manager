import json
import os

import pytest
from cryptography.fernet import Fernet

from password_manager.cli import main
from password_manager.crypto import derive_key
from password_manager.storage import save_users, save_vault


# A v1 users.json and a vault encrypted with that user's v1 Fernet key, as written before Argon2id
@pytest.fixture
def v1_account(set_test_env, make_user):
    v1_fernet = Fernet(derive_key("alice_wonderland:fernet", b"abcdefghijklmnop"))
    save_users(make_user(enc_salt=b"abcdefghijklmnop"))
    save_vault({"alice": {
        "github": {"password": v1_fernet.encrypt(b"test-only-pass-1").decode(), "login": v1_fernet.encrypt(b"alice@example.com").decode()},
        "github__v1": {"password": v1_fernet.encrypt(b"test-only-pass-0").decode()},
        "gitlab": {"password": v1_fernet.encrypt(b"test-only-pass-2").decode(), "tags": ["work"]},
    }})
    return set_test_env


@pytest.mark.integration
def test_v1_user_logs_in_is_upgraded_and_every_password_still_decrypts(v1_account, capsys):
    with open(os.environ["VAULT_FILE"], "rb") as f:
        vault_before = f.read()

    main(["login", "--username", "alice", "--password", "alice_wonderland"])
    # Log in again so the session key comes from unwrapping the new v2 record, not from the v1 derivation
    main(["logout"])
    main(["login", "--username", "alice", "--password", "alice_wonderland"])
    capsys.readouterr()
    main(["verify"])

    assert capsys.readouterr().out == "3 entries OK\n"
    with open(os.environ["USERS_FILE"]) as f:
        assert json.load(f)["alice"]["version"] == 2
    with open(os.environ["VAULT_FILE"], "rb") as f:
        assert f.read() == vault_before  # never re-encrypted
    assert any(name.startswith("users_backup_") for name in os.listdir(v1_account))


@pytest.mark.integration
def test_after_upgrade_a_wrong_password_fails_and_the_right_one_still_works(v1_account, capsys):
    main(["login", "--username", "alice", "--password", "alice_wonderland"])
    main(["logout"])
    with open(os.environ["USERS_FILE"], "rb") as f:
        users_after_upgrade = f.read()
    capsys.readouterr()

    main(["login", "--username", "alice", "--password", "wrongpassword"])
    assert capsys.readouterr().out == "Login failed: Incorrect password.\n"
    main(["verify"])
    assert capsys.readouterr().out == "You are not logged in. Please run `login` first.\n"
    with open(os.environ["USERS_FILE"], "rb") as f:
        assert f.read() == users_after_upgrade

    main(["login", "--username", "alice", "--password", "alice_wonderland"])
    assert capsys.readouterr().out.startswith("Login successful. Welcome, alice!\n")
    main(["verify"])
    assert capsys.readouterr().out == "3 entries OK\n"
