import builtins

import pytest
from cryptography.fernet import Fernet
from unittest.mock import patch

from password_manager import storage
from password_manager.cli import main
from password_manager.rotation import rotate_data_key
from password_manager.user import authenticate_user


# A vault built through the CLI on the JSON backend: alice (logged in) with github, a kept version and gitlab, and bob,
# whose entries are under his own key. The passwords are test placeholders.
def build_vault(monkeypatch):
    monkeypatch.setattr(builtins, "input", lambda prompt: "y")
    main(["register", "--username", "bob", "--password", "bob_secure_pass1"])
    main(["login", "--username", "bob", "--password", "bob_secure_pass1"])
    main(["set", "bank", "--password", "test-only-pass-4"])
    main(["register", "--username", "alice", "--password", "alice_wonderland"])
    main(["login", "--username", "alice", "--password", "alice_wonderland"])
    main(["set", "github", "--password", "test-only-pass-1", "--login", "alice@example.com", "--tag", "work"])
    main(["set", "github", "--password", "test-only-pass-2"])
    main(["set", "gitlab", "--password", "test-only-pass-3"])


# After a rotation alice's master password unwraps a new data key, every one of her entries decrypts under it to the
# same value, the record carries no pending key, the agent holds the new key so pm get works without logging in
# again, and bob's record and entries are untouched
@pytest.mark.integration
def test_rotate_data_key_reencrypts_the_vault_rewraps_the_key_and_gives_the_agent_the_new_key(set_test_env, fake_agent, monkeypatch, capsys):
    build_vault(monkeypatch)
    old_key = authenticate_user("alice", "alice_wonderland")
    bob_before = (storage.load_users()["bob"], storage.load_vault()["bob"])

    rotate_data_key("alice", "alice_wonderland")

    new_key = authenticate_user("alice", "alice_wonderland")
    assert new_key != old_key
    assert "pending_wrapped_key" not in storage.load_users()["alice"]
    assert {label: Fernet(new_key).decrypt(entry["password"].encode()) for label, entry in storage.load_vault()["alice"].items()} == {
        "github": b"test-only-pass-2", "github__v1": b"test-only-pass-1", "gitlab": b"test-only-pass-3",
    }
    assert Fernet(new_key).decrypt(storage.load_vault()["alice"]["github"]["login"].encode()) == b"alice@example.com"
    assert bytes(fake_agent["state"].key) == new_key
    assert (storage.load_users()["bob"], storage.load_vault()["bob"]) == bob_before
    capsys.readouterr()
    with patch("pyperclip.copy"):
        main(["get", "github", "--show"])
    assert "Password: test-only-pass-2" in capsys.readouterr().out
