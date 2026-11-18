import builtins
import os

import pytest
from cryptography.fernet import Fernet, InvalidToken
from unittest.mock import patch

from password_manager import storage
from password_manager.cli import main
from password_manager.crypto import wrap_data_key
from password_manager.rotation import RotationAborted, rotate_data_key
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


def read_files(directory):
    return {name: open(os.path.join(directory, name), "rb").read() for name in ("users.json", "vault.json")}


# A mistyped master password would wrap the new key under a password no one knows, so it is refused before anything
# else: both files stay byte for byte as they were, no backup is written, and the agent keeps the old key
@pytest.mark.integration
def test_rotate_data_key_refuses_a_wrong_master_password_and_writes_nothing(set_test_env, fake_agent, monkeypatch):
    build_vault(monkeypatch)
    files, names, agent_key = read_files(set_test_env), sorted(os.listdir(set_test_env)), bytes(fake_agent["state"].key)

    with pytest.raises(ValueError, match="^Incorrect password.$"):
        rotate_data_key("alice", "alice_wonderlanD")

    assert read_files(set_test_env) == files
    assert sorted(os.listdir(set_test_env)) == names
    assert bytes(fake_agent["state"].key) == agent_key


# One entry alice's key cannot decrypt (here gitlab, encrypted under a stray key) means the vault cannot be moved to a
# new key without losing it, so the rotation stops before any write: both files stay as they were, no backup is
# written, and the agent keeps the old key, so every other password still reads as before
@pytest.mark.integration
def test_rotate_data_key_writes_nothing_when_an_entry_does_not_decrypt(set_test_env, fake_agent, monkeypatch):
    build_vault(monkeypatch)
    vault = storage.load_vault()
    stray = Fernet(Fernet.generate_key()).encrypt(b"test-only-pass-3").decode()
    storage.save_vault({**vault, "alice": {**vault["alice"], "gitlab": {**vault["alice"]["gitlab"], "password": stray}}})
    files, names, agent_key = read_files(set_test_env), sorted(os.listdir(set_test_env)), bytes(fake_agent["state"].key)

    with pytest.raises(InvalidToken):
        rotate_data_key("alice", "alice_wonderland")

    assert read_files(set_test_env) == files
    assert sorted(os.listdir(set_test_env)) == names
    assert bytes(fake_agent["state"].key) == agent_key


# save_users() returns without writing when a record fails validation, so the rotation reads users.json back before it
# touches the vault: had it gone on, the vault would be under a key that is wrapped nowhere. Here validation refuses
# every change to alice's record; the rotation stops with the reason, both files stay as they were, and the agent
# keeps the old key.
@pytest.mark.integration
def test_rotate_data_key_stops_before_saving_the_vault_when_users_json_did_not_take_the_pending_key(set_test_env, fake_agent, monkeypatch):
    build_vault(monkeypatch)
    files, agent_key, alice = read_files(set_test_env), bytes(fake_agent["state"].key), storage.load_users()["alice"]
    real_validate_users = storage.validate_users
    monkeypatch.setattr(storage, "validate_users", lambda users: users["alice"] == alice and real_validate_users(users))

    with pytest.raises(RotationAborted, match="^users.json did not take the new key; nothing was changed$"):
        rotate_data_key("alice", "alice_wonderland")

    assert read_files(set_test_env) == files
    assert bytes(fake_agent["state"].key) == agent_key


# save_vault() also returns without writing when validation fails. Had the rotation gone on, users.json would hold only
# the new key while the vault is still under the old one, so it reads the vault back first. Here validation refuses
# the re-encrypted vault; the rotation stops with the reason, the vault is as it was, and the master password and the
# agent keep the old key. The pending key stays: a failed read-back does not prove the vault was not written, so
# dropping it is left to login, which keeps whichever key decrypts the vault.
@pytest.mark.integration
def test_rotate_data_key_keeps_the_old_key_when_the_vault_save_did_not_take_effect(set_test_env, fake_agent, monkeypatch):
    build_vault(monkeypatch)
    users, vault, agent_key = storage.load_users(), storage.load_vault(), bytes(fake_agent["state"].key)
    vault_file = read_files(set_test_env)["vault.json"]
    real_validate_vault = storage.validate_vault
    monkeypatch.setattr(storage, "validate_vault", lambda data: data == vault and real_validate_vault(data))

    with pytest.raises(RotationAborted, match="^the vault did not take the new key; the old key is kept$"):
        rotate_data_key("alice", "alice_wonderland")

    assert authenticate_user("alice", "alice_wonderland") == agent_key
    assert {**storage.load_users()["alice"], "pending_wrapped_key": None} == {**users["alice"], "pending_wrapped_key": None}
    assert read_files(set_test_env)["vault.json"] == vault_file
    assert bytes(fake_agent["state"].key) == agent_key


# The way back if a rotation goes wrong in a way the checks cannot see: before the first write, users.json and the vault
# are copied next to themselves, so restoring both copies gives back the old key and the entries it decrypts. The
# copies hold what the files held before the rotation, byte for byte.
@pytest.mark.integration
def test_rotate_data_key_backs_up_users_json_and_the_vault_before_writing(set_test_env, fake_agent, monkeypatch):
    build_vault(monkeypatch)
    files = read_files(set_test_env)

    rotate_data_key("alice", "alice_wonderland")

    backups = {name: open(os.path.join(set_test_env, name), "rb").read() for name in os.listdir(set_test_env) if "_backup_" in name}
    assert files["users.json"] in [content for name, content in backups.items() if name.startswith("users_backup_")]
    assert files["vault.json"] in [content for name, content in backups.items() if name.startswith("vault_backup_")]


# Without its backup a rotation has no way back if something goes wrong that the checks cannot see, so a backup that
# was not made (backup_vault() returns None, as for a vault file that is gone) stops it before the first write: both
# files stay as they were and the agent keeps the old key
@pytest.mark.integration
def test_rotate_data_key_stops_and_writes_nothing_when_a_backup_could_not_be_made(set_test_env, fake_agent, monkeypatch):
    build_vault(monkeypatch)
    files, agent_key = read_files(set_test_env), bytes(fake_agent["state"].key)
    monkeypatch.setattr(storage, "backup_vault", lambda: None)

    with pytest.raises(RotationAborted, match="^the vault could not be backed up; nothing was changed$"):
        rotate_data_key("alice", "alice_wonderland")

    assert read_files(set_test_env) == files
    assert bytes(fake_agent["state"].key) == agent_key


# The users.json backup is the copy of the old wrapped key, the one way back to the entries if both files must be
# restored, so a users.json backup that was not made (backup_users() returns None) stops the rotation before it backs
# up the vault or writes anything: both files stay as they were and the agent keeps the old key
@pytest.mark.integration
def test_rotate_data_key_stops_and_writes_nothing_when_users_json_could_not_be_backed_up(set_test_env, fake_agent, monkeypatch):
    build_vault(monkeypatch)
    files, names, agent_key = read_files(set_test_env), sorted(os.listdir(set_test_env)), bytes(fake_agent["state"].key)
    monkeypatch.setattr("password_manager.rotation.backup_users", lambda: None)

    with pytest.raises(RotationAborted, match="^users.json could not be backed up; nothing was changed$"):
        rotate_data_key("alice", "alice_wonderland")

    assert read_files(set_test_env) == files
    assert sorted(os.listdir(set_test_env)) == names
    assert bytes(fake_agent["state"].key) == agent_key


# Login never drops a pending key, so one can be left over from a rotation that was interrupted earlier. A rotation
# that completes ends with the new key as the only one: the leftover is gone from alice's record, so no later login
# needs to read the vault, and every entry decrypts with the key her master password unwraps.
@pytest.mark.integration
def test_rotate_data_key_replaces_a_leftover_pending_key(set_test_env, fake_agent, monkeypatch):
    build_vault(monkeypatch)
    users = storage.load_users()
    leftover = wrap_data_key(Fernet.generate_key(), "alice_wonderland", users["alice"]["kdf"])
    storage.save_users({**users, "alice": {**users["alice"], "pending_wrapped_key": leftover}})

    rotate_data_key("alice", "alice_wonderland")

    assert "pending_wrapped_key" not in storage.load_users()["alice"]
    new_key = authenticate_user("alice", "alice_wonderland")
    assert {label: Fernet(new_key).decrypt(entry["password"].encode()) for label, entry in storage.load_vault()["alice"].items()} == {
        "github": b"test-only-pass-2", "github__v1": b"test-only-pass-1", "gitlab": b"test-only-pass-3",
    }


# With a key pending, login reads the vault, which under PM_STORAGE=postgres is the database. With no server
# (conftest's PM_DATABASE_URL points where nothing listens) it says the rotation needs Postgres to finish, without
# the usual advice to switch to vault.json, which may be under the other key. users.json and the agent are unchanged.
@pytest.mark.integration
def test_main_login_says_the_rotation_needs_postgres_when_the_database_is_unreachable_during_a_pending_rotation(set_test_env, fake_agent, monkeypatch, capsys):
    build_vault(monkeypatch)
    users = storage.load_users()
    pending = wrap_data_key(Fernet.generate_key(), "alice_wonderland", users["alice"]["kdf"])
    storage.save_users({**users, "alice": {**users["alice"], "pending_wrapped_key": pending}})
    files, agent_key = read_files(set_test_env), bytes(fake_agent["state"].key)
    monkeypatch.setenv("PM_STORAGE", "postgres")
    capsys.readouterr()

    main(["login", "--username", "alice", "--password", "alice_wonderland"])

    assert capsys.readouterr().out == (
        "Login failed: could not reach the Postgres database; a key rotation is unfinished and needs it to finish.\n"
        "Nothing was changed; start the database and log in again.\n"
    )
    assert read_files(set_test_env) == files
    assert bytes(fake_agent["state"].key) == agent_key


class Interrupted(Exception):
    pass


# A crash (power loss, kill) during a rotation, at either point where users.json holds both keys: before the vault is
# saved under the new key, or after it but before users.json keeps only the new key. Logging in through pm then gives
# a key every password and login decrypts with, kept versions included; the rotation is finished only when the vault
# is under the new key, and otherwise the pending key stays for a later login or rotation.
@pytest.mark.integration
@pytest.mark.parametrize("crash_at, finished", [("vault save", False), ("final users.json save", True)])
def test_interrupted_rotate_data_key_still_logs_in_and_reads_every_password(set_test_env, fake_agent, monkeypatch, capsys, crash_at, finished):
    build_vault(monkeypatch)
    real_save_users, real_save_vault = storage.save_users, storage.save_vault
    saves = []

    def save_users(users):
        saves.append(users)
        if crash_at == "final users.json save" and len(saves) == 2:
            raise Interrupted()
        real_save_users(users)

    def save_vault(vault):
        if crash_at == "vault save":
            raise Interrupted()
        real_save_vault(vault)

    with patch("password_manager.rotation.save_users", save_users), patch.object(storage, "save_vault", save_vault), \
         pytest.raises(Interrupted):
        rotate_data_key("alice", "alice_wonderland")

    main(["login", "--username", "alice", "--password", "alice_wonderland"])
    capsys.readouterr()
    with patch("pyperclip.copy"):
        for label in ("github", "github__v1", "gitlab"):
            main(["get", label, "--show"])
    output = capsys.readouterr().out

    assert all(f"Password: {password}" in output for password in ("test-only-pass-2", "test-only-pass-1", "test-only-pass-3"))
    assert "alice@example.com" in output
    assert ("pending_wrapped_key" not in storage.load_users()["alice"]) == finished


# pm get --show for each of alice's labels: True when every password and the github login read back
def reads_every_password(capsys):
    capsys.readouterr()
    with patch("pyperclip.copy"):
        for label in ("github", "github__v1", "gitlab"):
            main(["get", label, "--show"])
    output = capsys.readouterr().out
    return all(f"Password: {password}" in output for password in ("test-only-pass-2", "test-only-pass-1", "test-only-pass-3")) \
        and "alice@example.com" in output


# pm rotate-key as it is run by hand: with alice logged in, her master password moves every entry to a new key. It
# reports the backups and the rotation, every password and login reads back at once (the agent was given the new key),
# and again after a fresh login, which now unwraps the new key.
@pytest.mark.integration
def test_main_rotate_key_keeps_every_password_readable_after_rotation(set_test_env, fake_agent, monkeypatch, capsys):
    build_vault(monkeypatch)
    old_key = authenticate_user("alice", "alice_wonderland")
    capsys.readouterr()

    main(["rotate-key", "--password", "alice_wonderland"])

    output = capsys.readouterr().out
    assert [line.split(": ")[0] for line in output.splitlines()] == ["Created backup", "Created backup", "Data key rotated"]
    assert output.endswith("Data key rotated: every password and login is now encrypted under a new key.\n")
    assert authenticate_user("alice", "alice_wonderland") != old_key
    assert reads_every_password(capsys)
    main(["login", "--username", "alice", "--password", "alice_wonderland"])
    assert reads_every_password(capsys)
