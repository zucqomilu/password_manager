import pytest
import logging
import pyperclip
from unittest.mock import Mock, call, patch, ANY
from cryptography.fernet import Fernet
from password_manager.core import generate_password, save_password, get_password, list_labels, remove_tags, verify_vault, delete_label
from password_manager.session import SessionLocked
from password_manager.storage import Storage


@pytest.mark.unit
def test_generate_password():
    password = generate_password()
    assert isinstance(password, str)
    assert len(password) == 16


@pytest.mark.unit
def test_generate_password_length():
    password = generate_password(20)
    assert isinstance(password, str)
    assert len(password) == 20


@pytest.mark.unit
def test_save_password_without_login(fernet):
    with patch("password_manager.core.load_vault", return_value={"alice": {}}), \
         patch("password_manager.core.save_vault") as mock_save:
        result = save_password("alice", "github", fernet, "supersecret")
        assert result is True
        saved = mock_save.call_args[0][0]
        assert "password" in saved["alice"]["github"]


@pytest.mark.unit
def test_save_password_with_login(fernet):
    with patch("password_manager.core.load_vault", return_value={"alice": {}}), \
         patch("password_manager.core.save_vault") as mock_save:
        result = save_password("alice", "github", fernet, "supersecret", login="user@example.com")
        assert result is True
        saved = mock_save.call_args[0][0]
        entry = saved["alice"]["github"]
        assert "password" in entry and "login" in entry


@pytest.mark.unit
def test_save_password_overwrite_prompt_no(caplog, fernet, valid_vault):
    with patch("password_manager.core.load_vault", return_value=valid_vault), \
         patch("password_manager.core.input", return_value='n'), \
         caplog.at_level(logging.INFO):
        result = save_password("alice", "github", fernet, "newpass")
        assert result is False
        assert "User cancelled overwrite for 'github'." in caplog.text


@pytest.mark.unit
def test_save_password_backup_decryption_fail(caplog, fernet, valid_vault):
    valid_vault["alice"]["github"]["password"] = "notbase64==="
    with patch("password_manager.core.load_vault", return_value=valid_vault), \
         patch("password_manager.core.input", return_value='y'), \
         caplog.at_level(logging.ERROR):
        result = save_password("alice", "github", fernet, "newpw")
        assert result is False
        assert "Failed to overwrite 'github' due to incorrect master password." in caplog.text


@pytest.mark.unit
def test_save_password_lets_session_locked_through_instead_of_reporting_a_wrong_master_password(valid_vault):
    locked_cipher = Mock(decrypt=Mock(side_effect=SessionLocked), encrypt=Mock(side_effect=SessionLocked))
    with patch("password_manager.core.load_vault", return_value=valid_vault), \
         patch("password_manager.core.save_vault") as mock_save, \
         patch("password_manager.core.backup_vault"), \
         patch("password_manager.core.input", return_value='y'), \
         pytest.raises(SessionLocked):
        save_password("alice", "github", locked_cipher, "newpw")
    mock_save.assert_not_called()


@pytest.mark.unit
def test_save_password_new_label(fernet):
    with patch("password_manager.core.load_vault", return_value={}), \
         patch("password_manager.core.save_vault") as mock_save, \
         patch("password_manager.core.backup_vault"), \
         patch("password_manager.core.input", return_value='y'):
        result = save_password("user1", "gmail", fernet, "pass123")
        assert result is True
        mock_save.assert_called_once()


@pytest.mark.unit
def test_save_password_logs_and_prints_on_vault_load_failure(capsys, caplog, fernet):
    with patch("password_manager.core.load_vault", return_value=None), \
         caplog.at_level(logging.ERROR):
        save_password("alice", "gmail", fernet, "securepw123")
        out = capsys.readouterr().out
        assert "Failed to load password vault" in out
        assert "Vault loading failed: returned None." in caplog.text


@pytest.mark.unit
def test_save_password_creates_correct_version_label(fernet, valid_vault):
    with patch("password_manager.core.load_vault", return_value=valid_vault), \
         patch("password_manager.core.save_vault") as mock_save, \
         patch("password_manager.core.backup_vault") as mock_backup, \
         patch("builtins.input", return_value="y"), \
         patch("builtins.print"):
        result = save_password("alice", "twitter", fernet, "newtwitterpass12")
        assert result is True
        saved_data = mock_save.call_args[0][0]  # The vault dict passed to save_vault
        assert "twitter__v2" in saved_data["alice"]  # Next available version
        mock_backup.assert_called_once()


@pytest.mark.unit
def test_save_password_overwrite(fernet, valid_vault):
    with patch("password_manager.core.load_vault", return_value=valid_vault), \
         patch("password_manager.core.save_vault") as mock_save, \
         patch("password_manager.core.backup_vault") as mock_backup, \
         patch("password_manager.core.input", return_value='y'):
        result = save_password("alice", "github", fernet, "newpass")
        assert result is True
        mock_backup.assert_called_once()
        mock_save.assert_called_once()



# The backend is passed in, so the same save_password() writes to the JSON files or to Postgres. An overwrite uses all
# three functions; the module's own JSON functions are patched only to prove they are never reached.
@pytest.mark.unit
def test_save_password_writes_through_the_storage_functions_it_is_given(fernet, valid_vault):
    storage = Storage(load_vault=Mock(return_value=valid_vault), save_vault=Mock(), backup_vault=Mock())
    with patch("password_manager.core.load_vault") as json_load, \
         patch("password_manager.core.save_vault") as json_save, \
         patch("password_manager.core.backup_vault") as json_backup, \
         patch("password_manager.core.input", return_value="y"):
        assert save_password("alice", "github", fernet, "newpass", storage=storage) is True
    storage.backup_vault.assert_called_once()
    assert fernet.decrypt(storage.save_vault.call_args[0][0]["alice"]["github"]["password"].encode()) == b"newpass"
    json_load.assert_not_called()
    json_save.assert_not_called()
    json_backup.assert_not_called()

@pytest.mark.unit
def test_save_password_user_declines_overwrite(fernet, valid_vault):
    with patch("password_manager.core.load_vault", return_value=valid_vault), \
         patch("password_manager.core.save_vault") as mock_save, \
         patch("password_manager.core.input", return_value='n'), \
         patch("builtins.print") as mock_print:
        result = save_password("alice", "github", fernet, "newpass")
        assert result is False
        mock_save.assert_not_called()
        mock_print.assert_any_call("Operation cancelled.")


@pytest.mark.unit
def test_save_password_overwrite_fails_on_bad_decryption(fernet, valid_vault):
    valid_vault["alice"]["github"]["password"] = "invalid_encrypted_data:newpassword"
    with patch("password_manager.core.load_vault", return_value=valid_vault), \
         patch("password_manager.core.save_vault") as mock_save, \
         patch("password_manager.core.backup_vault") as mock_backup, \
         patch("builtins.input", return_value="y"), \
         patch("builtins.print") as mock_print:
        assert not save_password("alice", "github", fernet, "newpassword")
        mock_save.assert_not_called()
        mock_backup.assert_not_called()
        mock_print.assert_any_call("Error: A password already exists for 'github', and the provided master password does not match.")


@pytest.mark.unit
def test_set_login_only(fernet):
    with patch("password_manager.core.load_vault", return_value={"bob": {}}), \
         patch("password_manager.core.save_vault") as mock_save, \
         patch("builtins.print") as mock_print:
        assert not save_password("bob", "gitlab", login="bob@example.com", fernet=fernet)
        mock_save.assert_not_called()
        mock_print.assert_any_call("Error: Cannot create label 'gitlab' without a password.")


@pytest.mark.unit
def test_set_password_only(fernet):
    with patch("password_manager.core.load_vault", return_value={"bob": {}}), \
         patch("password_manager.core.save_vault") as mock_save:
        assert save_password("bob", "gitlab", password="mysecretpassword", fernet=fernet)
        saved_data = mock_save.call_args[0][0]
        password_encrypted = saved_data["bob"]["gitlab"]["password"]
        assert isinstance(password_encrypted, str)
        assert fernet.decrypt(password_encrypted.encode()).decode() == "mysecretpassword"


@pytest.mark.unit
def test_set_password_and_login(fernet):
    with patch("password_manager.core.load_vault", return_value={"bob": {}}), \
         patch("password_manager.core.save_vault") as mock_save:
        assert save_password("bob", "gitlab", password="mysecretpassword", login="bob@example.com", fernet=fernet)
        saved_data = mock_save.call_args[0][0]
        password_encrypted = saved_data["bob"]["gitlab"]["password"]
        login_encrypted = saved_data["bob"]["gitlab"]["login"]
        assert isinstance(password_encrypted, str)
        assert fernet.decrypt(password_encrypted.encode()).decode() == "mysecretpassword"
        assert isinstance(login_encrypted, str)
        assert fernet.decrypt(login_encrypted.encode()).decode() == "bob@example.com"


@pytest.mark.unit
def test_get_password_success(fernet, capsys, valid_vault):
    with patch("password_manager.core.load_vault", return_value=valid_vault), \
         patch("password_manager.core.pyperclip.copy") as mock_clipboard:
        get_password("alice", "github", fernet, show=True)
        captured = capsys.readouterr()
        assert "supersecurepass1" in captured.out
        mock_clipboard.assert_called_once()


@pytest.mark.unit
def test_get_password_with_login(capsys, fernet, valid_vault):
    with patch("password_manager.core.load_vault", return_value=valid_vault), patch("pyperclip.copy"):
        get_password("alice", "github", fernet, show=True)
        out = capsys.readouterr().out
        assert "Password: supersecurepass1" in out
        assert "Login: alice@example.com" in out


@pytest.mark.unit
def test_get_password_reports_a_clipboard_failure_and_still_shows_the_password_with_show(fernet, capsys, valid_vault):
    with patch("password_manager.core.load_vault", return_value=valid_vault), \
         patch("password_manager.core.pyperclip.copy", side_effect=pyperclip.PyperclipException("no clipboard")):
        get_password("alice", "github", fernet, show=True)
    out = capsys.readouterr().out
    assert "Could not copy the password for 'github' to the clipboard." in out
    assert "Password: supersecurepass1" in out
    assert "Login: alice@example.com" in out
    assert "data corrupted" not in out


@pytest.mark.unit
def test_get_password_logs_and_prints_on_vault_load_failure(capsys, caplog, fernet):
    with patch("password_manager.core.load_vault", return_value=None), \
         caplog.at_level(logging.ERROR):
        get_password("alice", "gmail", fernet)
        out = capsys.readouterr().out
        assert "Failed to load password vault" in out
        assert "Vault loading failed: returned None." in caplog.text


@pytest.mark.unit
def test_get_password_invalid_decryption(fernet, capsys, valid_vault):
    valid_vault["alice"]["github"]["password"] = "invaliddata"
    with patch("password_manager.core.load_vault", return_value=valid_vault):
        get_password("alice", "github", fernet)
        captured = capsys.readouterr()
        assert "Incorrect master password" in captured.out


@pytest.mark.unit
def test_get_password_lets_session_locked_through_instead_of_reporting_corrupted_data(valid_vault):
    locked_cipher = Mock(decrypt=Mock(side_effect=SessionLocked))
    with patch("password_manager.core.load_vault", return_value=valid_vault), \
         patch("password_manager.core.pyperclip.copy"), \
         pytest.raises(SessionLocked):
        get_password("alice", "github", locked_cipher)


@pytest.mark.unit
def test_get_password_label_not_found(fernet, valid_vault):
    with patch("password_manager.core.load_vault", return_value=valid_vault), \
         patch("builtins.print") as mock_print:
        get_password("alice", "nonexistent", fernet)
        mock_print.assert_any_call("No password found for 'nonexistent'.")


@pytest.mark.unit
def test_list_labels_filters_decryptable(fernet, capsys, valid_vault):
    valid_vault["alice"]["github"]["password"] = "invaliddata"
    with patch("password_manager.core.load_vault", return_value=valid_vault):
        list_labels("alice", fernet)
        captured = capsys.readouterr()
        assert "- twitter" in captured.out
        assert "- github" not in captured.out


@pytest.mark.unit
def test_list_labels_lets_session_locked_through_instead_of_hiding_entries(valid_vault):
    locked_cipher = Mock(decrypt=Mock(side_effect=SessionLocked))
    with patch("password_manager.core.load_vault", return_value=valid_vault), \
         pytest.raises(SessionLocked):
        list_labels("alice", locked_cipher)


@pytest.mark.unit
def test_list_labels_empty_user_vault(fernet):
    with patch("password_manager.core.load_vault", return_value={"testuser": {}}), \
         patch("builtins.print") as mock_print:
        list_labels("testuser", fernet)
        mock_print.assert_any_call("No passwords found for this user.")


@pytest.mark.unit
def test_list_labels_logs_and_prints_on_vault_load_failure(capsys, caplog, fernet):
    with patch("password_manager.core.load_vault", return_value=None), \
         caplog.at_level(logging.ERROR):
        list_labels("alice", fernet)
        out = capsys.readouterr().out
        assert "Failed to load password vault" in out
        assert "Vault loading failed: returned None." in caplog.text


@pytest.mark.unit
def test_list_labels_filters_versioned_backups(fernet, capsys, valid_vault):
    with patch("password_manager.core.load_vault", return_value=valid_vault):
        list_labels("alice", fernet)

        captured = capsys.readouterr()

        assert "- github" in captured.out
        assert "- twitter" in captured.out
        assert "- twitter__v1" not in captured.out


@pytest.mark.unit
def test_list_labels_keeps_labels_with_similar_names(fernet, capsys, valid_vault):
    valid_vault["alice"]["my__vpn"] = {
        "password": fernet.encrypt(b"vpnpassword").decode()
    }
    valid_vault["alice"]["github__version"] = {
        "password": fernet.encrypt(b"versionpassword").decode()
    }
    valid_vault["alice"]["github__vabc"] = {
        "password": fernet.encrypt(b"abpassword").decode()
    }

    with patch("password_manager.core.load_vault", return_value=valid_vault):
        list_labels("alice", fernet)

        captured = capsys.readouterr()

        assert "- my__vpn" in captured.out
        assert "- github__version" in captured.out
        assert "- github__vabc" in captured.out


@pytest.mark.unit
def test_list_labels_filters_multiple_digit_versioned_backups(fernet, capsys, valid_vault):
    valid_vault["alice"]["github__v10"] = {
        "password": fernet.encrypt(b"oldpassword").decode()
    }

    with patch("password_manager.core.load_vault", return_value=valid_vault):
        list_labels("alice", fernet)

        captured = capsys.readouterr()

        assert "- github__v10" not in captured.out


@pytest.mark.unit
def test_set_tag_on_existing_label(fernet, valid_vault):
    with patch("password_manager.core.load_vault", return_value=valid_vault), \
         patch("password_manager.core.save_vault") as mock_save:

        result = save_password(
            "alice",
            "github",
            fernet,
            tags=["development"]
        )

        assert result is True

        saved_data = mock_save.call_args[0][0]
        entry = saved_data["alice"]["github"]

        assert "tags" in entry
        assert "development" in entry["tags"]


@pytest.mark.unit
def test_set_tag_preserves_existing_tags(fernet, valid_vault):
    valid_vault["alice"]["github"]["tags"] = ["development"]

    with patch("password_manager.core.load_vault", return_value=valid_vault), \
         patch("password_manager.core.save_vault") as mock_save:

        result = save_password(
            "alice",
            "github",
            fernet,
            tags=["business"]
        )

        assert result is True

        saved_data = mock_save.call_args[0][0]
        tags = saved_data["alice"]["github"]["tags"]

        assert tags == ["development", "business"]


@pytest.mark.unit
def test_set_multiple_tags(fernet, valid_vault):
    with patch("password_manager.core.load_vault", return_value=valid_vault), \
         patch("password_manager.core.save_vault") as mock_save:

        result = save_password(
            "alice",
            "github",
            fernet,
            tags=["development", "business", "personal"]
        )

        assert result is True

        saved_data = mock_save.call_args[0][0]
        tags = saved_data["alice"]["github"]["tags"]

        assert tags == ["development", "business", "personal"]


@pytest.mark.unit
def test_set_tag_does_not_duplicate_existing_tag(fernet, valid_vault):
    valid_vault["alice"]["github"]["tags"] = ["development"]

    with patch("password_manager.core.load_vault", return_value=valid_vault), \
         patch("password_manager.core.save_vault") as mock_save:

        result = save_password(
            "alice",
            "github",
            fernet,
            tags=["development"]
        )

        assert result is True

        saved_data = mock_save.call_args[0][0]
        tags = saved_data["alice"]["github"]["tags"]

        assert tags == ["development"]


@pytest.mark.unit
def test_set_tag_does_not_create_version_backup(fernet, valid_vault):
    valid_vault["alice"]["github"]["tags"] = ["development"]

    with patch("password_manager.core.load_vault", return_value=valid_vault), \
         patch("password_manager.core.save_vault") as mock_save, \
         patch("password_manager.core.backup_vault") as mock_backup, \
         patch("password_manager.core.input") as mock_input:

        result = save_password("alice", "github", fernet, tags=["droppshipping"])

        assert result is True

        saved_data = mock_save.call_args[0][0]
        github = saved_data["alice"]

        assert "github" in github
        assert "github__v1" not in github
        assert github["github"]["tags"] == [
            "development",
            "droppshipping"
        ]

        mock_backup.assert_not_called()
        mock_input.assert_not_called()


@pytest.mark.unit
def test_list_labels_filters_by_tag(fernet, capsys, valid_vault):
    valid_vault["alice"]["github"]["tags"] = ["development", "work"]
    valid_vault["alice"]["twitter"]["tags"] = ["social"]

    with patch("password_manager.core.load_vault", return_value=valid_vault):
        list_labels("alice", fernet, tags=["development"])

    captured = capsys.readouterr()

    assert "- github" in captured.out
    assert "- twitter" not in captured.out


@pytest.mark.unit
def test_list_labels_returns_multiple_labels_with_tag(fernet, capsys, valid_vault):
    valid_vault["alice"]["github"]["tags"] = ["development"]
    valid_vault["alice"]["twitter"]["tags"] = ["development", "social"]

    with patch("password_manager.core.load_vault", return_value=valid_vault):
        list_labels("alice", fernet, tags=["development"])

    captured = capsys.readouterr()

    assert "- github" in captured.out
    assert "- twitter" in captured.out


@pytest.mark.unit
def test_list_labels_no_matching_tag(fernet, capsys, valid_vault):
    valid_vault["alice"]["github"]["tags"] = ["work"]
    valid_vault["alice"]["twitter"]["tags"] = ["social"]

    with patch("password_manager.core.load_vault", return_value=valid_vault):
        list_labels("alice", fernet, tags=["development"])

    captured = capsys.readouterr()

    assert "No passwords found with tag 'development'." in captured.out
    assert "- github" not in captured.out
    assert "- twitter" not in captured.out


@pytest.mark.unit
def test_list_labels_tag_filter_excludes_untagged_labels(fernet, capsys, valid_vault):
    valid_vault["alice"]["github"]["tags"] = ["development"]

    with patch("password_manager.core.load_vault", return_value=valid_vault):
        list_labels("alice", fernet, tags=["development"])

    captured = capsys.readouterr()

    assert "- github" in captured.out
    assert "- twitter" not in captured.out


@pytest.mark.unit
def test_list_labels_filters_by_multiple_tags(fernet, capsys, valid_vault):
    valid_vault["alice"]["github"]["tags"] = ["development", "work"]
    valid_vault["alice"]["twitter"]["tags"] = ["development", "social"]

    with patch("password_manager.core.load_vault", return_value=valid_vault):
        list_labels("alice", fernet, tags=["development", "work"])

    captured = capsys.readouterr()
    assert "- github" in captured.out
    assert "- twitter" not in captured.out


@pytest.mark.unit
def test_list_labels_no_matching_multiple_tags(fernet, capsys, valid_vault):
    valid_vault["alice"]["github"]["tags"] = ["work"]
    valid_vault["alice"]["twitter"]["tags"] = ["social"]

    with patch("password_manager.core.load_vault", return_value=valid_vault):
        list_labels("alice", fernet, tags=["development", "business"])

    captured = capsys.readouterr()

    assert "No passwords found with tags: development, business." in captured.out


@pytest.mark.unit
def test_remove_tags_removes_existing_tag(valid_vault):
    valid_vault["alice"]["github"]["tags"] = ["development", "work"]

    with patch("password_manager.core.load_vault", return_value=valid_vault), \
         patch("password_manager.core.save_vault") as mock_save_vault:

        remove_tags("alice", "github", tags=["development"])

    assert valid_vault["alice"]["github"]["tags"] == ["work"]
    mock_save_vault.assert_called_once_with(valid_vault)


@pytest.mark.unit
def test_remove_tags_handles_vault_load_failure(capsys):
    with patch("password_manager.core.load_vault", return_value=None), \
         patch("password_manager.core.save_vault") as mock_save_vault:

        remove_tags("alice", "github", tags=["development"])

    captured = capsys.readouterr()

    assert "Failed to load password vault." in captured.out
    mock_save_vault.assert_not_called()


@pytest.mark.unit
def test_remove_tags_preserves_password_and_login(valid_vault):
    valid_vault["alice"]["github"]["tags"] = ["development", "work"]

    original_password = valid_vault["alice"]["github"]["password"]
    original_login = valid_vault["alice"]["github"]["login"]

    with patch("password_manager.core.load_vault", return_value=valid_vault), \
         patch("password_manager.core.save_vault") as mock_save_vault:

        remove_tags("alice", "github", tags=["development"])

    entry = valid_vault["alice"]["github"]

    assert entry["password"] == original_password
    assert entry["login"] == original_login
    assert entry["tags"] == ["work"]

    mock_save_vault.assert_called_once_with(valid_vault)


@pytest.mark.unit
def test_remove_tags_removes_multiple_tags(valid_vault):
    valid_vault["alice"]["github"]["tags"] = ["development", "work", "personal"]

    with patch("password_manager.core.load_vault", return_value=valid_vault), \
         patch("password_manager.core.save_vault") as mock_save_vault:

        remove_tags("alice", "github", tags=["development", "personal"])

    assert valid_vault["alice"]["github"]["tags"] == ["work"]
    mock_save_vault.assert_called_once_with(valid_vault)


@pytest.mark.unit
def test_remove_tags_removes_tags_field_when_last_tag_removed(valid_vault):
    valid_vault["alice"]["github"]["tags"] = ["development"]

    with patch("password_manager.core.load_vault", return_value=valid_vault), \
         patch("password_manager.core.save_vault") as mock_save_vault:

        remove_tags("alice", "github", tags=["development"])

    entry = valid_vault["alice"]["github"]

    assert "tags" not in entry
    mock_save_vault.assert_called_once_with(valid_vault)


@pytest.mark.unit
def test_remove_tags_handles_label_without_tags(valid_vault):
    valid_vault["alice"]["github"].pop("tags", None)

    with patch("password_manager.core.load_vault", return_value=valid_vault), \
         patch("password_manager.core.save_vault") as mock_save_vault:

        remove_tags("alice", "github", tags=["development"])

    assert "tags" not in valid_vault["alice"]["github"]
    mock_save_vault.assert_not_called()
    

@pytest.mark.unit
def test_remove_tags_does_not_save_when_tag_does_not_exist(valid_vault):
    valid_vault["alice"]["github"]["tags"] = ["development", "work"]

    with patch("password_manager.core.load_vault", return_value=valid_vault), \
         patch("password_manager.core.save_vault") as mock_save_vault:

        remove_tags("alice", "github", tags=["personal"])

    assert valid_vault["alice"]["github"]["tags"] == ["development", "work"]
    mock_save_vault.assert_not_called()


@pytest.mark.unit
def test_remove_tags_removes_existing_tags_and_ignores_missing_tags(valid_vault):
    valid_vault["alice"]["github"]["tags"] = ["development", "work", "personal"]

    with patch("password_manager.core.load_vault", return_value=valid_vault), \
         patch("password_manager.core.save_vault") as mock_save_vault:

        remove_tags("alice", "github", tags=["development", "nonexistent"])

    assert valid_vault["alice"]["github"]["tags"] == ["work", "personal"]
    mock_save_vault.assert_called_once_with(valid_vault)


@pytest.mark.unit
def test_remove_tags_handles_nonexistent_label(valid_vault, capsys):
    with patch("password_manager.core.load_vault", return_value=valid_vault), \
         patch("password_manager.core.save_vault") as mock_save_vault:

        remove_tags("alice", "nonexistent", tags=["development"])

    captured = capsys.readouterr()

    assert "Password label 'nonexistent' not found." in captured.out
    mock_save_vault.assert_not_called()


@pytest.mark.unit
def test_remove_tags_does_not_create_password_backup(valid_vault):
    valid_vault["alice"]["github"]["tags"] = ["development", "work"]

    original_labels = set(valid_vault["alice"])

    with patch("password_manager.core.load_vault", return_value=valid_vault), \
         patch("password_manager.core.save_vault") as mock_save_vault:

        remove_tags("alice", "github", tags=["development"])

    assert set(valid_vault["alice"]) == original_labels
    mock_save_vault.assert_called_once_with(valid_vault)


@pytest.mark.unit
def test_verify_vault_returns_count_of_entries_that_decrypt(fernet, valid_vault):
    valid_vault["alice"]["gitlab"] = {"password": Fernet(Fernet.generate_key()).encrypt(b"test-only-pass-1").decode()}
    with patch("password_manager.core.load_vault", return_value=valid_vault):
        assert verify_vault("alice", fernet)["ok"] == 3


@pytest.mark.unit
def test_verify_vault_reports_labels_whose_password_fails_to_decrypt(fernet, valid_vault):
    valid_vault["alice"]["gitlab"] = {"password": Fernet(Fernet.generate_key()).encrypt(b"test-only-pass-1").decode()}
    with patch("password_manager.core.load_vault", return_value=valid_vault):
        assert verify_vault("alice", fernet)["bad_password"] == ["gitlab"]


@pytest.mark.unit
def test_verify_vault_reports_labels_whose_login_fails_to_decrypt(fernet, valid_vault):
    valid_vault["alice"]["github"]["login"] = Fernet(Fernet.generate_key()).encrypt(b"alice@example.com").decode()
    with patch("password_manager.core.load_vault", return_value=valid_vault):
        assert verify_vault("alice", fernet) == {"ok": 2, "bad_password": [], "bad_login": ["github"]}


@pytest.mark.unit
def test_verify_vault_returns_none_when_vault_cannot_be_loaded(fernet):
    with patch("password_manager.core.load_vault", return_value=None):
        assert verify_vault("alice", fernet) is None


@pytest.mark.unit
def test_delete_label_removes_label_from_users_vault(valid_vault):
    with patch("password_manager.core.load_vault", return_value=valid_vault), \
         patch("password_manager.core.save_vault") as mock_save, \
         patch("builtins.input", return_value="y"):
        delete_label("alice", "github")
        assert mock_save.call_args.args[0]["alice"].keys() == {"twitter", "twitter__v1"}


@pytest.mark.unit
def test_delete_label_does_not_remove_the_labels_versions(valid_vault):
    with patch("password_manager.core.load_vault", return_value=valid_vault), \
         patch("password_manager.core.save_vault") as mock_save, \
         patch("builtins.input", return_value="y"):
        delete_label("alice", "twitter")
        assert mock_save.call_args.args[0]["alice"].keys() == {"github", "twitter__v1"}


@pytest.mark.unit
def test_delete_label_leaves_labels_that_only_share_a_prefix_untouched(valid_vault):
    valid_vault["alice"]["github-work"] = valid_vault["alice"]["github"]
    valid_vault["alice"]["githubv1"] = valid_vault["alice"]["github"]
    with patch("password_manager.core.load_vault", return_value=valid_vault), \
         patch("password_manager.core.save_vault") as mock_save, \
         patch("builtins.input", return_value="y"):
        delete_label("alice", "github")
        assert mock_save.call_args.args[0]["alice"].keys() == {"github-work", "githubv1", "twitter", "twitter__v1"}


@pytest.mark.unit
def test_delete_label_backs_up_vault_before_deleting(valid_vault):
    calls = Mock()
    with patch("password_manager.core.load_vault", return_value=valid_vault), \
         patch("password_manager.core.backup_vault", calls.backup_vault), \
         patch("password_manager.core.save_vault", calls.save_vault), \
         patch("builtins.input", return_value="y"):
        delete_label("alice", "github")
        assert calls.mock_calls == [call.backup_vault(), call.save_vault(ANY)]


@pytest.mark.unit
@pytest.mark.parametrize("answer", ["n", "", "yes"])
def test_delete_label_cancels_unless_user_confirms_with_y(valid_vault, capsys, answer):
    with patch("password_manager.core.load_vault", return_value=valid_vault), \
         patch("password_manager.core.backup_vault") as mock_backup, \
         patch("password_manager.core.save_vault") as mock_save, \
         patch("builtins.input", return_value=answer):
        delete_label("alice", "github")
        mock_backup.assert_not_called()
        mock_save.assert_not_called()
        assert "Operation cancelled." in capsys.readouterr().out


@pytest.mark.unit
def test_delete_label_reports_error_for_label_that_does_not_exist(valid_vault, capsys):
    with patch("password_manager.core.load_vault", return_value=valid_vault), \
         patch("password_manager.core.backup_vault") as mock_backup, \
         patch("password_manager.core.save_vault") as mock_save, \
         patch("builtins.input") as mock_input:
        delete_label("alice", "gitlab")
        mock_input.assert_not_called()
        mock_backup.assert_not_called()
        mock_save.assert_not_called()
        assert capsys.readouterr().out == "Password label 'gitlab' not found.\n"


@pytest.mark.unit
def test_delete_label_reports_error_when_vault_cannot_be_loaded(capsys):
    with patch("password_manager.core.load_vault", return_value=None), \
         patch("password_manager.core.backup_vault") as mock_backup, \
         patch("password_manager.core.save_vault") as mock_save, \
         patch("builtins.input") as mock_input:
        delete_label("alice", "github")
        mock_input.assert_not_called()
        mock_backup.assert_not_called()
        mock_save.assert_not_called()
        assert capsys.readouterr().out == "Failed to load password vault. The vault may be corrupted or unreadable.\n"
