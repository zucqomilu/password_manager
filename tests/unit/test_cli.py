import argparse
import pytest
import re
import sys
from unittest.mock import ANY, Mock, call, patch
from password_manager import cli
from password_manager.session import SessionLocked


def run_cli_with_args(args):
    with patch.object(sys, 'argv', args):
        cli.main()


@pytest.mark.unit
def test_register_user():
    with patch('password_manager.cli.register_user') as mock_register_user, \
         patch('builtins.input', return_value='testuser'), \
         patch('getpass.getpass', return_value='testpass'):
        mock_register_user.return_value = True
        run_cli_with_args(['prog', 'register'])
        mock_register_user.assert_called_once_with('testuser', 'testpass')


@pytest.mark.unit
def test_login_success():
    with patch('password_manager.cli.authenticate_user') as mock_authenticate_user, \
         patch('password_manager.cli.save_session') as mock_save_session, \
         patch('builtins.input', return_value='testuser'), \
         patch('getpass.getpass', return_value='testpass'):
        mock_authenticate_user.return_value = b'somefernetkey'
        run_cli_with_args(['prog', 'login'])
        mock_authenticate_user.assert_called_once_with('testuser', 'testpass')
        mock_save_session.assert_called_once()


@pytest.mark.unit
def test_login_failure(capsys):
    with patch.object(sys, "argv", ["prog", "login"]), \
         patch("builtins.input", return_value="testuser"), \
         patch("getpass.getpass", return_value="wrongpassword"), \
         patch('password_manager.cli.authenticate_user', side_effect=ValueError("Login failed: Incorrect password.")):
        cli.main()
        captured = capsys.readouterr()
        assert "Login failed: Incorrect password." in captured.out
    

@pytest.mark.unit
def test_logout():
    with patch('password_manager.cli.clear_session') as mock_clear_session:
        run_cli_with_args(['prog', 'logout'])
        mock_clear_session.assert_called_once()


@pytest.mark.unit
def test_generate_command():
    with patch('password_manager.cli.load_session') as mock_load_session, \
         patch('password_manager.cli.generate_password') as mock_generate_password, \
         patch('password_manager.cli.save_password') as mock_save_password:
        mock_load_session.return_value = ('testuser', b'fernet')
        mock_generate_password.return_value = 'password123!'
        mock_save_password.return_value = True
        run_cli_with_args(['prog', 'generate', 'mylabel', '--length', '20'])
        mock_generate_password.assert_called_once_with(20)
        mock_save_password.assert_called_once_with('testuser', 'mylabel', b'fernet', password='password123!', login=None, storage=ANY)


@pytest.mark.unit
def test_set_command_success():
    with patch('password_manager.cli.load_session') as mock_load_session, \
         patch('password_manager.cli.save_password') as mock_save_password:
        mock_load_session.return_value = ('testuser', b'fernet')
        run_cli_with_args(['prog', 'set', 'mylabel', '--password', 'mypassword', '--login', 'testuser@example.com'])
        mock_save_password.assert_called_once_with('testuser', 'mylabel', b'fernet', password='mypassword', login='testuser@example.com', tags=None, storage=ANY)


@pytest.mark.unit
def test_set_command_failure(capsys):
    with patch('password_manager.cli.load_session') as mock_load_session, \
         patch('password_manager.cli.save_password') as mock_save_password:
        mock_load_session.return_value = ('testuser', b'fernet')
        run_cli_with_args(['prog', 'set', 'mylabel'])
        mock_save_password.assert_not_called()
        captured = capsys.readouterr()
        assert "Error: You must specify at least --password or --login or --tags." in captured.out


@pytest.mark.unit
def test_get_command():
    with patch('password_manager.cli.load_session') as mock_load_session, \
         patch('password_manager.cli.get_password') as mock_get_password:
        mock_load_session.return_value = ('testuser', b'fernet')
        run_cli_with_args(['prog', 'get', 'mylabel', '--show'])
        mock_get_password.assert_called_once_with('testuser', 'mylabel', b'fernet', show=True, storage=ANY)


@pytest.mark.unit
def test_list_command():
    with patch('password_manager.cli.load_session') as mock_load_session, \
         patch('password_manager.cli.list_labels') as mock_list_labels:
        mock_load_session.return_value = ('testuser', b'fernet')
        run_cli_with_args(['prog', 'list'])
        mock_list_labels.assert_called_once_with('testuser', b'fernet', tags=None, storage=ANY)


@pytest.mark.unit
def test_no_session_for_protected_commands(capfd):
    with patch('password_manager.cli.load_session', return_value=None):
        run_cli_with_args(['prog', 'list'])
        output = capfd.readouterr()
        assert "not logged in" in output.out.lower()


@pytest.mark.unit
@pytest.mark.parametrize("args, command_function", [
    (['prog', 'generate', 'mylabel'], 'save_password'),
    (['prog', 'set', 'mylabel', '--password', 'mypassword'], 'save_password'),
    (['prog', 'get', 'mylabel'], 'get_password'),
    (['prog', 'list'], 'list_labels'),
    (['prog', 'verify'], 'verify_vault'),
])
def test_main_asks_for_login_when_the_session_locks_during_a_command(capsys, args, command_function):
    with patch('password_manager.cli.load_session', return_value=('testuser', b'fernet')), \
         patch(f'password_manager.cli.{command_function}', side_effect=SessionLocked):
        run_cli_with_args(args)
    assert capsys.readouterr().out.endswith("Your session has expired. Please run `login` and try again.\n")


@pytest.mark.unit
def test_main_no_longer_calls_refresh_session():
    with patch('password_manager.cli.load_session', return_value=('testuser', b'fernet')), \
         patch('password_manager.cli.list_labels'), \
         patch('password_manager.session.keyring') as mock_keyring:
        run_cli_with_args(['prog', 'list'])
    # The agent refreshes the session whenever the key is used; nothing in the keyring is read or rewritten
    assert mock_keyring.mock_calls == []


@pytest.mark.unit
def test_set_command_with_tag():
    with patch('password_manager.cli.load_session') as mock_load_session, \
         patch('password_manager.cli.save_password') as mock_save_password:
        mock_load_session.return_value = ('testuser', b'fernet')

        run_cli_with_args(['prog', 'set', 'mylabel', '--tag', 'droppshipping'])

        mock_save_password.assert_called_once_with(
            'testuser',
            'mylabel',
            b'fernet',
            password=None,
            login=None,
            tags=['droppshipping'],
            storage=ANY,
        )


@pytest.mark.unit
def test_list_command_with_tag():
    with patch('password_manager.cli.load_session') as mock_load_session, \
         patch('password_manager.cli.list_labels') as mock_list_labels:
        mock_load_session.return_value = ('testuser', b'fernet')

        run_cli_with_args(['prog', 'list', '--tag', 'droppshipping'])

        mock_list_labels.assert_called_once_with(
            'testuser',
            b'fernet',
            tags=['droppshipping'],
            storage=ANY,
        )


@pytest.mark.unit
def test_list_command_with_multiple_tags():
    with patch('password_manager.cli.load_session') as mock_load_session, \
         patch('password_manager.cli.list_labels') as mock_list_labels:
        mock_load_session.return_value = ('testuser', b'fernet')

        run_cli_with_args(['prog', 'list', '--tag', 'droppshipping', 'economy'])

        mock_list_labels.assert_called_once_with(
            'testuser',
            b'fernet',
            tags=['droppshipping', 'economy'],
            storage=ANY,
        )


@pytest.mark.unit
def test_remove_command_with_tag():
    with patch('password_manager.cli.load_session') as mock_load_session, \
         patch('password_manager.cli.remove_tags') as mock_remove_tags:
        mock_load_session.return_value = ('testuser', b'fernet')

        run_cli_with_args(['prog', 'remove', 'github', '--tag', 'development'])

        mock_remove_tags.assert_called_once_with(
            'testuser',
            'github',
            tags=['development'],
            storage=ANY,
        )


@pytest.mark.unit
def test_remove_command_with_multiple_tags():
    with patch('password_manager.cli.load_session') as mock_load_session, \
         patch('password_manager.cli.remove_tags') as mock_remove_tags:

        mock_load_session.return_value = ('testuser', b'fernet')

        run_cli_with_args(['prog', 'remove', 'github', '--tag', 'development', 'work'])

        mock_remove_tags.assert_called_once_with(
            'testuser',
            'github',
            tags=['development', 'work'],
            storage=ANY,
        )


@pytest.mark.unit
def test_verify_command_prints_verification_summary(capsys):
    with patch('password_manager.cli.load_session', return_value=('testuser', b'fernet')), \
         patch('password_manager.cli.verify_vault', return_value={"ok": 2, "bad_password": ["gitlab"], "bad_login": ["github"]}) as mock_verify_vault:
        run_cli_with_args(['prog', 'verify'])
        mock_verify_vault.assert_called_once_with('testuser', b'fernet', storage=ANY)
        assert capsys.readouterr().out == (
            "2 entries OK\n"
            "Password failed to decrypt: gitlab\n"
            "Login failed to decrypt: github\n"
        )


@pytest.mark.unit
def test_verify_command_prints_error_when_vault_cannot_be_loaded(capsys):
    with patch('password_manager.cli.load_session', return_value=('testuser', b'fernet')), \
         patch('password_manager.cli.verify_vault', return_value=None):
        run_cli_with_args(['prog', 'verify'])
        assert capsys.readouterr().out == "Failed to load password vault. The vault may be corrupted or unreadable.\n"


@pytest.mark.unit
def test_delete_command_calls_delete_label_for_given_label():
    with patch('password_manager.cli.load_session', return_value=('testuser', b'fernet')), \
         patch('password_manager.cli.delete_label') as mock_delete_label:
        run_cli_with_args(['prog', 'delete', 'github'])
        mock_delete_label.assert_called_once_with('testuser', 'github', storage=ANY)


@pytest.mark.unit
def test_build_parser_returns_parser_with_every_subcommand():
    assert re.search(r"\{(.+?)\}", cli.build_parser().format_help()).group(1).split(",") == [
        "register", "login", "logout", "generate", "set", "get", "remove", "delete", "list", "verify", "db", "completion",
    ]


@pytest.mark.unit
def test_main_calls_argcomplete_autocomplete_before_parse_args():
    calls = Mock()
    calls.parser.parse_args.return_value = argparse.Namespace(command='logout')
    with patch('password_manager.cli.build_parser', return_value=calls.parser), \
         patch('password_manager.cli.argcomplete', calls.argcomplete), \
         patch('password_manager.cli.clear_session'):
        cli.main(['logout'])
        assert calls.mock_calls[:2] == [call.argcomplete.autocomplete(calls.parser, always_complete_options=False), call.parser.parse_args(['logout'])]


@pytest.mark.unit
def test_completion_command_prints_bash_script_that_never_falls_back_to_file_names(capsys):
    with patch('password_manager.cli.load_session') as mock_load_session:
        run_cli_with_args(['prog', 'completion'])
        script = capsys.readouterr().out
        assert "complete -o nospace -o bashdefault -F _python_argcomplete pm" in script
        assert "-o default" not in script
        mock_load_session.assert_not_called()


# Faked, like everywhere in the suite: the real harden_process() would harden the pytest process. One parent mock
# records the order: the process is hardened before the first prompt, so the master password typed there never sits
# in a dumpable process.
@pytest.mark.unit
def test_main_calls_harden_process_before_handling_commands(set_test_env, monkeypatch):
    calls = Mock()
    monkeypatch.setattr("password_manager.cli.harden_process", calls.harden_process)
    monkeypatch.setattr("getpass.getpass", calls.getpass)
    monkeypatch.setattr("password_manager.cli.register_user", calls.register_user)

    cli.main(["register", "--username", "testuser"])

    assert calls.mock_calls[:2] == [call.harden_process(), call.getpass("Choose a master password: ")]


# PM_STORAGE only takes effect if every vault command hands get_storage() to its core function
@pytest.mark.unit
@pytest.mark.parametrize("args, command_function", [
    (['prog', 'generate', 'mylabel'], 'save_password'),
    (['prog', 'set', 'mylabel', '--password', 'mypassword'], 'save_password'),
    (['prog', 'get', 'mylabel'], 'get_password'),
    (['prog', 'remove', 'mylabel', '--tag', 'work'], 'remove_tags'),
    (['prog', 'delete', 'mylabel'], 'delete_label'),
    (['prog', 'list'], 'list_labels'),
    (['prog', 'verify'], 'verify_vault'),
])
def test_run_command_passes_get_storage_to_the_core_functions(args, command_function):
    storage = Mock()
    with patch('password_manager.cli.load_session', return_value=('testuser', b'fernet')), \
         patch('password_manager.cli.get_storage', return_value=storage), \
         patch(f'password_manager.cli.{command_function}') as mock_command:
        run_cli_with_args(args)
    assert mock_command.call_args.kwargs["storage"] is storage
