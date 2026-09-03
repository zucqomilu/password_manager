import sys
from unittest.mock import patch
from src import cli


def run_cli_with_args(args):
    with patch.object(sys, 'argv', args):
        cli.main()


def test_register_user():
    with patch('src.cli.register_user') as mock_register_user, \
         patch('builtins.input', return_value='testuser'), \
         patch('getpass.getpass', return_value='testpass'):
        mock_register_user.return_value = True
        run_cli_with_args(['prog', 'register'])
        mock_register_user.assert_called_once_with('testuser', 'testpass')


def test_login_success():
    with patch('src.cli.authenticate_user') as mock_authenticate_user, \
         patch('src.cli.save_session') as mock_save_session, \
         patch('builtins.input', return_value='testuser'), \
         patch('getpass.getpass', return_value='testpass'):
        mock_authenticate_user.return_value = b'somefernetkey'
        run_cli_with_args(['prog', 'login'])
        mock_authenticate_user.assert_called_once_with('testuser', 'testpass')
        mock_save_session.assert_called_once()


def test_login_failure(capsys):
    with patch.object(sys, "argv", ["prog", "login"]), \
         patch("builtins.input", return_value="testuser"), \
         patch("getpass.getpass", return_value="wrongpassword"), \
         patch('src.cli.authenticate_user', side_effect=ValueError("Login failed: Incorrect password.")):
        cli.main()
        captured = capsys.readouterr()
        assert "Login failed: Incorrect password." in captured.out
    

def test_logout():
    with patch('src.cli.clear_session') as mock_clear_session:
        run_cli_with_args(['prog', 'logout'])
        mock_clear_session.assert_called_once()


def test_generate_command():
    with patch('src.cli.load_session') as mock_load_session, \
         patch('src.cli.generate_password') as mock_generate_password, \
         patch('src.cli.save_password') as mock_save_password:
        mock_load_session.return_value = ('testuser', b'fernet')
        mock_generate_password.return_value = 'password123!'
        mock_save_password.return_value = True
        run_cli_with_args(['prog', 'generate', 'mylabel', '--length', '20'])
        mock_generate_password.assert_called_once_with(20)
        mock_save_password.assert_called_once_with('testuser', 'mylabel', b'fernet', password='password123!', login=None)


def test_set_command_success():
    with patch('src.cli.load_session') as mock_load_session, \
         patch('src.cli.save_password') as mock_save_password:
        mock_load_session.return_value = ('testuser', b'fernet')
        run_cli_with_args(['prog', 'set', 'mylabel', '--password', 'mypassword', '--login', 'testuser@example.com'])
        mock_save_password.assert_called_once_with('testuser', 'mylabel', b'fernet', password='mypassword', login='testuser@example.com', tags=None)


def test_set_command_failure(capsys):
    with patch('src.cli.load_session') as mock_load_session, \
         patch('src.cli.save_password') as mock_save_password:
        mock_load_session.return_value = ('testuser', b'fernet')
        run_cli_with_args(['prog', 'set', 'mylabel'])
        mock_save_password.assert_not_called()
        captured = capsys.readouterr()
        assert "Error: You must specify at least --password or --login or --tags." in captured.out


def test_get_command():
    with patch('src.cli.load_session') as mock_load_session, \
         patch('src.cli.get_password') as mock_get_password:
        mock_load_session.return_value = ('testuser', b'fernet')
        run_cli_with_args(['prog', 'get', 'mylabel', '--show'])
        mock_get_password.assert_called_once_with('testuser', 'mylabel', b'fernet', show=True)


def test_list_command():
    with patch('src.cli.load_session') as mock_load_session, \
         patch('src.cli.list_labels') as mock_list_labels:
        mock_load_session.return_value = ('testuser', b'fernet')
        run_cli_with_args(['prog', 'list'])
        mock_list_labels.assert_called_once_with('testuser', b'fernet', tags=None)


def test_no_session_for_protected_commands(capfd):
    with patch('src.cli.load_session', return_value=None):
        run_cli_with_args(['prog', 'list'])
        output = capfd.readouterr()
        assert "not logged in" in output.out.lower()


def test_set_command_with_tag():
    with patch('src.cli.load_session') as mock_load_session, \
         patch('src.cli.save_password') as mock_save_password:
        mock_load_session.return_value = ('testuser', b'fernet')

        run_cli_with_args(['prog', 'set', 'mylabel', '--tag', 'droppshipping'])

        mock_save_password.assert_called_once_with(
            'testuser',
            'mylabel',
            b'fernet',
            password=None,
            login=None,
            tags=['droppshipping']
        )


def test_list_command_with_tag():
    with patch('src.cli.load_session') as mock_load_session, \
         patch('src.cli.list_labels') as mock_list_labels:
        mock_load_session.return_value = ('testuser', b'fernet')

        run_cli_with_args(['prog', 'list', '--tag', 'droppshipping'])

        mock_list_labels.assert_called_once_with(
            'testuser',
            b'fernet',
            tags=['droppshipping']
        )


def test_list_command_with_multiple_tags():
    with patch('src.cli.load_session') as mock_load_session, \
         patch('src.cli.list_labels') as mock_list_labels:
        mock_load_session.return_value = ('testuser', b'fernet')

        run_cli_with_args(['prog', 'list', '--tag', 'droppshipping', 'economy'])

        mock_list_labels.assert_called_once_with(
            'testuser',
            b'fernet',
            tags=['droppshipping', 'economy']
        )
