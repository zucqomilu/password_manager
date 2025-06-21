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
        mock_save_password.assert_called_once_with('testuser', 'mylabel', 'password123!', b'fernet')

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
        mock_list_labels.assert_called_once_with('testuser', b'fernet')

def test_no_session_for_protected_commands(capfd):
    with patch('src.cli.load_session', return_value=None):
        run_cli_with_args(['prog', 'list'])
        output = capfd.readouterr()
        assert "not logged in" in output.out.lower()
