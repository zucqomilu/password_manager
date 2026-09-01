import argparse
import getpass
from .logger import logger
from .user import register_user, authenticate_user
from .core import save_password, get_password, list_labels, generate_password
from .session import load_session, save_session, clear_session, refresh_session

def main(argv=None):
    parser = argparse.ArgumentParser(description="Password Manager CLI")
    subparsers = parser.add_subparsers(dest='command')

    # === REGISTER ===
    register_parser = subparsers.add_parser('register', help='Register a new user')
    register_parser.add_argument('--username', help='Username for registration')
    register_parser.add_argument('--password', help='Master password (optional for scripting)')

    # === LOGIN ===
    login_parser = subparsers.add_parser('login', help='Login as an existing user')
    login_parser.add_argument('--username', help='Username for login')
    login_parser.add_argument('--password', help='Master password (optional for scripting)')

    # === LOGOUT ===
    subparsers.add_parser('logout', help='Log out and clear session')

    # === GENERATE ===
    gen_parser = subparsers.add_parser('generate', help='Generate and store a password')
    gen_parser.add_argument('label', help='Label for the password')
    gen_parser.add_argument('--length', type=int, default=16, help='Password length')
    gen_parser.add_argument('--login', help='Optional login/email/username to associate with password')

    # === SET ===
    set_parser = subparsers.add_parser('set', help='Set password/login for a label')
    set_parser.add_argument('label', help='Label to set credentials for')
    set_parser.add_argument('--password', help='Password to set (optional)')
    set_parser.add_argument('--login', help='Login (email/username) to set (optional)')
    set_parser.add_argument('--tag', action='append', dest='tags', help='Tag to add to the label')

    # === GET ===
    get_parser = subparsers.add_parser('get', help='Get a password by label')
    get_parser.add_argument('label')
    get_parser.add_argument('--show', action='store_true', help='Show password in terminal')

    # === LIST ===
    list_parser = subparsers.add_parser('list', help='List all saved password labels')
    list_parser.add_argument('--tag', help='Only list labels with this tag')

    args = parser.parse_args(argv)

    # === REGISTER USER ===
    if args.command == 'register':
        username = args.username or input("Choose a username: ").strip()
        password = args.password or getpass.getpass("Choose a master password: ")
        if register_user(username, password):
            print("Registration successful.")
        return

    # === LOGIN USER ===
    if args.command == 'login' or args.command is None:
        username = args.username or input("Username: ").strip()
        password = args.password or getpass.getpass("Master password: ")
        try:
            fernet_key = authenticate_user(username, password)
            save_session(username, fernet_key)
            print(f"Login successful. Welcome, {username}!")
        except ValueError as e:
            print(f"Login failed: {e}")
            return

    # === LOGOUT USER ===
    if args.command == "logout":
        clear_session()
        return

    # === LOAD SESSION ===
    session = load_session()
    if not session:
        print("You are not logged in. Please run `login` first.")
        return

    username, fernet = session

    refresh_session()

    # === HANDLE USER COMMANDS ===
    if args.command == 'generate':
        pwd = generate_password(args.length)
        if save_password(username, args.label, fernet, password=pwd, login=args.login):
            logger.info(f"Generated new password for '{args.label}' with length {args.length}.")
            print(f"Generated password: {pwd}")
    elif args.command == "set":
        if not args.password and not args.login and not args.tags:
            logger.error(f"You must run with eather args --password or --login or --tags.")
            print("Error: You must specify at least --password or --login or --tags.")
            return
        save_password(username, args.label, fernet, password=args.password, login=args.login, tags=args.tags)
    elif args.command == 'get':
        get_password(username, args.label, fernet, show=args.show)
    elif args.command == 'list':
        list_labels(username, fernet, tag=args.tag)
    else:
        parser.print_help()
