import logging
import argparse
import getpass
from core import save_password, get_password, list_labels, generate_password
from user import register_user, authenticate_user
from session import load_session, save_session, clear_session

def main():
    parser = argparse.ArgumentParser(description="Password Manager CLI")
    subparsers = parser.add_subparsers(dest='command')

    # Add command parsers
    subparsers.add_parser('register', help='Register a new user')
    parser_login = subparsers.add_parser('login', help='Login as an existing user')
    parser_logout = subparsers.add_parser('logout', help='Log out and clear session')

    gen_parser = subparsers.add_parser('generate', help='Generate and store a password')
    gen_parser.add_argument('label', help='Label for the password')
    gen_parser.add_argument('--length', type=int, default=16, help='Password length')

    get_parser = subparsers.add_parser('get', help='Get a password by label')
    get_parser.add_argument('label')
    get_parser.add_argument('--show', action='store_true', help='Show password in terminal')

    list_parser = subparsers.add_parser('list', help='List all saved password labels')

    # Parse args first
    args = parser.parse_args()

    # === REGISTER USER ===
    if args.command == 'register':
        username = input("Choose a username: ").strip()
        password = getpass.getpass("Choose a master password: ")
        if register_user(username, password):
            print("Registration successful.")
        return

    # === LOGIN USER ===
    if args.command == 'login' or args.command is None:
        username = input("Username: ").strip()
        password = getpass.getpass("Master password: ")
        try:
            # Authenticate and get Fernet instance (for session storage)
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
    username, fernet = load_session()
    if not username or not fernet:
        print("You are not logged in. Please run `login` first.")
        return

    # === HANDLE USER COMMANDS ===
    if args.command == 'generate':
        pwd = generate_password(args.length)
        if save_password(username, args.label, pwd, fernet):
            logging.info(f"Generated new password for '{args.label}' with length {args.length}.")
            print(f"Generated password: {pwd}")
    elif args.command == 'get':
        get_password(username, args.label, fernet, show=args.show)
    elif args.command == 'list':
        list_labels(username, fernet)
    else:
        parser.print_help()
