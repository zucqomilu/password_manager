import argparse
import getpass
import argcomplete
from .logger import logger
from .memory import harden_process
from .user import register_user, authenticate_user
from .core import save_password, get_password, list_labels, generate_password, remove_tags, verify_vault, delete_label, is_versioned_backup
from .session import SessionLocked, load_session, save_session, clear_session
from .storage import get_storage, load_vault

# Tab-completion for label arguments: label names are plain text in vault.json,
# so this never decrypts and never touches the keyring session or users.json.
# A damaged vault (None) offers nothing; that is safe because completion never saves.
def complete_labels(**kwargs):
    return list(dict.fromkeys(label for entries in (load_vault() or {}).values() for label in entries if not is_versioned_backup(label)))

# Tab-completion for --tag: tags are plain text in vault.json, so this never decrypts either.
# A damaged vault (None) offers nothing; that is safe because completion never saves.
def complete_tags(**kwargs):
    return list(dict.fromkeys(tag for entries in (load_vault() or {}).values() for entry in entries.values() for tag in entry.get("tags", [])))

# Tab-completion for remove's --tag: only the tags of the label already typed on the command line
def complete_label_tags(parsed_args, **kwargs):
    return list(dict.fromkeys(tag for entries in (load_vault() or {}).values() for tag in entries.get(parsed_args.label, {}).get("tags", [])))

# Tab-completion for arguments that must not suggest anything (new labels, passwords, logins, usernames), instead of file names
def no_completions(**kwargs):
    return []

def build_parser():
    parser = argparse.ArgumentParser(description="Password Manager CLI")
    subparsers = parser.add_subparsers(dest='command')

    # === REGISTER ===
    register_parser = subparsers.add_parser('register', help='Register a new user')
    register_parser.add_argument('--username', help='Username for registration').completer = no_completions
    register_parser.add_argument('--password', help='Master password (optional for scripting)').completer = no_completions

    # === LOGIN ===
    login_parser = subparsers.add_parser('login', help='Login as an existing user')
    login_parser.add_argument('--username', help='Username for login').completer = no_completions
    login_parser.add_argument('--password', help='Master password (optional for scripting)').completer = no_completions

    # === LOGOUT ===
    subparsers.add_parser('logout', help='Log out and clear session')

    # === GENERATE ===
    gen_parser = subparsers.add_parser('generate', help='Generate and store a password')
    gen_parser.add_argument('label', help='Label for the password').completer = no_completions
    gen_parser.add_argument('--length', type=int, default=16, help='Password length')
    gen_parser.add_argument('--login', help='Optional login/email/username to associate with password').completer = no_completions

    # === SET ===
    set_parser = subparsers.add_parser('set', help='Set password/login for a label')
    set_parser.add_argument('label', help='Label to set credentials for').completer = complete_labels
    set_parser.add_argument('--password', help='Password to set (optional)').completer = no_completions
    set_parser.add_argument('--login', help='Login (email/username) to set (optional)').completer = no_completions
    set_parser.add_argument('--tag', action='append', dest='tags', help='Tag to add to the label').completer = complete_tags

    # === GET ===
    get_parser = subparsers.add_parser('get', help='Get a password by label')
    get_parser.add_argument('label').completer = complete_labels
    get_parser.add_argument('--show', action='store_true', help='Show password in terminal')

    # === REMOVE ===
    remove_parser = subparsers.add_parser('remove',help='Remove tags from a password label')
    remove_parser.add_argument('label', help='Label to remove tags from').completer = complete_labels
    remove_parser.add_argument('--tag', nargs='+', dest='tags', required=True, help='Tags to remove from the label').completer = complete_label_tags

    # === DELETE ===
    delete_parser = subparsers.add_parser('delete', help='Delete a password label (its versions are kept)')
    delete_parser.add_argument('label', help='Label to delete').completer = complete_labels

    # === LIST ===
    list_parser = subparsers.add_parser('list', help='List all saved password labels')
    list_parser.add_argument('--tag', nargs='+', dest='tags', help='Only list labels with these tags').completer = complete_tags

    # === VERIFY ===
    subparsers.add_parser('verify', help='Check that every entry in the vault decrypts')

    # === COMPLETION ===
    subparsers.add_parser('completion', help='Print the bash completion script')

    return parser

def run_command(parser, args, username, fernet):
    if args.command == 'generate':
        pwd = generate_password(args.length)
        if save_password(username, args.label, fernet, password=pwd, login=args.login, storage=get_storage()):
            logger.info(f"Generated new password for '{args.label}' with length {args.length}.")
            print(f"Generated password: {pwd}")
    elif args.command == "set":
        if not args.password and not args.login and not args.tags:
            logger.error(f"You must run with eather args --password or --login or --tags.")
            print("Error: You must specify at least --password or --login or --tags.")
            return
        save_password(username, args.label, fernet, password=args.password, login=args.login, tags=args.tags, storage=get_storage())
    elif args.command == 'get':
        get_password(username, args.label, fernet, show=args.show, storage=get_storage())
    elif args.command == 'remove':
        remove_tags(username, args.label, tags=args.tags, storage=get_storage())
    elif args.command == 'delete':
        delete_label(username, args.label, storage=get_storage())
    elif args.command == 'list':
        list_labels(username, fernet, tags=args.tags, storage=get_storage())
    elif args.command == 'verify':
        result = verify_vault(username, fernet, storage=get_storage())
        if result is None:
            print("Failed to load password vault. The vault may be corrupted or unreadable.")
            return
        print(f"{result['ok']} entries OK")
        for label in result["bad_password"]:
            print(f"Password failed to decrypt: {label}")
        for label in result["bad_login"]:
            print(f"Login failed to decrypt: {label}")
    else:
        parser.print_help()

def main(argv=None):
    # First, before any prompt or key: the master password typed at login or register, the data key it unwraps and
    # every decrypted password then live in a process that writes no core file and other processes cannot read
    harden_process()
    parser = build_parser()
    argcomplete.autocomplete(parser, always_complete_options=False)
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

    # === PRINT COMPLETION SCRIPT ===
    # use_defaults=False drops bash's "-o default", which would fall back to file names
    # wherever pm deliberately offers nothing (passwords, logins, new labels)
    if args.command == "completion":
        print(argcomplete.shellcode(["pm"], use_defaults=False))
        return

    # === LOAD SESSION ===
    session = load_session()
    if not session:
        print("You are not logged in. Please run `login` first.")
        return

    username, fernet = session

    # A key lost mid-command (expired, or a logout elsewhere) ends it with a login prompt, never a traceback.
    # The core functions never save a half-done change, so nothing is left partly written.
    try:
        run_command(parser, args, username, fernet)
    except SessionLocked:
        logger.warning("Session expired during a command.")
        print("Your session has expired. Please run `login` and try again.")
