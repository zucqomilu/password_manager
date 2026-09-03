# password_manager

A command-line password manager written in Python for securely storing passwords and login information in an encrypted vault.

The project is currently intended for **learning and personal use**, with the long-term goal of developing it into a production-ready password manager.

## Features

* User registration and authentication
* Master password-based encryption
* Encrypted password and login storage
* Secure password generation using Python's `secrets` module
* Password retrieval and clipboard integration
* Password/login management by label
* Tag-based password organization and filtering
* Multiple users supported
* Automatic vault backups when overwriting passwords
* Session persistence through the operating system's keyring
* 15-minute session expiration
* Automatic session activity refresh
* JSON-based storage
* Storage validation to detect malformed or corrupted data
* Comprehensive automated test suite
* 100% test coverage of the `src` package

## Security Overview

The password manager uses the user's master password to derive cryptographic keys using **PBKDF2-HMAC-SHA256**.

Two independent salts are generated for each user:

* An authentication salt used to derive the key used for authentication.
* An encryption salt used to derive the Fernet key used to encrypt vault credentials.

The encryption key is derived from the master password and the encryption salt using a separate derivation input:

```text
master password + ":fernet"
```

The resulting key is used with [Fernet](https://cryptography.io/en/latest/fernet/) for symmetric encryption.

### Key derivation

The current implementation uses:

* Algorithm: PBKDF2-HMAC-SHA256
* Derived key length: 32 bytes
* Iterations: 100,000
* Authentication salt: 16 bytes
* Encryption salt: 16 bytes

The derived keys are encoded using URL-safe Base64 where required for storage and Fernet compatibility.

## Authentication

When a user registers, the application generates two cryptographically random salts.

The authentication key is derived from the master password and authentication salt and stored in `users.json`.

The master password itself is **never stored**.

During login, the application derives the authentication key again and compares it with the stored value. If authentication succeeds, the application derives the Fernet encryption key and creates a session.

Conceptually, the process is:

```text
                    Master Password
                           |
              +------------+------------+
              |                         |
              v                         v
       Authentication              Encryption
           salt                       salt
              |                         |
              v                         v
          PBKDF2                    PBKDF2
              |                         |
              v                         v
      Authentication key        Fernet encryption key
```

## Vault Encryption

Passwords and login information stored in the vault are encrypted individually using Fernet.

A vault entry has the following logical structure:

```json
{
    "username": {
        "label": {
            "password": "encrypted-password",
            "login": "encrypted-login",
            "tags": [
                "not-encrypted",
                "not-encrypted"
            ]
        }
    }
}
```

For example:

```json
{
    "steve": {
        "github.com": {
            "password": "encrypted-value",
            "login": "encrypted-value",
            "tags": [
                "personal",
                "important"
            ]
        }
    }
}
```

The actual encrypted values are not human-readable.

## Session Management

The application does not use a disk-based `session.json` file.

Instead, authenticated session information is stored using the operating system's keyring through the [`keyring`](https://pypi.org/project/keyring/) Python package.

A session contains:

* Username
* Fernet encryption key
* Last activity timestamp

The session uses a **15-minute time-to-live (TTL)**.

### Session lifecycle

After successful authentication:

1. The Fernet encryption key is generated.
2. The username, Fernet key, and activity timestamp are stored in the system keyring.
3. Subsequent commands load the session from the keyring.
4. The session timestamp is checked against the 15-minute TTL.
5. Expired sessions are automatically deleted.
6. Successful authenticated operations refresh the activity timestamp.

Logging out explicitly removes the session from the keyring.

This means that normal application operation no longer creates or depends on a `session.json` file.

## Storage

The application currently uses JSON files for persistent application data.

### `users.json`

Stores registered users and the cryptographic information required to authenticate them.

Example:

```json
{
    "jonathan": {
        "auth_salt": "...",
        "enc_salt": "...",
        "password": "..."
    }
}
```

The master password itself is not stored.

### `vault.json`

Stores the encrypted password vault.

Example:

```json
{
    "steve": {
        "github.com": {
            "password": "...",
            "login": "...",
            "tags": [
                "...",
                "..."
            ]
        }
    }
}
```

Passwords and login information are encrypted before being written to the vault.

### `vault_backup_*.json`

When an existing password is overwritten, the previous encrypted password is retained under a versioned label and a backup of the vault is created.

Backups use the following naming format:

```text
vault_backup_YYYYMMDD_HHMMSS.json
```

### `vault.log`

Application logging is written to `vault.log`.

The log contains operational information useful for debugging and auditing application behavior. Sensitive credential values should not be stored in the log.

## Requirements

* Python 3.14 or compatible Python version
* `cryptography`
* `pyperclip`
* `keyring`

Current dependency versions:

```text
cryptography==46.0.3
pyperclip==1.11.0
keyring==25.7.0
```

## Installation

Clone the repository:

```bash
git clone <repository-url>
cd password_manager
```

Create a virtual environment:

```bash
python -m venv .venv
```

Activate the virtual environment:

```bash
source .venv/bin/activate
```

Install the dependencies:

```bash
pip install -r requirements.txt
```

## Usage

The application is started through `main.py`.

The available commands are:

```text
register
login
logout
generate
set
get
list
```

### Register a user

Register interactively:

```bash
python main.py register
```

The application will ask for a username and master password.

A username and master password can also be supplied directly:

```bash
python main.py register --username alice
```

The `--password` option is available for scripting:

```bash
python main.py register --username alice --password "example-password"
```

> **Security note:** Supplying passwords directly on the command line can expose them through shell history, process inspection, or other operating-system mechanisms. Interactive password entry is recommended.

### Login

Login interactively:

```bash
python main.py login
```

Or specify the username:

```bash
python main.py login --username alice
```

After successful authentication, a session is created in the operating system's keyring.

### Logout

Clear the current session:

```bash
python main.py logout
```

### Generate a password

Generate and store a password:

```bash
python main.py generate github
```

The default password length is 16 characters.

A different length can be specified:

```bash
python main.py generate github --length 24
```

A login/email/username can also be associated with the generated password:

```bash
python main.py generate github --length 24 --login alice@example.com
```

### Set credentials

Set a password:

```bash
python main.py set github --password "example-password"
```

Set a login:

```bash
python main.py set github --login alice@example.com
```

Both can be set at the same time:

```bash
python main.py set github \
    --login alice@example.com \
    --password "example-password"
```

If a password already exists for the label, the application asks for confirmation before overwriting it.

The previous encrypted password is retained as a versioned entry and the vault is backed up.

Changing only the login does not create a versioned password entry or vault backup.

### Tags

Password entries can be assigned tags to make it easier to organize and filter related accounts. Tags are currently stored as plaintext metadata in the vault.

Add a tag to an existing label with:

```bash
python main.py set ebay.com --tag dropshipping
```

Multiple tags can be added to the same label by repeating the `--tag` option:

```bash
python main.py set ebay.com \
    --tag dropshipping \
    --tag ecommerce
```

Tags can be added without changing the existing password or login information. Adding a tag does **not** create a versioned backup of the password entry.

Tags are additive, so adding a new tag does not replace existing tags. Duplicate tags are not added.

To list only labels containing a specific tag:

```bash
python main.py list --tag dropshipping
```

For example:

```text
Stored labels:
- ebay.com (with login)
```

Multiple tags can be supplied to `list`:

```bash
python main.py list --tag dropshipping ecommerce
```

When multiple tags are specified, a label must contain **all** of the requested tags to be included in the results.

For example, given:

```text
ebay.com       -> dropshipping, ecommerce
amazon.com     -> dropshipping
github.com     -> development, personal
```

the following command:

```bash
python main.py list --tag dropshipping ecommerce
```

returns only:

```text
Stored labels:
- ebay.com
```

If no labels have the specified tag, the command reports:

```text
Stored labels:
No passwords found with tag 'dropshipping'.
```

When multiple tags produce no matches, the command reports:

```text
Stored labels:
No passwords found with tags: dropshipping, ecommerce.
```

### Get a password

Retrieve a password:

```bash
python main.py get github
```

The password is copied to the system clipboard.

If the entry contains a login, it is displayed as well.

To explicitly display the password in the terminal:

```bash
python main.py get github --show
```

Displaying passwords in the terminal should be avoided when unnecessary.

### List stored labels

List all stored password labels:

```bash
python main.py list
```

To filter labels by a single tag:

```bash
python main.py list --tag dropshipping
```

To filter labels by multiple tags:

```bash
python main.py list --tag dropshipping ecommerce
```

When multiple tags are supplied, only labels containing **all** requested tags are displayed.

Example:

```text
Stored labels:
- github (with login)
- router.asus (with login)
- email
```

## Environment Variables

The locations of the vault and user database can be overridden through environment variables.

### `VAULT_FILE`

Overrides the default `vault.json` location.

Example:

```bash
VAULT_FILE=/tmp/test-vault.json python main.py list
```

### `USERS_FILE`

Overrides the default `users.json` location.

Example:

```bash
USERS_FILE=/tmp/test-users.json python main.py register
```

These environment variables are particularly useful for testing.

## Project Structure

```text
password_manager/
├── main.py
├── requirements.txt
├── pytest.ini
├── src/
│   ├── __init__.py
│   ├── cli.py
│   ├── constants.py
│   ├── core.py
│   ├── crypto.py
│   ├── logger.py
│   ├── session.py
│   ├── storage.py
│   ├── user.py
│   └── validate_storage.py
└── tests/
    ├── conftest.py
    ├── __init__.py
    ├── test_cli.py
    ├── test_core.py
    ├── test_crypto.py
    ├── test_e2e.py
    ├── test_integration.py
    ├── test_logger.py
    ├── test_session.py
    ├── test_storage.py
    ├── test_user.py
    └── test_validate_storage.py
```

### Source modules

| Module                | Responsibility                                     |
| --------------------- | -------------------------------------------------- |
| `cli.py`              | Command-line interface and command dispatch        |
| `constants.py`        | File paths, keyring configuration, and session TTL |
| `core.py`             | Password generation and vault operations           |
| `crypto.py`           | Salt generation and cryptographic key derivation   |
| `logger.py`           | Application logging                                |
| `session.py`          | Keyring-backed session management                  |
| `storage.py`          | Reading, writing, and backing up persistent data   |
| `user.py`             | User registration and authentication               |
| `validate_storage.py` | Validation of users and vault data                 |
| `main.py`             | Application entry point                            |

## Testing

The project uses [pytest](https://pytest.org/) for automated testing.

Run the complete test suite with:

```bash
pytest
```

The current test suite contains **175 tests**.

Coverage can be generated with:

```bash
pytest --cov=src --cov-report=term-missing
```

The current implementation achieves:

```text
412 statements
412 statements covered
100% coverage
```

All modules under `src` currently have 100% test coverage.

## Security Considerations

This project is currently intended for **learning and personal use** and should not yet be considered a production-grade password manager.

Although the application uses established cryptographic primitives, cryptographic security depends on the complete system design, implementation, configuration, operating system, and user environment.

Important considerations include:

### Master passwords

The master password is used to derive cryptographic keys and is not stored directly.

Users should choose a strong, unique master password.

If the master password is lost, there is currently no password-recovery mechanism.

### Command-line passwords

The CLI supports supplying passwords through command-line arguments for scripting:

```bash
python main.py login --username alice --password "example-password"
```

This can expose sensitive information through shell history or process inspection.

Interactive password entry should be preferred.

### Clipboard

The `get` command copies decrypted passwords to the system clipboard.

Clipboard contents may be accessible to other applications depending on the operating system and desktop environment.

### Local files

The security of the vault also depends on protecting the local filesystem.

Users should protect:

* `vault.json`
* `users.json`
* Vault backups
* The user's operating-system account
* The operating-system keyring

### Session key

The Fernet encryption key is stored in the operating system keyring while an authenticated session is active.

Sessions expire after 15 minutes of inactivity.

## Current Limitations

The project is actively being developed. Current limitations include:

* No password recovery mechanism
* No built-in master-password change workflow
* No synchronization between devices
* No secure remote backup mechanism
* No graphical user interface
* JSON is currently used as the persistent storage format
* Tags are stored as plaintext metadata and are not encrypted
* Clipboard contents are not automatically cleared by the application
* Command-line password arguments are available for scripting
* The cryptographic parameters and security architecture may require further review before production use

## Development Status

The project is currently under active development.

Recent development has focused on replacing disk-based session caching with operating-system keyring storage, introducing session expiration, and adding tag-based organization and filtering for password entries.

The previous `session.json` workflow has been removed from normal application operation.

Future development will focus on improving the security model, usability, storage architecture, and production readiness of the application.

## License

This project is licensed under the MIT License.

See [`LICENSE`](LICENSE) for the complete license text.

## Disclaimer

This software is provided for learning and personal use. It is not currently intended to replace established, professionally audited password-management software.

Use it at your own risk and do not rely on it to protect critical credentials until the project's security architecture has undergone appropriate review and hardening.
