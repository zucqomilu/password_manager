# password_manager

A command-line password manager written in Python for securely storing passwords and login information in an encrypted vault.

The project is currently intended for **learning and personal use**, with the long-term goal of developing it into a production-ready password manager.

## Features

* User registration and authentication
* Master password-based encryption, with the vault key wrapped under an **Argon2id**-derived key
* Existing accounts are upgraded automatically on the next login, with a `users.json` backup made first
* Encrypted password and login storage
* Secure password generation using Python's `secrets` module
* Password retrieval and clipboard integration
* Password/login management by label
* Tag-based password organization, filtering, and removal
* `pm delete` removes a label after confirmation, with a vault backup made first
* Multiple users supported
* Automatic vault backups when overwriting passwords
* Atomic saves: a crash or full disk never leaves a half-written vault or users file
* `pm verify` checks that every stored password and login still decrypts
* Shell tab-completion for commands, options, labels and tags (via `argcomplete`), without decrypting anything
* Sessions held by a per-user agent process: the data key stays in memory, never on disk or in the keyring
* Best-effort memory hardening: no core dumps, no memory reads by other processes, the agent's key kept out of swap and zeroed when the session ends
* 15-minute session expiration, extended each time a password is encrypted or decrypted
* JSON-based storage, with an optional PostgreSQL backend for the vault (`PM_STORAGE=postgres`)
* `pm db import` and `pm db export` move the vault between the JSON files and PostgreSQL, verified and all-or-nothing
* Storage validation to detect malformed or corrupted data
* Comprehensive automated test suite
* 100% test coverage of the `password_manager` package

## Security Overview

Every user has a random **data key**: the [Fernet](https://cryptography.io/en/latest/fernet/) key that encrypts the vault entries. The data key is never stored in plain form. Instead it is **wrapped** (encrypted) under a key derived from the master password with **Argon2id**, and only the wrapped form is written to `users.json`.

Conceptually:

```text
Master password + salt --Argon2id--> key-encryption key
                                           |
                     AES-256-GCM unwrap    v
users.json "wrapped_key" ------------> data key (Fernet) ---> decrypts vault entries
```

Because the data key is separate from the master password, the vault never has to be re-encrypted when the key derivation changes.

### Key derivation (v2 accounts)

* Algorithm: Argon2id (RFC 9106 low-memory profile)
* Time cost: 3
* Memory cost: 64 MiB
* Parallelism: 4
* Salt: 16 random bytes per user
* Derived key length: 32 bytes

The parameters are stored with each user, so they can be raised later without breaking existing accounts.

### Key wrapping

* The data key is encrypted with AES-256-GCM under the Argon2id key, with a fresh random 12-byte nonce.
* Stored as Base64 of `nonce + ciphertext + tag` (72 bytes).

## Authentication

When a user registers, the application generates a random data key and a random salt, derives the Argon2id key from the master password, and stores the Argon2id parameters and the wrapped data key in `users.json`.

The master password is **never stored**, and v2 accounts store **no password hash** either.

During login, the application derives the Argon2id key again and unwraps the data key. AES-GCM authenticates the unwrap, so a wrong master password fails with `Incorrect password.` and never yields a key. On success, the data key is stored in the session.

### Accounts created before Argon2id (v1)

Older accounts use PBKDF2-HMAC-SHA256 (100,000 iterations): an authentication key derived from the master password and an authentication salt is stored as a verifier, and the Fernet key is derived from `master password + ":fernet"` and an encryption salt.

The first successful login of a v1 account upgrades it to v2:

1. The master password is checked against the v1 verifier.
2. A backup of `users.json` is written (`users_backup_YYYYMMDD_HHMMSS_ffffff.json`) and its path is printed.
3. The existing Fernet key is wrapped under a new Argon2id key and the record is replaced.

The vault itself is not touched: the same Fernet key keeps decrypting every entry. If the backup or the save fails (for example on a full disk), login still succeeds on v1 and the upgrade is retried at the next login. A wrong password never changes `users.json`.

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

A session is held by a small background process, the **session agent**, in the style of `ssh-agent`. The data key lives only in the agent's memory: it is never written to disk or to the keyring, and `pm` commands never see it after login. They send each value to the agent to be encrypted or decrypted.

The agent listens on a Unix socket at `$XDG_RUNTIME_DIR/password_manager/agent.sock` (or in the data directory when `XDG_RUNTIME_DIR` is not set; `PM_AGENT_SOCKET` overrides both). The directory is `0700`, the socket `0600`, and the agent only answers processes running as the same user.

A Unix socket path can be at most 107 bytes long. If yours is longer (a long `PM_AGENT_SOCKET`, or a long data directory path without `XDG_RUNTIME_DIR`), `login` and `logout` stop and say so; set a shorter `PM_AGENT_SOCKET`.

The session uses a **15-minute time-to-live (TTL)**.

### Session lifecycle

1. `pm login` unwraps the data key (or derives it for a not-yet-upgraded v1 account), starts the agent if none is running, and hands it the key.
2. Commands ask the agent whether a session is active, then use it to encrypt and decrypt.
3. Each successful encryption or decryption extends the session. Commands that do not use the key (`delete`, `remove`) do not.
4. After 15 minutes without use, the agent zeroes the key and exits.
5. `pm logout` tells the agent to zero the key and exit.

If the session ends while a command is running, the command stops without saving anything and asks you to log in again.

Older versions kept the key in the operating system's keyring between commands. The first login with this version removes that entry.

### Memory hardening

On Linux, the agent and every `pm` command harden their own process before handling anything secret:

* **No core dumps.** The core-file limit is set to 0, so a crash never writes the process's memory to disk.
* **Not dumpable.** Other processes running as your user (but not root) cannot attach a debugger (`ptrace`) or read the process's memory through `/proc`. This covers every copy of the key in the process, not only the agent's own.
* **Kept out of swap.** The agent locks its copy of the key into RAM with `mlock`. If the system refuses (for example, over the locked-memory limit), the session still works and a warning goes to `vault.log`.
* **Zeroed when the session ends.** The agent overwrites its copy of the key on logout, when the session expires, when a new login replaces it, and when it exits.

This is best effort. Python and the `cryptography` library keep short-lived copies of the key of their own (for example, while decoding a request or encrypting a value) that cannot be zeroed from Python. The hardening narrows how long and where the key can be found; it does not remove every copy.

## Storage

By default the application uses JSON files for persistent application data. The vault can also be kept in PostgreSQL; see [PostgreSQL storage](#postgresql-storage).

All files are stored in the data directory, which is created with `0700` permissions (only your user can open it):

1. `$PM_DATA_DIR`, if set.
2. Otherwise `$XDG_DATA_HOME/password_manager`, if `XDG_DATA_HOME` is set to an absolute path.
3. Otherwise `~/.local/share/password_manager`.

Earlier versions stored these files in the repository root.

`vault.json` and `users.json` are saved atomically: the new content is written to a temporary file in the same directory, flushed to disk, then renamed over the old file. Both files end up with `0600` permissions (readable only by your user).

### `users.json`

Stores registered users and the cryptographic information required to authenticate them.

Example:

```json
{
    "jonathan": {
        "version": 2,
        "kdf": {
            "salt": "...",
            "time_cost": 3,
            "memory_cost": 65536,
            "parallelism": 4
        },
        "wrapped_key": "..."
    }
}
```

Records without `"version"` are v1 records (`auth_salt`, `enc_salt`, `password`). They are still read, and are upgraded to v2 on the next successful login.

The master password itself is not stored.

### `users_backup_*.json`

Before a v1 account is upgraded, `users.json` is copied next to itself (with `0600` permissions):

```text
users_backup_YYYYMMDD_HHMMSS_ffffff.json
```

Older versions of `pm` cannot read v2 records. To roll back to an older version, copy this backup over `users.json`; the vault does not need to be restored. The backup contains the v1 password verifier, so delete it once you have confirmed that the upgraded account works (for example with `pm verify`).

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

Removing or adding tags does **not** create a versioned password entry or vault backup.

### `vault.log`

Application logging is written to `vault.log` in the data directory.

The log contains operational information useful for debugging and auditing application behavior. Sensitive credential values should not be stored in the log.

### PostgreSQL storage

With `PM_STORAGE=postgres` (exactly that value), the vault is read from and saved to a PostgreSQL database instead of `vault.json`. Without it, or with any other value, `pm` uses the JSON files.

* **Only the vault moves.** Users stay in `users.json`: registering and logging in work exactly as before. The database's `users` table is only filled by `pm db import`.
* **The same encrypted values.** The database holds the same Fernet tokens as `vault.json`, and tags in plain text as before. Nothing is decrypted to store it.
* **Tables:** `entries` (one row per label), `tags` (one row per tag, in order), `password_history` (one row per `__vN` version), `users` and `schema_migrations`. The schema is created on the first connection.
* **Whole-vault saves.** Every save rewrites the vault in one transaction, as `vault.json` is rewritten whole, so a failure leaves the previous rows. The same validation as for `vault.json` runs first.
* **Backups stay JSON.** An overwrite or `pm delete` still writes `vault_backup_YYYYMMDD_HHMMSS_ffffff.json` (`0600`) into the data directory, holding the stored vault.
* **Connection:** `postgresql:///password_manager` by default: the local socket, with no host and no password, so peer authentication admits your own user. `PM_DATABASE_URL` overrides it. The URL may hold a password, so it is never printed or logged.
* **Unreachable database.** If the server cannot be reached, the command stops before reading or changing anything and explains how to fall back to the JSON files.

`vault.json` is never written while `PM_STORAGE=postgres` is set. It keeps the vault as of `pm db import`, so changes made under PostgreSQL since then are only in the database until you run `pm db export`.

## Requirements

* Linux (the session agent and the memory hardening use Linux-only system calls; on any other platform `pm` stops with "pm only supports Linux.")
* Python 3.12 or newer (developed on 3.14)
* `cryptography`
* `pyperclip`
* `keyring`
* `argcomplete`

Dependencies are declared in `pyproject.toml`. Current versions:

```text
cryptography==46.0.3
pyperclip==1.11.0
keyring==25.7.0
argcomplete==3.7.2
```

Optional, for the PostgreSQL backend (the `postgres` extra): a PostgreSQL server and `psycopg[binary]==3.3.6`. `pm` imports `psycopg` only when it connects to the database, so a JSON-only install does not need it.

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

Install the package with its development dependencies:

```bash
pip install -e ".[dev]"
```

This installs the `pm` command into the virtual environment.

### PostgreSQL (optional)

Install the `postgres` extra (the `dev` extra already includes `psycopg`):

```bash
pip install -e ".[postgres]"
```

On Arch Linux, installing the `postgresql` package does not create or start a server. Set one up once, give your user a role and create the database `pm` uses by default:

```bash
sudo -u postgres initdb -D /var/lib/postgres/data
sudo systemctl enable --now postgresql
sudo -u postgres createuser --createdb $USER
createdb password_manager
```

Then move your vault over with `pm db import`; see [Move the vault to PostgreSQL and back](#move-the-vault-to-postgresql-and-back).

### Shell completion

`pm` supports tab-completion in bash through `argcomplete`. `pm` prints its own completion script, so set it up once with:

```bash
mkdir -p ~/.local/share/bash-completion/completions
pm completion > ~/.local/share/bash-completion/completions/pm
```

Open a new shell afterwards. Re-run the command after upgrading `pm` if completion behaves differently.

Use `pm completion` rather than `register-python-argcomplete pm`: the generic script registers `pm` with bash's `-o default`, which makes bash fall back to **file names** wherever `pm` deliberately offers nothing, such as after `--password`.

What completes:

* Subcommands after `pm `, and options only once a `-` is typed.
* Labels for `get`, `set`, `remove` and `delete`, without `__vN` versions.
* Tags for `--tag`; for `remove`, only the tags of the label already typed.
* Nothing for `generate`'s new label, `--password`, `--login` or `--username`, so a file name can never slip into a password.

Labels and tags are read from `vault.json`, where they are stored in plain text. Completion never decrypts anything and never contacts the session agent or reads `users.json`, so it also works (and shows labels) when you are logged out. A damaged vault simply offers no suggestions.

With `PM_STORAGE=postgres`, completion still reads `vault.json`, so it suggests labels and tags as of `pm db import`, not ones added in the database since.

## Usage

The application is started with the `pm` command. `python main.py` still works and runs the same CLI.

The available commands are:

```text
register
login
logout
generate
set
get
remove
delete
list
verify
db
completion
```

### Register a user

Register interactively:

```bash
pm register
```

The application will ask for a username and master password.

A username and master password can also be supplied directly:

```bash
pm register --username alice
```

The `--password` option is available for scripting:

```bash
pm register --username alice --password "example-password"
```

> **Security note:** Supplying passwords directly on the command line can expose them through shell history, process inspection, or other operating-system mechanisms. Interactive password entry is recommended.

### Login

Login interactively:

```bash
pm login
```

Or specify the username:

```bash
pm login --username alice
```

After successful authentication, the session agent is started and holds the key for 15 minutes.

### Logout

Clear the current session:

```bash
pm logout
```

### Generate a password

Generate and store a password:

```bash
pm generate github
```

The default password length is 16 characters.

A different length can be specified:

```bash
pm generate github --length 24
```

A login/email/username can also be associated with the generated password:

```bash
pm generate github --length 24 --login alice@example.com
```

### Set credentials

Set a password:

```bash
pm set github --password "example-password"
```

Set a login:

```bash
pm set github --login alice@example.com
```

Both can be set at the same time:

```bash
pm set github \
    --login alice@example.com \
    --password "example-password"
```

If a password already exists for the label, the application asks for confirmation before overwriting it.

The previous encrypted password is retained as a versioned entry and the vault is backed up.

Changing only the login does not create a versioned password entry or vault backup.

### Tags

Password entries can be assigned tags to make it easier to organize and filter related accounts. Tags are currently stored as plaintext metadata in the vault.

#### Add tags

Add a tag to an existing label with:

```bash
pm set ebay.com --tag dropshipping
```

Multiple tags can be added to the same label by repeating the `--tag` option:

```bash
pm set ebay.com \
    --tag dropshipping \
    --tag ecommerce
```

Tags can be added without changing the existing password or login information. Adding a tag does **not** create a versioned backup of the password entry.

Tags are additive, so adding a new tag does not replace existing tags. Duplicate tags are not added.

#### Filter by tags

To list only labels containing a specific tag:

```bash
pm list --tag dropshipping
```

For example:

```text
Stored labels:
- ebay.com (with login)
```

Multiple tags can be supplied to `list`:

```bash
pm list --tag dropshipping ecommerce
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
pm list --tag dropshipping ecommerce
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

#### Remove tags

A tag can be removed from an existing password label with:

```bash
pm remove github --tag development
```

Multiple tags can be removed in a single operation:

```bash
pm remove github --tag development work
```

Removing tags does not modify the password or login associated with the label.

Removing tags also does **not** create a versioned password entry or vault backup.

If the final tag is removed from a label, the `tags` field is removed from the vault entry entirely.

For example, an entry containing:

```json
{
    "password": "encrypted-value",
    "login": "encrypted-value",
    "tags": [
        "development"
    ]
}
```

becomes:

```json
{
    "password": "encrypted-value",
    "login": "encrypted-value"
}
```

If a requested tag does not exist, it is ignored. The vault is only saved when an actual change is made.

Labels that do not contain a `tags` field are supported for backwards compatibility.

### Get a password

Retrieve a password:

```bash
pm get github
```

The password is copied to the system clipboard.

If the entry contains a login, it is displayed as well.

To explicitly display the password in the terminal:

```bash
pm get github --show
```

Displaying passwords in the terminal should be avoided when unnecessary.

### Delete a label

Delete a stored label:

```bash
pm delete github
```

You are asked to confirm first:

```text
Delete 'github'? A backup is made first. (y/N):
```

Only `y` deletes; anything else prints `Operation cancelled.` and leaves the vault untouched. Before deleting, a `vault_backup_YYYYMMDD_HHMMSS.json` copy of the vault is written next to it.

The label's previous versions (`github__v1`, `github__v2`, ...) are **kept**. They are hidden from `pm list` but can still be read with `pm get github__v1`, or deleted individually with `pm delete github__v1`. Labels that merely start with the same text, such as `github-work`, are never affected.

### List stored labels

List all stored password labels:

```bash
pm list
```

To filter labels by a single tag:

```bash
pm list --tag dropshipping
```

To filter labels by multiple tags:

```bash
pm list --tag dropshipping ecommerce
```

When multiple tags are supplied, only labels containing **all** requested tags are displayed.

Example:

```text
Stored labels:
- github (with login)
- router.asus (with login)
- email
```

### Verify the vault

Check that every entry, including versioned backups, still decrypts with your master password:

```bash
pm verify
```

Example:

```text
3 entries OK
Password failed to decrypt: gitlab
Login failed to decrypt: github
```

Only labels are printed, never passwords or logins. The vault is not modified.

### Move the vault to PostgreSQL and back

Both commands need a logged-in session.

#### Import

```bash
pm db import
```

Copies `users.json` and `vault.json` into an empty database, then checks the result:

```text
Imported into Postgres: 1 users, 42 entries, 7 kept versions
Verified alice's entries: 49 of 49 decrypt identically from Postgres
```

* **Verification.** Every password and login of the logged-in user, versions included, is decrypted from both `vault.json` and the database and compared. Only the logged-in user's entries can be decrypted; other users' entries are copied token for token. A label that differs is named, followed by the advice to keep using the JSON files.
* **Read-only on the JSON side.** The JSON files are only read, never changed, so the JSON backend keeps working whatever happens.
* **All or nothing.** The import is one transaction: a failure leaves the database empty, ready for another try.
* **Refusals** (nothing is written):
  * a database that already holds a user, entry or version: an import never merges;
  * a v1 user record: run `pm login` once to upgrade it;
  * a `__vN` version with tags, since versions have no tags in the database: remove them with `pm remove` as the message says;
  * an unreadable `users.json` or `vault.json`.

Once it reports every entry identical, set `PM_STORAGE=postgres` (for example in your shell profile) to use the database.

#### Export

```bash
mkdir ~/pm-export
pm db export ~/pm-export
```

Writes the database's vault and the users as `users.json` holds them as `users.json` and `vault.json` (`0600`) into the directory. Nothing is decrypted: the tokens and wrapped keys are copied as they are.

An export never overwrites: it refuses a directory that already has `users.json` or `vault.json`, such as the live data directory. It also refuses an unreadable `users.json`.

To go back to the JSON backend, unset `PM_STORAGE` and either copy the two exported files into the data directory (after moving the old ones aside) or point `USERS_FILE` and `VAULT_FILE` at them.

## Environment Variables

The locations of the vault and user database can be overridden through environment variables.

### `PM_DATA_DIR`

Overrides the whole data directory. Useful for running against a copy of your data:

```bash
PM_DATA_DIR=/tmp/pm-copy pm list
```

### `VAULT_FILE`

Overrides the default `vault.json` location.

Example:

```bash
VAULT_FILE=/tmp/test-vault.json pm list
```

### `USERS_FILE`

Overrides the default `users.json` location.

Example:

```bash
USERS_FILE=/tmp/test-users.json pm register
```

These environment variables are particularly useful for testing.

### `PM_STORAGE`

`postgres` keeps the vault in PostgreSQL; unset (or any other value) uses `vault.json`:

```bash
PM_STORAGE=postgres pm list
```

### `PM_DATABASE_URL`

Overrides the database `pm` connects to (default `postgresql:///password_manager`). For example, a database on a socket in another directory:

```bash
PM_DATABASE_URL="postgresql:///pm_copy?host=/tmp/pm-pg" PM_STORAGE=postgres pm list
```

The URL is never printed or logged, but a password in it can be read from the environment by processes running as your user (and root); prefer peer authentication over the local socket.

## Project Structure

```text
password_manager/
├── main.py
├── pyproject.toml
├── src/
│   └── password_manager/
│       ├── __init__.py
│       ├── agent.py
│       ├── cli.py
│       ├── constants.py
│       ├── core.py
│       ├── crypto.py
│       ├── logger.py
│       ├── memory.py
│       ├── postgres_storage.py
│       ├── session.py
│       ├── storage.py
│       ├── user.py
│       └── validate_storage.py
└── tests/
    ├── conftest.py
    ├── unit/
    ├── integration/
    └── e2e/
```

### Source modules

| Module                | Responsibility                                     |
| --------------------- | -------------------------------------------------- |
| `cli.py`              | Command-line interface and command dispatch        |
| `agent.py`            | Session agent: holds the key, encrypts, decrypts   |
| `constants.py`        | File and socket paths, keyring IDs, session TTL    |
| `core.py`             | Password generation and vault operations           |
| `crypto.py`           | Salt generation and cryptographic key derivation   |
| `logger.py`           | Application logging                                |
| `memory.py`           | Process hardening, locking and zeroing the key     |
| `postgres_storage.py` | PostgreSQL vault, schema, import, verify, export   |
| `session.py`          | Login, logout and the agent-backed cipher          |
| `storage.py`          | JSON files, and choosing the storage backend       |
| `user.py`             | User registration and authentication               |
| `validate_storage.py` | Validation of users and vault data                 |
| `main.py`             | Alternative entry point (`pm` is the main one)     |

## Testing

The project uses [pytest](https://pytest.org/) for automated testing.

Tests are split by type, and every test is tagged with a matching marker:

* `tests/unit/` (`@pytest.mark.unit`): fast and isolated, with no real I/O.
* `tests/integration/` (`@pytest.mark.integration`): real dependencies such as files or subprocesses, for one feature.
* `tests/e2e/` (`@pytest.mark.e2e`): full CLI flows across several features.

```bash
pytest -m unit                    # unit tests only
pytest -m "unit or integration"   # unit and integration tests
pytest                            # complete suite
```

No test can touch the real operating-system keyring or the real session agent: the test setup replaces the keyring with an inactive backend and points the agent socket into a throwaway directory.

The PostgreSQL tests need `initdb` and `pg_ctl` on the `PATH` (the `postgresql` package), but no running server: the test run starts its own throwaway cluster in a temporary directory, with only a local socket and no TCP port, gives each test an empty database, and removes it all at the end. A `PM_STORAGE` set in your shell is ignored during tests, and `PM_DATABASE_URL` points at a directory with no server in it, so no test can reach your real database.

The current test suite contains **454 tests**.

Coverage can be generated with:

```bash
pytest --cov --cov-report=term-missing
```

The current implementation achieves:

```text
990 statements
990 statements covered
100% coverage
```

All modules in the `password_manager` package currently have 100% test coverage.

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
pm login --username alice --password "example-password"
```

This can expose sensitive information through shell history or process inspection.

Interactive password entry should be preferred.

### Clipboard

The `get` command copies decrypted passwords to the system clipboard.

Clipboard contents may be accessible to other applications depending on the operating system and desktop environment.

### Local files

The security of the vault also depends on protecting the local filesystem.

Users should protect:

* The PostgreSQL database, when `PM_STORAGE=postgres` is used: it holds the same encrypted values as `vault.json`, and after `pm db import` the wrapped keys from `users.json`
* The data directory (`~/.local/share/password_manager` by default), which holds:
  * `vault.json`
  * `users.json`
  * Vault backups
  * `users.json` backups
* The user's operating-system account

### Session key

The Fernet encryption key is held only in the session agent's memory while a session is active. Any process running as your user can ask the agent to decrypt values during that time, the same trust model as `ssh-agent`. Such a process cannot read the agent's memory directly, though: see [Memory hardening](#memory-hardening), including its limits.

Sessions expire after 15 minutes without use.

## Current Limitations

The project is actively being developed. Current limitations include:

* No password recovery mechanism
* No built-in master-password change workflow (key wrapping makes one possible without re-encrypting the vault)
* No synchronization between devices
* No secure remote backup mechanism
* No graphical user interface
* With the PostgreSQL backend, users stay in `users.json`, and tab-completion reads labels and tags from `vault.json`
* Tags are stored as plaintext metadata and are not encrypted
* Clipboard contents are not automatically cleared by the application
* Command-line password arguments are available for scripting
* The cryptographic parameters and security architecture may require further review before production use

## Development Status

The project is currently under active development.

Recent development has focused on moving the session key out of the operating-system keyring into a per-user session agent and hardening the memory that holds it, along with tag-based organization, filtering, and removal for password entries.

Future development will focus on improving the security model, usability, storage architecture, and production readiness of the application.

## License

This project is licensed under the MIT License.

See [`LICENSE`](LICENSE) for the complete license text.

## Disclaimer

This software is provided for learning and personal use. It is not currently intended to replace established, professionally audited password-management software.

Use it at your own risk and do not rely on it to protect critical credentials until the project's security architecture has undergone appropriate review and hardening.
