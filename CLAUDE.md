# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Commands

```bash
source .venv/bin/activate
pip install -e ".[dev]"                  # editable install from pyproject.toml

python main.py <command> [args]          # register | login | logout | generate | set | get | remove | list

pytest                                   # full suite
pytest tests/test_core.py                # one file
pytest tests/test_core.py::test_name     # one test
pytest --cov --cov-report=term-missing  # coverage (README claims 100% of src/)
```

There is no linter or build step configured.

## Layout deviations from the global conventions

This project predates the global `~/.claude/CLAUDE.md` conventions and differs from them. Ask before restructuring any of these:

- Tests are flat in `tests/` (`test_<module>.py`, plus `test_integration.py` and `test_e2e.py`) rather than `tests/unit|integration|e2e/`.
- The `unit`/`integration`/`e2e` markers are registered, but only `tests/test_session.py` uses them, so `pytest -m unit` runs only a small subset.

## Architecture

`main.py` → `src/password_manager/cli.py:main(argv)`: one argparse dispatcher. Its control flow matters:
- `register` returns early. `login` (also used when no command is given) authenticates and saves a session, then **falls through** to the session-loading code.
- `logout` clears the session and returns.
- Every other command calls `load_session()`, then `refresh_session()`, then dispatches to a function in `core.py`.

Module layers (dependencies point downward):
- `cli.py`: arg parsing and I/O prompts.
- `user.py` (register/authenticate) and `core.py` (vault operations: `save_password`, `get_password`, `list_labels`, `remove_tags`, `generate_password`).
- `session.py`: keyring-backed session.
- `storage.py`: JSON load/save/backup. Every load and save goes through `validate_storage.py`.
- `crypto.py`: PBKDF2 `derive_key` and `generate_salt`.
- `constants.py`: paths, keyring IDs, TTL.

Key behaviors that span files:
- **Two keys from one master password.** `derive_key(pw, auth_salt)` is stored in `users.json` as `"password"` and compared on login. `derive_key(pw + ":fernet", enc_salt)` is the Fernet key, which is never written to disk. It lives only in the OS keyring session (service `password_manager`, account `session`) along with the username and `last_activity`. The 15-minute TTL is checked in `load_session`.
- **Vault shape:** `{username: {label: {"password": enc, "login": enc?, "tags": [plaintext]}}}`. The password and login are Fernet-encrypted per field. Tags are plaintext.
- **Password overwrite versioning:** overwriting an existing password in `save_password` prompts for confirmation, moves the old password to `<label>__v<N>`, and calls `backup_vault()`, which writes `vault_backup_YYYYMMDD_HHMMSS.json` next to the vault. `is_versioned_backup()` recognizes these labels. Changes to the login or tags alone don't create a version or a backup.
- **Error convention:** storage functions return `None` on corrupt or invalid data and `{}` when the file is missing. Callers check for `None`. Most functions print user-facing messages and log through `logger` instead of raising. `authenticate_user` is the exception: it raises `ValueError`.

## Testing notes

- `storage.py` reads paths through `password_manager.constants.get_vault()` / `get_users()` at call time. These functions honor the `VAULT_FILE` / `USERS_FILE` environment variables, which makes the paths patchable. Keep that indirection; don't import the values directly.
- The `set_test_env` fixture in `tests/conftest.py` points both files at a temp dir and replaces `password_manager.session.keyring.*` with an in-memory dict. Any test that touches storage or sessions must use it. The repo root holds real `vault.json` / `users.json` files (gitignored), and the real keyring would otherwise be used.
- `test_clock` freezes `password_manager.session.time.time` for testing TTL expiry. `mock_session_keyring` reads and writes the raw session entry.
- `vault.log` always goes to the repo root because `get_log()` has no override. `src/password_manager/logger.py` is excluded from coverage in `pyproject.toml`.
- E2E tests drive `password_manager.cli.main([...])` with `--username`/`--password` flags and assert on `capsys` output.

## Scope of convention changes

When a feature or fix touches a function or file, bring that specific code toward the global conventions as part of the change. Don't refactor nearby code the task doesn't touch. Don't widen the scope to clean up things that weren't asked about.

## Security-sensitive code

This is a password manager. Take extra care with any code that touches encryption, key derivation, credential storage, authentication or the keyring session (mainly `crypto.py`, `user.py`, `session.py`, `storage.py` and the encrypt/decrypt paths in `core.py`).

- Never reduce security to satisfy a style convention.
- Flag every change to this code clearly, and explain the security reasoning before it's approved, even for small edits.
- Never log, print or include secrets, passwords, keys or the master password in any output, test fixture or commit.
