# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Commands

```bash
source .venv/bin/activate
pip install -e ".[dev]"                  # editable install from pyproject.toml

python main.py <command> [args]          # register | login | logout | generate | set | get | remove | delete | list | verify | completion

pytest -m unit                           # day-to-day loop
pytest -m "unit or integration"          # before merging a feature branch
pytest                                   # full suite incl. e2e, before merging to main
pytest tests/unit/test_core.py           # one file
pytest tests/unit/test_core.py::test_name  # one test
pytest --cov --cov-report=term-missing  # coverage (README claims 100% of src/)
```

There is no linter or build step configured.

## Architecture

`main.py` → `src/password_manager/cli.py:main(argv)`: one argparse dispatcher. Its control flow matters:
- `register` returns early. `login` (also used when no command is given) authenticates and saves a session, then **falls through** to the session-loading code.
- `logout` clears the session and returns. `completion` prints the bash script from `argcomplete.shellcode(["pm"], use_defaults=False)` and returns; `use_defaults=False` drops bash's `-o default` file-name fallback.
- Every other command calls `load_session()`, then `run_command()`, which dispatches to a function in `core.py`. `main()` turns a `SessionLocked` raised mid-command into a login prompt.

Module layers (dependencies point downward):
- `cli.py`: arg parsing (`build_parser()`) and I/O prompts. `main()` first calls `harden_process()`, before any prompt, then `argcomplete.autocomplete()` right after `build_parser()`, before any login, session or vault code; during Tab-completion it prints suggestions and exits there. Label and tag completers read plain-text names from `load_vault()` only (never decrypt, never contact the session agent or read `users.json`); `no_completions` stops file-name suggestions for new labels, passwords, logins and usernames.
- `user.py` (`register_user`, `authenticate_user`, `upgrade_user_record`, `make_v2_record`) and `core.py` (vault operations: `save_password`, `get_password`, `list_labels`, `remove_tags`, `generate_password`, `verify_vault`, `delete_label`).
- `session.py`: the client side of the session agent. `save_session` (login) starts or reuses the agent and sends it the key (UNLOCK); `load_session` asks STATUS and returns the username plus an `AgentCipher`, a frozen dataclass whose `encrypt`/`decrypt` call the agent, so `core.py` uses it like a `Fernet`; `clear_session` (logout) sends LOCK. A lost key raises `SessionLocked`, a rejected token `InvalidToken`.
- `agent.py`: the session agent, a detached daemon that holds the data key in memory. Pure core `handle_request(state, request, now)`; one JSON line per connection over a Unix socket (`get_socket_path()`: `PM_AGENT_SOCKET`, else `$XDG_RUNTIME_DIR/password_manager/agent.sock`, else the data dir), dir 0700, socket 0600, peer uid checked with `SO_PEERCRED`. `start_agent` binds the socket in the parent and passes the fd to the child, whose `run_daemon` calls `harden_process()` before `run_agent`. The key is held as a `bytearray`, `mlock`ed on UNLOCK and zeroed (`wipe_key`) on LOCK, on expiry, when an UNLOCK replaces it (only after the request's fields are read, so a malformed UNLOCK keeps the old key) and in `run_agent`'s `finally`.
- `memory.py`: best-effort, Linux-only hardening. `wipe` zeroes a `bytearray` in place (a deliberate mutation); `lock_buffer` `mlock`s one and only logs a warning when refused; `harden_process` sets `RLIMIT_CORE` to (0, 0) and `PR_SET_DUMPABLE` to 0. Copies of the key held by Python or `cryptography` are out of its reach.
- `storage.py`: JSON load/save/backup (`backup_vault`, `backup_users`). Every load and save goes through `validate_storage.py`. Saves go through `write_json_atomically()` (temp file in the same dir, fsync, `os.replace`; the temp file is removed on failure), which also leaves the files `0600`.
- `crypto.py`: Argon2id `derive_master_key`, AES-256-GCM `wrap_data_key` / `unwrap_data_key` (a wrong password raises `ValueError`), plus the v1 PBKDF2 `derive_key` and `generate_salt`.
- `constants.py`: data dir, file and socket paths, keyring IDs (only for removing the legacy session entry), TTL, agent message size and connection timeout, `ARGON2_PARAMS` for new v2 records.

Key behaviors that span files:
- **Data dir.** All data files live in `get_data_dir()`: `PM_DATA_DIR` if set, else `$XDG_DATA_HOME/password_manager` (only if absolute), else `~/.local/share/password_manager`. `ensure_data_dir()` creates it and forces `0700`; it runs when `logger.py` is imported, before `vault.log` is opened. `VAULT_FILE` / `USERS_FILE` still override the individual file paths.
- **Two user record formats; one data key.** The data key is the Fernet key that encrypts the vault. It is never written to disk or to the keyring unwrapped; between commands it lives only in the agent's memory. The agent enforces the 15-minute TTL: only a successful ENCRYPT or DECRYPT extends it (STATUS never does), and an idle agent exits when it runs out. Login deletes the legacy keyring entry (service `password_manager`, account `session`) that older versions stored; a keyring that cannot be reached never blocks login or logout.
  - **v2** (`"version": 2`, written by `register_user`): `{"version": 2, "kdf": {salt, time_cost, memory_cost, parallelism}, "wrapped_key"}`. Login unwraps `wrapped_key` (AES-GCM) with the Argon2id key from the stored `kdf`; GCM authentication is the password check, so there is no stored password hash.
  - **v1** (no `version`): `{"auth_salt", "enc_salt", "password"}`. `derive_key(pw, auth_salt)` is the stored verifier; `derive_key(pw + ":fernet", enc_salt)` is the Fernet key. `validate_users` accepts both formats side by side.
  - **Upgrade on login.** A successful v1 login calls `upgrade_user_record()` (which re-checks the v1 password, constant-time, and wraps the *same* Fernet key, so the vault is never re-encrypted), then `backup_users()` (`users_backup_YYYYMMDD_HHMMSS_ffffff.json`), then `save_users()`. No backup, or an `OSError` from either step, skips the upgrade and still returns the v1 key, so a disk problem never blocks login; the upgrade is retried next time. Older `pm` versions cannot read v2 records: rolling back the code means restoring the `users_backup_*` file.
- **Vault shape:** `{username: {label: {"password": enc, "login": enc?, "tags": [plaintext]}}}`. The password and login are Fernet-encrypted per field. Tags are plaintext.
- **Password overwrite versioning:** overwriting an existing password in `save_password` prompts for confirmation, moves the old password to `<label>__v<N>`, and calls `backup_vault()`, which writes `vault_backup_YYYYMMDD_HHMMSS.json` next to the vault. `is_versioned_backup()` recognizes these labels. Changes to the login or tags alone don't create a version or a backup. `delete_label` also prompts and calls `backup_vault()` first, but removes only the exact label: its `__vN` versions are kept.
- **Error convention:** storage functions return `None` on corrupt or invalid data and `{}` when the file is missing. Callers check for `None`. Most functions print user-facing messages and log through `logger` instead of raising. `authenticate_user` is the exception: it raises `ValueError`.

## Testing notes

- `tests/unit/test_layout.py` fails unless every test function has exactly one `@pytest.mark.unit|integration|e2e` decorator matching its directory. Module-level `pytestmark` doesn't count.
- An autouse fixture in `tests/conftest.py` switches `keyring` to its null backend for every test, so no test can touch the real OS keyring.
- Another autouse fixture, `no_process_hardening`, turns `cli.harden_process` into a no-op, so in-process `main()` calls never make the pytest process non-dumpable or drop its core limit. Never call the real `harden_process()` in the pytest process; fake `resource.setrlimit` and `libc.prctl` instead.
- `storage.py` reads paths through `password_manager.constants.get_vault()` / `get_users()` at call time. These functions honor the `VAULT_FILE` / `USERS_FILE` environment variables, which makes the paths patchable. Keep that indirection; don't import the values directly.
- The `set_test_env` fixture in `tests/conftest.py` points both files at a temp dir, replaces `password_manager.session.keyring.*` with an in-memory dict, and pulls in `fake_agent`, which replaces `password_manager.agent.start_agent` / `send_request` with an in-process agent built on the real `handle_request()` (no daemon, no socket; `fake_agent["calls"]` and `["state"]` are inspectable). Any test that touches storage or sessions must use it.
- `test_clock` freezes `time.time` globally, which is the clock the fake agent (or an in-thread `run_agent`) checks the TTL against. `mock_session_keyring` reads and writes the raw legacy keyring entry.
- `pytest_configure` in `tests/conftest.py` points `PM_DATA_DIR` at a throwaway temp dir before any test module imports the package, so no test run can touch the real data dir or a copy exported in the shell. `src/password_manager/logger.py` is excluded from coverage in `pyproject.toml`; `patch = ["subprocess"]` there also measures the agent daemon.
- `pytest_configure` also points `PM_AGENT_SOCKET` into the throwaway data dir, so no test can reach the real agent. `tests/integration/test_session_agent.py` runs a real agent (a daemon, or `run_agent` in a thread when the TTL must be controlled) and always sends LOCK at the end.
- To run `pm` by hand against a copy of real data, point `PM_DATA_DIR` at the copy and `PM_AGENT_SOCKET` at a socket path of its own, so it never talks to the agent holding the real key. Never run feature-branch code against the real data dir.
- `tests/unit/test_completion.py`'s `complete(line)` presses Tab through the real `main()` in-process. It sets the shell's completion env vars and makes argcomplete's `os.fdopen(9)` debug stream fail (fd 9 belongs to pytest). `load_session()` swallows every exception, so assert completion isolation (no `users.json` load, no `agent.send_request`) with `assert_not_called()`, not with mocks that raise. `tests/integration/test_completion.py` also presses Tab in a real interactive bash through a pty, because shell-level behavior such as file-name fallback is invisible to in-process tests.
- E2E tests drive `password_manager.cli.main([...])` with `--username`/`--password` flags and assert on `capsys` output.

## Scope of convention changes

When a feature or fix touches a function or file, bring that specific code toward the global conventions as part of the change. Don't refactor nearby code the task doesn't touch. Don't widen the scope to clean up things that weren't asked about.

## Security-sensitive code

This is a password manager. Take extra care with any code that touches encryption, key derivation, credential storage, authentication or the session agent (mainly `crypto.py`, `user.py`, `session.py`, `agent.py`, `memory.py`, `storage.py` and the encrypt/decrypt paths in `core.py`).

- Never reduce security to satisfy a style convention.
- Flag every change to this code clearly, and explain the security reasoning before it's approved, even for small edits.
- Never log, print or include secrets, passwords, keys or the master password in any output, test fixture or commit.
