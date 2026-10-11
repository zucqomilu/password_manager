import io
import os
from contextlib import contextmanager
from unittest.mock import patch

import argcomplete
import pytest

from password_manager.cli import build_parser, main


# Set the environment a shell sets when Tab is pressed on `line`.
# argcomplete's debug output normally goes to fd 9, which the shell provides; under pytest that fd
# isn't argcomplete's to take, so make opening it fail and argcomplete falls back to stderr.
@contextmanager
def completion_env(line):
    with patch.dict(os.environ, {"_ARGCOMPLETE": "1", "_ARGCOMPLETE_IFS": "\n", "COMP_LINE": line, "COMP_POINT": str(len(line))}), \
         patch("argcomplete.finders.os.fdopen", side_effect=OSError):
        yield


# Run argcomplete in-process on the parser and return the completions it offers
def complete(line):
    output = io.StringIO()
    with completion_env(line):
        argcomplete.autocomplete(build_parser(), exit_method=lambda code: None, output_stream=output)
    return output.getvalue().split("\n")


@pytest.mark.unit
def test_completing_pm_lists_all_subcommands():
    assert [word for word in complete("pm ") if not word.startswith("-")] == [
        "register", "login", "logout", "generate", "set", "get", "remove", "delete", "list", "verify",
    ]


@pytest.mark.unit
def test_completing_pm_set_dashes_lists_the_set_commands_flags():
    assert complete("pm set --") == ["--help", "--password", "--login", "--tag"]


def exit_completion(code):
    raise SystemExit(code)


@pytest.mark.unit
@pytest.mark.parametrize("line", ["pm ", "pm get ", "pm set github --", "pm delete "])
def test_completion_never_loads_vault_users_or_session(line):
    real_autocomplete = argcomplete.autocomplete
    with completion_env(line), \
         patch("password_manager.cli.argcomplete.autocomplete",
               lambda parser: real_autocomplete(parser, exit_method=exit_completion, output_stream=io.StringIO())), \
         patch("password_manager.core.load_vault") as mock_load_vault, \
         patch("password_manager.user.load_users") as mock_load_users, \
         patch("password_manager.session.keyring.get_password") as mock_get_session, \
         pytest.raises(SystemExit) as completion_exit:
        main([])
    assert completion_exit.value.code == 0
    mock_load_vault.assert_not_called()
    mock_load_users.assert_not_called()
    mock_get_session.assert_not_called()
