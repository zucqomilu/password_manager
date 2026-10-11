import io
import os
from unittest.mock import patch

import argcomplete
import pytest

from password_manager.cli import build_parser


# Run argcomplete in-process, the way a shell triggers it, and return the completions it offers.
# Its debug output normally goes to fd 9, which the shell provides; under pytest that fd isn't
# argcomplete's to take, so make opening it fail and argcomplete falls back to stderr.
def complete(line):
    output = io.StringIO()
    with patch.dict(os.environ, {"_ARGCOMPLETE": "1", "_ARGCOMPLETE_IFS": "\n", "COMP_LINE": line, "COMP_POINT": str(len(line))}), \
         patch("argcomplete.finders.os.fdopen", side_effect=OSError):
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
