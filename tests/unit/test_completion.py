import io
import os
from contextlib import contextmanager
from unittest.mock import patch

import argcomplete
import pytest

from password_manager.cli import main


# Set the environment a shell sets when Tab is pressed on `line`.
# argcomplete's debug output normally goes to fd 9, which the shell provides; under pytest that fd
# isn't argcomplete's to take, so make opening it fail and argcomplete falls back to stderr.
@contextmanager
def completion_env(line):
    with patch.dict(os.environ, {"_ARGCOMPLETE": "1", "_ARGCOMPLETE_IFS": "\n", "COMP_LINE": line, "COMP_POINT": str(len(line))}), \
         patch("argcomplete.finders.os.fdopen", side_effect=OSError):
        yield


def exit_completion(code):
    raise SystemExit(code)


# Press Tab on `line` through the real main(), keeping the arguments main() passes to argcomplete,
# and return the completions it offers
def complete(line):
    output = io.StringIO()
    real_autocomplete = argcomplete.autocomplete
    with completion_env(line), \
         patch("password_manager.cli.argcomplete.autocomplete",
               lambda parser, **kwargs: real_autocomplete(parser, **kwargs, exit_method=exit_completion, output_stream=output)), \
         pytest.raises(SystemExit) as completion_exit:
        main([])
    assert completion_exit.value.code == 0
    return output.getvalue().splitlines()


@pytest.mark.unit
def test_completing_pm_lists_all_subcommands():
    assert [word for word in complete("pm ") if not word.startswith("-")] == [
        "register", "login", "logout", "generate", "set", "get", "remove", "delete", "list", "verify", "db", "completion",
    ]


@pytest.mark.unit
def test_completing_pm_set_dashes_lists_the_set_commands_flags():
    assert complete("pm set --") == ["--help", "--password", "--login", "--tag"]


@pytest.mark.unit
@pytest.mark.parametrize("line", ["pm ", "pm get ", "pm set github --", "pm delete "])
def test_completion_never_loads_users_file_or_session(line):
    with patch("password_manager.user.load_users") as mock_load_users, \
         patch("password_manager.session.keyring.get_password") as mock_get_session, \
         patch("password_manager.agent.send_request") as mock_send_request:
        complete(line)
    mock_load_users.assert_not_called()
    mock_get_session.assert_not_called()
    mock_send_request.assert_not_called()


@pytest.mark.unit
@pytest.mark.parametrize("command", ["get", "set", "remove", "delete"])
def test_label_arguments_complete_labels_from_vault_without_decrypting(command, valid_vault):
    with patch("password_manager.cli.load_vault", return_value=valid_vault), \
         patch("cryptography.fernet.Fernet.decrypt") as mock_decrypt:
        # A single match gets a trailing space, so the shell moves on to the next word
        assert complete(f"pm {command} g") == ["github "]
        mock_decrypt.assert_not_called()


@pytest.mark.unit
def test_label_completion_hides_versions(valid_vault):
    with patch("password_manager.cli.load_vault", return_value=valid_vault):
        assert complete("pm get t") == ["twitter "]


@pytest.mark.unit
def test_label_completion_offers_nothing_when_vault_cannot_be_loaded():
    with patch("password_manager.cli.load_vault", return_value=None):
        assert [word for word in complete("pm get ") if not word.startswith("-")] == []


@pytest.mark.unit
def test_completion_offers_options_only_after_a_dash_is_typed():
    assert complete("pm ") == ["register", "login", "logout", "generate", "set", "get", "remove", "delete", "list", "verify", "db", "completion"]
    assert complete("pm -") == ["-h", "--help"]


@pytest.mark.unit
def test_generate_label_argument_offers_no_completions(valid_vault):
    with patch("password_manager.cli.load_vault", return_value=valid_vault):
        assert complete("pm generate ") == []


@pytest.mark.unit
@pytest.mark.parametrize("line", ["pm generate -", "pm generate github -"])
def test_generate_still_completes_its_options_after_a_dash(line):
    assert complete(line) == ["-h", "--help", "--length", "--login"]


@pytest.mark.unit
@pytest.mark.parametrize("line", ["pm register --password ", "pm login --password ", "pm set github --password "])
def test_password_offers_no_completions(line, valid_vault):
    with patch("password_manager.cli.load_vault", return_value=valid_vault):
        assert complete(line) == []


@pytest.mark.unit
@pytest.mark.parametrize("line", ["pm generate github --login ", "pm set github --login "])
def test_login_offers_no_completions(line, valid_vault):
    with patch("password_manager.cli.load_vault", return_value=valid_vault):
        assert complete(line) == []


@pytest.mark.unit
@pytest.mark.parametrize("line", ["pm register --username ", "pm login --username "])
def test_username_offers_no_completions(line):
    with patch("password_manager.user.load_users") as mock_load_users:
        assert complete(line) == []
        mock_load_users.assert_not_called()


@pytest.mark.unit
@pytest.mark.parametrize("line", ["pm set github --tag ", "pm list --tag "])
def test_tag_completes_tags_from_vault(line, valid_vault):
    valid_vault["alice"]["github"]["tags"] = ["work", "dev"]
    valid_vault["alice"]["twitter"]["tags"] = ["social", "work"]
    with patch("password_manager.cli.load_vault", return_value=valid_vault), \
         patch("cryptography.fernet.Fernet.decrypt") as mock_decrypt:
        assert complete(line) == ["work", "dev", "social"]
        mock_decrypt.assert_not_called()


@pytest.mark.unit
def test_tag_completion_offers_nothing_when_vault_cannot_be_loaded():
    with patch("password_manager.cli.load_vault", return_value=None):
        assert complete("pm list --tag ") == []


@pytest.mark.unit
def test_remove_tag_completes_only_that_labels_tags(valid_vault):
    valid_vault["alice"]["github"]["tags"] = ["work", "dev"]
    valid_vault["alice"]["twitter"]["tags"] = ["social", "work"]
    with patch("password_manager.cli.load_vault", return_value=valid_vault):
        assert complete("pm remove github --tag ") == ["work", "dev"]
