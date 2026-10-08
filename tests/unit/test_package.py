import importlib
from importlib.metadata import entry_points

import pytest


@pytest.mark.unit
def test_cli_main_is_importable_from_password_manager_package():
    assert callable(importlib.import_module("password_manager.cli").main)


@pytest.mark.unit
def test_pm_console_script_resolves_to_cli_main():
    assert [ep.value for ep in entry_points(group="console_scripts", name="pm")] == [
        "password_manager.cli:main"
    ]
