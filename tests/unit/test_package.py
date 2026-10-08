import importlib

import pytest


@pytest.mark.unit
def test_cli_main_is_importable_from_password_manager_package():
    assert callable(importlib.import_module("password_manager.cli").main)
