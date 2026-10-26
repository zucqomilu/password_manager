import importlib
import importlib.util
from importlib.metadata import entry_points

import pytest

import password_manager


@pytest.mark.unit
def test_cli_main_is_importable_from_password_manager_package():
    assert callable(importlib.import_module("password_manager.cli").main)


@pytest.mark.unit
def test_pm_console_script_resolves_to_cli_main():
    assert [ep.value for ep in entry_points(group="console_scripts", name="pm")] == [
        "password_manager.cli:main"
    ]


# Runs the package's __init__.py as a fresh module under another name, so the real, already imported package is never
# touched or left half-reloaded
def import_fresh_package():
    spec = importlib.util.spec_from_file_location("password_manager_fresh", password_manager.__file__)
    spec.loader.exec_module(importlib.util.module_from_spec(spec))


# Faked platforms: on a real one pm would otherwise fail later, with an ImportError (Windows has no resource module)
# or an AttributeError (macOS has no prctl), instead of saying why
@pytest.mark.unit
@pytest.mark.parametrize("platform", ["darwin", "win32"])
def test_importing_password_manager_stops_with_pm_only_supports_linux_on_other_platforms(monkeypatch, platform):
    monkeypatch.setattr("sys.platform", platform)

    with pytest.raises(SystemExit, match=r"^pm only supports Linux\.$"):
        import_fresh_package()
