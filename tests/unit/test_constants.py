import pytest

from password_manager.constants import get_data_dir


@pytest.mark.unit
def test_get_data_dir_defaults_to_xdg_data_home(monkeypatch):
    monkeypatch.setenv("XDG_DATA_HOME", "/xdg/data")
    assert get_data_dir() == "/xdg/data/password_manager"
