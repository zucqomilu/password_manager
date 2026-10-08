import pytest

from password_manager.constants import get_data_dir


@pytest.mark.unit
def test_get_data_dir_defaults_to_xdg_data_home(monkeypatch):
    monkeypatch.setenv("XDG_DATA_HOME", "/xdg/data")
    assert get_data_dir() == "/xdg/data/password_manager"


@pytest.mark.unit
def test_get_data_dir_falls_back_to_local_share_without_xdg_data_home(monkeypatch):
    monkeypatch.delenv("XDG_DATA_HOME", raising=False)
    monkeypatch.setenv("HOME", "/home/alice")
    assert get_data_dir() == "/home/alice/.local/share/password_manager"


@pytest.mark.unit
def test_get_data_dir_treats_empty_xdg_data_home_as_unset(monkeypatch):
    monkeypatch.setenv("XDG_DATA_HOME", "")
    monkeypatch.setenv("HOME", "/home/alice")
    assert get_data_dir() == "/home/alice/.local/share/password_manager"
