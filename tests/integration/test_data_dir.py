import os
import stat

import pytest

from password_manager.constants import ensure_data_dir


@pytest.mark.integration
def test_ensure_data_dir_creates_data_dir_with_0700_permissions(monkeypatch, tmp_path):
    monkeypatch.setenv("PM_DATA_DIR", str(tmp_path / "pm"))
    ensure_data_dir()
    assert stat.S_IMODE(os.stat(tmp_path / "pm").st_mode) == 0o700
