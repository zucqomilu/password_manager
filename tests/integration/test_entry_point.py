import os
import re
import subprocess
import sys
from pathlib import Path

import pytest

SUBCOMMANDS = ["register", "login", "logout", "generate", "set", "get", "remove", "list"]


@pytest.mark.integration
def test_installed_pm_help_lists_every_subcommand():
    assert re.search(
        r"\{(.+?)\}",
        subprocess.run(
            [Path(sys.executable).with_name("pm"), "--help"],
            capture_output=True, text=True, check=True,
        ).stdout,
    ).group(1).split(",") == SUBCOMMANDS


@pytest.mark.integration
def test_installed_pm_help_works_when_data_dir_does_not_exist(tmp_path):
    result = subprocess.run(
        [Path(sys.executable).with_name("pm"), "--help"],
        capture_output=True, text=True,
        env={**os.environ, "PM_DATA_DIR": str(tmp_path / "missing")},
    )
    assert (result.returncode, result.stderr) == (0, "")
