import os
import subprocess
import sys
from pathlib import Path

import pytest


@pytest.mark.integration
def test_installed_pm_completes_ge_to_generate_and_get(tmp_path):
    result = subprocess.run(
        [Path(sys.executable).with_name("pm")],
        capture_output=True, text=True,
        env={
            **os.environ,
            "PM_DATA_DIR": str(tmp_path / "pm"),
            "_ARGCOMPLETE": "1",
            "_ARGCOMPLETE_IFS": "\n",
            "_ARGCOMPLETE_STDOUT_FILENAME": str(tmp_path / "completions"),
            "COMP_LINE": "pm ge",
            "COMP_POINT": "5",
        },
    )
    assert (result.returncode, (tmp_path / "completions").read_text().split("\n")) == (0, ["generate", "get"])
