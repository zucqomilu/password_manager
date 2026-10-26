import os
import subprocess
import sys
import time
from pathlib import Path

import coverage
import pytest

import password_manager.agent

PROJECT_ROOT = Path(__file__).resolve().parents[2]
AGENT_FILE = password_manager.agent.__file__

# Starts a real daemon and locks it at once; the daemon's pid is printed so the test can wait for it to exit
START_AND_LOCK = """
import sys
from password_manager.agent import send_request, start_agent
print(start_agent(sys.argv[1]))
send_request(sys.argv[1], {"cmd": "LOCK"})
"""


# The daemon writes its coverage data on exit, just after it has removed its socket, so only its exit is a safe point
def wait_for_exit(pid, timeout=5):
    deadline = time.monotonic() + timeout
    while os.path.exists(f"/proc/{pid}") and time.monotonic() < deadline:
        time.sleep(0.01)
    return not os.path.exists(f"/proc/{pid}")


# The line the daemon alone runs: start_agent() itself only ever runs in the parent
def entry_point_line():
    return next(
        number for number, line in enumerate(Path(AGENT_FILE).read_text().splitlines(), 1)
        if "socket.socket(fileno=int(sys.argv[1]))" in line
    )


# A separate coverage run with its own data file, so the pytest-cov run this test is part of never sees its data.
# The COVERAGE_* variables of that outer run are left out of the child's environment, so they cannot redirect it.
# --parallel-mode gives the parent's data a suffix as well, so combine has data to read even when the daemon wrote none.
@pytest.mark.integration
def test_a_coverage_run_measures_the_entry_point_of_the_daemon_start_agent_spawns(tmp_path):
    (tmp_path / "start_and_lock.py").write_text(START_AND_LOCK)
    data_file = str(tmp_path / "data" / ".coverage")
    run = subprocess.run(
        [sys.executable, "-m", "coverage", "run", "--parallel-mode", f"--rcfile={PROJECT_ROOT / 'pyproject.toml'}",
         f"--data-file={data_file}", str(tmp_path / "start_and_lock.py"), str(tmp_path / "run" / "agent.sock")],
        cwd=PROJECT_ROOT, capture_output=True, text=True, timeout=30,
        env={name: value for name, value in os.environ.items() if not name.startswith("COVERAGE_")},
    )
    assert run.returncode == 0, run.stderr
    assert wait_for_exit(int(run.stdout.split()[-1]))

    subprocess.run(
        [sys.executable, "-m", "coverage", "combine", f"--rcfile={PROJECT_ROOT / 'pyproject.toml'}",
         f"--data-file={data_file}", str(tmp_path / "data")],
        cwd=PROJECT_ROOT, capture_output=True, check=True, timeout=30,
        env={name: value for name, value in os.environ.items() if not name.startswith("COVERAGE_")},
    )

    data = coverage.CoverageData(basename=data_file)
    data.read()
    assert entry_point_line() in data.lines(AGENT_FILE)
