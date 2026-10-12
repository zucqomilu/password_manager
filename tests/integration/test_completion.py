import os
import pty
import select
import signal
import subprocess
import sys
import time
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


def read_until_quiet(fd, deadline):
    output = b""
    while time.monotonic() < deadline and select.select([fd], [], [], 0.5)[0]:
        try:
            output += os.read(fd, 4096)
        except OSError:
            break
    return output.decode(errors="replace")


# Start an interactive bash in a pseudo-terminal, load `pm completion`, type `line`, press Tab twice,
# and return everything bash printed in response to the two Tabs
def press_tab_twice_in_bash(line, workdir, env):
    script = workdir / "pm-completion.bash"
    script.write_text(subprocess.run([Path(sys.executable).with_name("pm"), "completion"], env=env,
                                     capture_output=True, text=True, check=True).stdout)
    pid, fd = pty.fork()
    if pid == 0:
        os.chdir(workdir)
        os.execvpe("bash", ["bash", "--norc", "--noprofile", "-i"], {**env, "PS1": "$ ", "TERM": "dumb"})
    deadline = time.monotonic() + 10
    read_until_quiet(fd, deadline)
    os.write(fd, f"source {script}\n".encode())
    read_until_quiet(fd, deadline)
    os.write(fd, line.encode() + b"\t\t")
    shown = read_until_quiet(fd, deadline)
    os.kill(pid, signal.SIGKILL)
    os.waitpid(pid, 0)
    os.close(fd)
    return shown


@pytest.mark.integration
def test_tab_after_pm_generate_in_real_bash_offers_no_file_names(tmp_path):
    (tmp_path / "SOMEFILE.txt").touch()
    env = {**os.environ, "PM_DATA_DIR": str(tmp_path / "pm"),
           "PATH": f"{Path(sys.executable).parent}{os.pathsep}{os.environ['PATH']}"}

    assert "SOMEFILE.txt" not in press_tab_twice_in_bash("pm generate ", tmp_path, env)
