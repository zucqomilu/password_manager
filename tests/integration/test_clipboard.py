import os
import subprocess
import time

import pytest

from password_manager.clipboard import start_clearer

# A made-up value, never a real password
COPIED = "not-a-real-password-1"

# Stand-ins for wl-clipboard: the clipboard is a file of the test's own. pyperclip picks wl-copy / wl-paste when
# WAYLAND_DISPLAY is set and both are on PATH, and calls wl-copy --clear to empty it.
WL_COPY = '#!/bin/sh\nif [ "$1" = "--clear" ]; then : > "$PM_TEST_CLIPBOARD"; else cat > "$PM_TEST_CLIPBOARD"; fi\n'
WL_PASTE = '#!/bin/sh\ncat "$PM_TEST_CLIPBOARD"\n'


# The fake clipboard file's content once it changes from what it holds now, or after ten seconds
def wait_for_change(clipboard, before):
    deadline = time.monotonic() + 10
    while clipboard.read_text() == before and time.monotonic() < deadline:
        time.sleep(0.1)
    return clipboard.read_text()


# The whole path pm get starts, for real: start_clearer() spawns a detached `python -m password_manager.clipboard`,
# which reads the digest from the pipe, waits, finds the clipboard unchanged and empties it. The clearer process gets a
# clipboard of its own (fake wl-copy / wl-paste on PATH), so the developer's real clipboard is never touched.
@pytest.mark.integration
def test_real_clearer_process_empties_clipboard_after_timeout(tmp_path, monkeypatch):
    bin_dir = tmp_path / "bin"
    bin_dir.mkdir()
    for name, script in (("wl-copy", WL_COPY), ("wl-paste", WL_PASTE)):
        (bin_dir / name).write_text(script)
        (bin_dir / name).chmod(0o700)
    clipboard = tmp_path / "clipboard"
    clipboard.write_text(COPIED)
    monkeypatch.setenv("PATH", f"{bin_dir}{os.pathsep}{os.environ['PATH']}")
    monkeypatch.setenv("WAYLAND_DISPLAY", "pm-test")
    monkeypatch.delenv("DISPLAY", raising=False)
    monkeypatch.setenv("PM_TEST_CLIPBOARD", str(clipboard))
    monkeypatch.setattr("password_manager.clipboard.Popen", subprocess.Popen)
    start_clearer(COPIED, 1)
    assert wait_for_change(clipboard, COPIED) == ""
