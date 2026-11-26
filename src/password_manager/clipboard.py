import hashlib
import hmac
import sys
from subprocess import DEVNULL, PIPE, Popen
from time import sleep

import pyperclip

from .logger import logger
from .memory import harden_process

# Clears the password pm get copied, after the clipboard timeout. Runs in its own short-lived process, which knows only
# a SHA-256 digest of the copied password: never the password, the data key, the vault or the session agent.
# The clipboard's contents are only hashed and compared in constant time, never kept, printed or logged; anything the
# user copied since is left alone. It runs detached, so a clipboard it cannot read or write is logged (a fixed text per
# case, never the exception's) instead of raising.
def clear_if_unchanged(digest):
    try:
        clipboard = pyperclip.paste()
    except pyperclip.PyperclipException:
        logger.warning("Could not read the clipboard to clear the copied password.")
        return
    if hmac.compare_digest(hashlib.sha256(clipboard.encode()).hexdigest(), digest):
        try:
            pyperclip.copy("")
        except pyperclip.PyperclipException:
            logger.warning("Could not clear the copied password from the clipboard.")


# Starts the clearer for a password pm get just copied. The digest goes through a pipe, never argv
# (/proc/<pid>/cmdline is readable by every process); the timeout is not secret. Its own session keeps it alive after
# the terminal closes; no output, since nobody is there to read it. A timeout of 0 means never clear: no clearer.
def start_clearer(password, timeout):
    if not timeout:
        return
    clearer = Popen([sys.executable, "-m", "password_manager.clipboard", str(timeout)], stdin=PIPE, stdout=DEVNULL,
                    stderr=DEVNULL, text=True, start_new_session=True)
    clearer.stdin.write(hashlib.sha256(password.encode()).hexdigest())
    clearer.stdin.close()


# The clearer process's main: hardened first, since the clipboard it reads may hold the password; then the digest from
# the pipe, the wait, and the check. An empty pipe (pm get died before writing) gives a digest nothing matches.
def run_clearer(timeout, stdin):
    harden_process()
    digest = stdin.readline().strip()
    sleep(timeout)
    clear_if_unchanged(digest)
