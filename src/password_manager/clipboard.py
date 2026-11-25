import hashlib
import hmac

import pyperclip

from .logger import logger

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
