import hashlib
import hmac

import pyperclip

# Clears the password pm get copied, after the clipboard timeout. Runs in its own short-lived process, which knows only
# a SHA-256 digest of the copied password: never the password, the data key, the vault or the session agent.
# The clipboard's contents are only hashed and compared in constant time, never kept, printed or logged; anything the
# user copied since is left alone.
def clear_if_unchanged(digest):
    if hmac.compare_digest(hashlib.sha256(pyperclip.paste().encode()).hexdigest(), digest):
        pyperclip.copy("")
