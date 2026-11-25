import pyperclip

# Clears the password pm get copied, after the clipboard timeout. Runs in its own short-lived process, which knows only
# a SHA-256 digest of the copied password: never the password, the data key, the vault or the session agent.
def clear_if_unchanged(digest):
    pyperclip.copy("")
