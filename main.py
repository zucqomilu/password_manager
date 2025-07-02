#Would you like this to be extended with a menu-based UI, SQLite storage.
#TOTP integration Time-Based One Time Password
#Let me know if you'd like adding encryption for usernames or labels. Once you're ready, we can proceed to things like optional logout, session tokens, or improved CLI prompts.
#Delete password functionality.
#Password export/import (per-user).
#Later, we can add commands like logout, whoami, or implement session timeouts
#Let me know if you'd like to also make the session more robust by including automatic logout, session expiration, or per-user session files.
#you should encrypt the session file, or store the session key only in memory (e.g., via an agent), or use OS-level secure storage (e.g., keyrings, credential manager)
#Let me know if you want to also automatically back up corrupted files before refusing to proceed
# Password Strength Enforcement (if applicable)
#Would you like to add a utility or CLI command to regenerate a valid users.json file if it's missing or broken?
#Consider encryption versioning or format tagging (optional):

#e2e unit tests
#Storing password + login
#Retrieving both correctly
#Validation fails on malformed login

from src.cli import main

if __name__ == '__main__':
    main()
