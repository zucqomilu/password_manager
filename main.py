#Would you like this to be extended with a menu-based UI, SQLite storage.
#TOTP integration Time-Based One Time Password
#Mask the copied value when displaying it
#Let me know if you'd like adding encryption for usernames or labels. Once you're ready, we can proceed to things like optional logout, session tokens, or improved CLI prompts.
#Delete password functionality.
#Password export/import (per-user).
#Later, we can add commands like logout, whoami, or implement session timeouts
#Implement session persistence across commands (e.g. by storing a session token or encrypted key on disk temporarily)
#Let me know if you'd like to also make the session more robust by including automatic logout, session expiration, or per-user session files.
#you should encrypt the session file, or store the session key only in memory (e.g., via an agent), or use OS-level secure storage (e.g., keyrings, credential manager)
#Modify main.py and/or cli.py to support file path overrides via environment variables for isolation?
from src.cli import main

if __name__ == '__main__':
    main()
