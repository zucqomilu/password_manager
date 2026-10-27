# Postgres storage, filled in by the row tests that follow. Until then every call fails loudly,
# so PM_STORAGE=postgres can never silently drop a write or show an empty vault.
def load_vault():
    raise NotImplementedError("Postgres storage is not available yet")

def save_vault(data):
    raise NotImplementedError("Postgres storage is not available yet")

def backup_vault():
    raise NotImplementedError("Postgres storage is not available yet")
