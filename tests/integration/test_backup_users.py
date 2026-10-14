import json
import os
import re
import stat

import pytest

from password_manager.storage import backup_users, save_users


@pytest.mark.integration
def test_backup_users_copies_users_json_to_a_timestamped_0600_file(set_test_env, valid_user):
    save_users(valid_user)

    backup = backup_users()

    assert os.path.dirname(backup) == set_test_env
    assert re.fullmatch(r"users_backup_\d{8}_\d{6}_\d{6}\.json", os.path.basename(backup))
    with open(backup) as f:
        assert json.load(f) == valid_user
    assert stat.S_IMODE(os.stat(backup).st_mode) == 0o600
