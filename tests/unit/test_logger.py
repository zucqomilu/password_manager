# tests/unit/test_logger.py
import pytest
from password_manager import logger

@pytest.mark.unit
def test_logger_name():
    assert logger.logger.name == "password_manager"
