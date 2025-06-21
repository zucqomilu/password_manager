# tests/test_logger.py
import logging
from src import logger

def test_logger_name():
    assert logger.logger.name == "password_manager"

def test_logging_writes_to_file(tmp_path):
    # Temporarily override LOG_FILE path for this test
    test_log_file = tmp_path / "test_vault.log"

    # Reconfigure logging to use the test log file
    logging.basicConfig(
        filename=str(test_log_file),
        level=logging.INFO,
        format="%(asctime)s [%(levelname)s] %(message)s",
        datefmt="%Y-%m-%d %H:%M:%S",
        force=True  # Python 3.8+ allows forcing reconfig
    )

    test_logger = logging.getLogger("password_manager")
    test_logger.info("Test log entry")

    # Check file was created
    assert test_log_file.exists()

    # Check content has the test message
    content = test_log_file.read_text()
    assert "Test log entry" in content
