import logging
from .constants import get_log_file

logging.basicConfig(
    filename=get_log_file(),
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s",
    datefmt="%Y-%m-%d %H:%M:%S"
)

logger = logging.getLogger("password_manager")
