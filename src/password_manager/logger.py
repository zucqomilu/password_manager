import logging
from .constants import ensure_data_dir, get_log

ensure_data_dir()

logging.basicConfig(
    filename=get_log(),
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s",
    datefmt="%Y-%m-%d %H:%M:%S"
)

logger = logging.getLogger("password_manager")
