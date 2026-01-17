import hashlib
import re
from pathlib import Path

HEX_RE = re.compile(r'^[0-9a-fA-F]+$')

BASE64URL_RE = re.compile(r"^[A-Za-z0-9_-]+$")

LOG_LEVELS = ['debug', 'info', 'warning', 'error', 'critical']

LOG_FORMAT = (
    "%(asctime)s "
    "[%(levelname)s] "
    "%(name)s: "
    "%(message)s"
)

DIGEST_MAP = {
    'SHA256': hashlib.sha256,
}

PROJECT_ROOT = Path(__file__).resolve().parent.parent

CONFIG_FILE = PROJECT_ROOT / "config.json"

BASE64_BLOCK_SIZE = 4

MIN_PORT, MAX_PORT = 1, 65535
