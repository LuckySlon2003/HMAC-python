"""Application logging configuration."""

from __future__ import annotations

import logging
from functools import lru_cache

from src.config import load_config
from src.constants import CONFIG_FILE, LOG_FORMAT


@lru_cache(maxsize=1)
def setup_logging() -> None:
    """Configure application-wide logging."""
    cfg = load_config(CONFIG_FILE)

    level = cfg.log_level.upper()

    logging.basicConfig(
        level=level,
        format=LOG_FORMAT,
        datefmt="%Y-%m-%d %H:%M:%S",
    )


def get_logger(name: str | None = None) -> logging.Logger:
    """
    Get a configured logger instance.

    Args:
        name: Logger name. If None, root logger is returned.

    Returns:
        Configured logging.Logger instance.
    """
    setup_logging()
    return logging.getLogger(name)
