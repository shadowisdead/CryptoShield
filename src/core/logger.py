"""
Centralized logging for CryptoShield.

Log file:
    logs/cryptoshield.log

Format:
    [%(asctime)s] [%(levelname)s] %(message)s
"""

from __future__ import annotations

import logging
import os
from typing import Final

_LOGGER_NAME: Final[str] = "cryptoshield"
_LOG_DIR_NAME: Final[str] = "logs"
_LOG_FILE_NAME: Final[str] = "cryptoshield.log"


def _get_log_path() -> str:
    """Resolve the log file path relative to the project root."""
    # This file lives in src/core/logger.py → project root is two levels up.
    here = os.path.abspath(os.path.dirname(__file__))
    project_root = os.path.abspath(os.path.join(here, os.pardir, os.pardir))
    log_dir = os.path.join(project_root, _LOG_DIR_NAME)
    os.makedirs(log_dir, exist_ok=True)
    return os.path.join(log_dir, _LOG_FILE_NAME)


def get_logger() -> logging.Logger:
    """
    Return the shared CryptoShield logger.

    Ensures the logger is configured exactly once with a file handler.
    """
    logger = logging.getLogger(_LOGGER_NAME)
    if logger.handlers:
        return logger

    logger.setLevel(logging.INFO)

    log_path = _get_log_path()
    handler = logging.FileHandler(log_path, encoding="utf-8")
    formatter = logging.Formatter("[%(asctime)s] [%(levelname)s] %(message)s")
    handler.setFormatter(formatter)

    logger.addHandler(handler)
    logger.propagate = False

    return logger

