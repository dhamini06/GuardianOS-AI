"""Structured logging setup.

A single consistent, JSON-friendly structured logger is used across all
layers. A file handler writes to ``logs/guardianos.log`` when the parent
directory exists and is writable; the console handler always applies.
"""

from __future__ import annotations

import logging
import sys
from pathlib import Path

LOGGER_NAME = "guardianos"
LOG_DIR = Path(__file__).resolve().parents[2] / "logs"


def get_logger(name: str) -> logging.Logger:
    """Return a child logger of the root ``guardianos`` logger."""
    return logging.getLogger(f"{LOGGER_NAME}.{name}")


def setup_logging(level: str = "INFO", log_to_file: bool = True) -> None:
    """Configure the root ``guardianos`` logger once."""
    root = logging.getLogger(LOGGER_NAME)
    if root.handlers:
        root.setLevel(level.upper())
        return

    root.setLevel(level.upper())
    formatter = logging.Formatter(
        fmt="%(asctime)s %(levelname)-7s %(name)s: %(message)s",
        datefmt="%Y-%m-%dT%H:%M:%S%z",
    )

    console = logging.StreamHandler(sys.stdout)
    console.setFormatter(formatter)
    root.addHandler(console)

    if log_to_file:
        try:
            LOG_DIR.mkdir(parents=True, exist_ok=True)
            fh = logging.FileHandler(LOG_DIR / "guardianos.log", encoding="utf-8")
            fh.setFormatter(formatter)
            root.addHandler(fh)
        except OSError:
            # Logging to file is best-effort; never crash on startup.
            root.warning("Could not create log file; console-only logging.")


__all__ = ["get_logger", "setup_logging"]
