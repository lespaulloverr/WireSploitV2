"""Structured logging utility for WireSploit.

Provides consistent timestamped logging with log levels using the standard library.
"""

import logging
import sys
from typing import Optional


# Re-export standard log levels for convenience
DEBUG = logging.DEBUG
INFO = logging.INFO
WARNING = logging.WARNING
ERROR = logging.ERROR
CRITICAL = logging.CRITICAL


_DEFAULT_FORMAT = "%(asctime)s | %(levelname)-8s | %(name)s | %(message)s"
_DATE_FORMAT = "%Y-%m-%d %H:%M:%S"


def get_logger(name: str, level: int = INFO) -> logging.Logger:
    """Get a configured logger with timestamp formatting.
    
    Args:
        name: Logger name (typically __name__)
        level: Logging level (DEBUG, INFO, WARNING, ERROR, CRITICAL)
    
    Returns:
        Configured logger instance
    """
    logger = logging.getLogger(name)
    logger.setLevel(level)
    
    # Avoid duplicate handlers if called multiple times
    if not logger.handlers:
        handler = logging.StreamHandler(sys.stdout)
        handler.setLevel(level)
        formatter = logging.Formatter(_DEFAULT_FORMAT, datefmt=_DATE_FORMAT)
        handler.setFormatter(formatter)
        logger.addHandler(handler)
        logger.propagate = False
    
    return logger


def setup_root_logger(level: int = INFO) -> logging.Logger:
    """Configure the root logger for application-wide logging.
    
    Args:
        level: Root logging level
    
    Returns:
        Root logger instance
    """
    root = logging.getLogger()
    root.setLevel(level)
    
    # Clear existing handlers
    for h in root.handlers[:]:
        root.removeHandler(h)
    
    handler = logging.StreamHandler(sys.stdout)
    handler.setLevel(level)
    formatter = logging.Formatter(_DEFAULT_FORMAT, datefmt=_DATE_FORMAT)
    handler.setFormatter(formatter)
    root.addHandler(handler)
    
    return root


def set_log_level(logger: logging.Logger, level: int) -> None:
    """Dynamically adjust log level for a logger and its handlers.
    
    Args:
        logger: Logger instance to modify
        level: New logging level
    """
    logger.setLevel(level)
    for handler in logger.handlers:
        handler.setLevel(level)
