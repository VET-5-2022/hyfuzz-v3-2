"""
Utility helper functions for HyFuzz-v3
"""

import os
import yaml
import logging
from datetime import datetime
from typing import Dict, Any, Optional

import colorlog


def load_config(config_path: str = "config/config.yaml") -> Dict[str, Any]:
    """
    Load configuration from YAML file.

    Args:
        config_path: Path to the configuration file

    Returns:
        Dictionary containing configuration settings
    """
    # Get the project root directory
    if not os.path.isabs(config_path):
        project_root = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
        config_path = os.path.join(project_root, config_path)

    with open(config_path, 'r') as f:
        config = yaml.safe_load(f)

    return config


def setup_logging(
    name: str,
    log_level: str = "INFO",
    log_file: Optional[str] = None
) -> logging.Logger:
    """
    Set up logging with colored console output and optional file logging.

    Args:
        name: Logger name
        log_level: Logging level (DEBUG, INFO, WARNING, ERROR, CRITICAL)
        log_file: Optional file path for log output

    Returns:
        Configured logger instance
    """
    logger = logging.getLogger(name)
    logger.setLevel(getattr(logging, log_level.upper()))

    # Prevent adding handlers multiple times
    if logger.handlers:
        return logger

    # Console handler with colors
    console_handler = colorlog.StreamHandler()
    console_handler.setFormatter(colorlog.ColoredFormatter(
        '%(log_color)s%(asctime)s - %(name)s - %(levelname)s - %(message)s',
        datefmt='%Y-%m-%d %H:%M:%S',
        log_colors={
            'DEBUG': 'cyan',
            'INFO': 'green',
            'WARNING': 'yellow',
            'ERROR': 'red',
            'CRITICAL': 'red,bg_white',
        }
    ))
    logger.addHandler(console_handler)

    # File handler if specified
    if log_file:
        os.makedirs(os.path.dirname(log_file), exist_ok=True)
        file_handler = logging.FileHandler(log_file)
        file_handler.setFormatter(logging.Formatter(
            '%(asctime)s - %(name)s - %(levelname)s - %(message)s',
            datefmt='%Y-%m-%d %H:%M:%S'
        ))
        logger.addHandler(file_handler)

    return logger


def get_timestamp() -> str:
    """
    Get current timestamp in ISO format.

    Returns:
        Formatted timestamp string
    """
    return datetime.now().isoformat()


def get_timestamp_filename() -> str:
    """
    Get current timestamp suitable for filenames.

    Returns:
        Formatted timestamp string without colons
    """
    return datetime.now().strftime("%Y%m%d_%H%M%S")


def ensure_dir(path: str) -> str:
    """
    Ensure a directory exists, creating it if necessary.

    Args:
        path: Directory path

    Returns:
        The same path (for chaining)
    """
    os.makedirs(path, exist_ok=True)
    return path


def calculate_statistics(data: list) -> Dict[str, float]:
    """
    Calculate basic statistics for a list of numbers.

    Args:
        data: List of numeric values

    Returns:
        Dictionary with min, max, mean, and count
    """
    if not data:
        return {"min": 0, "max": 0, "mean": 0, "count": 0}

    return {
        "min": min(data),
        "max": max(data),
        "mean": sum(data) / len(data),
        "count": len(data)
    }
