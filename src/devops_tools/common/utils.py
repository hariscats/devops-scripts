"""Common utilities and shared functionality."""

import logging
import os
import sys
from pathlib import Path
from typing import Any, Dict, List, Optional

import yaml


def setup_logging(
    level: str = "INFO",
    log_file: Optional[Path] = None,
    format_string: Optional[str] = None,
) -> logging.Logger:
    """Set up logging configuration.

    Args:
        level: Logging level (DEBUG, INFO, WARNING, ERROR, CRITICAL)
        log_file: Optional file to write logs to
        format_string: Custom format string for log messages

    Returns:
        Configured logger instance
    """
    if format_string is None:
        format_string = "%(asctime)s - %(name)s - %(levelname)s - %(message)s"

    logging.basicConfig(
        level=getattr(logging, level.upper()),
        format=format_string,
        handlers=[
            logging.StreamHandler(sys.stdout),
            *([logging.FileHandler(log_file)] if log_file else []),
        ],
    )

    return logging.getLogger(__name__)


def load_config(config_path: Path) -> Dict[str, Any]:
    """Load configuration from YAML file.

    Args:
        config_path: Path to the configuration file

    Returns:
        Configuration dictionary

    Raises:
        FileNotFoundError: If config file doesn't exist
        yaml.YAMLError: If config file is invalid YAML
    """
    if not config_path.exists():
        raise FileNotFoundError(f"Config file not found: {config_path}")

    with open(config_path, "r") as f:
        config_data = yaml.safe_load(f)
        return config_data or {}


def get_project_root() -> Path:
    """Get the project root directory.

    Returns:
        Path to the project root
    """
    return Path(__file__).parent.parent.parent.parent


def format_bytes(bytes_value: float) -> str:
    """Format bytes into human readable format.

    Args:
        bytes_value: Number of bytes

    Returns:
        Formatted string (e.g., "1.5 GB")
    """
    for unit in ["B", "KB", "MB", "GB", "TB"]:
        if bytes_value < 1024.0:
            return f"{bytes_value: .1f} {unit}"
        bytes_value = bytes_value / 1024.0
    return f"{bytes_value: .1f} PB"


def validate_required_env_vars(required_vars: List[str]) -> None:
    """Validate that required environment variables are set.

    Args:
        required_vars: List of required environment variable names

    Raises:
        ValueError: If any required variables are missing
    """
    import os

    missing = [var for var in required_vars if not os.getenv(var)]
    if missing:
        raise ValueError(f"Missing required environment variables: {', '.join(missing)}")
