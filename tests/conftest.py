"""Test configuration for devops-tools."""

from pathlib import Path

import pytest


@pytest.fixture
def project_root():
    """Return the project root directory."""
    return Path(__file__).parent.parent


@pytest.fixture
def sample_config():
    """Return sample configuration for testing."""
    return {
        "logging": {
            "level": "DEBUG",
            "format": "%(asctime)s - %(name)s - %(levelname)s - %(message)s",
        },
        "docker": {"timeout": 30},
        "aws": {"regions": ["us-east-1", "us-west-2"]},
    }
