"""
Shared fixtures for server-management-lib tests.

Provides common fixtures used across multiple test modules:
- Basic SSH config
- Config with key authentication
- Config with password authentication
- SecurityValidator instances
"""

import pytest

from server_management_lib.security import SecurityValidator


@pytest.fixture
def config():
    """Basic SSH configuration."""
    return {
        "ssh": {
            "host": "localhost",
            "port": 22,
            "username": "test",
            "key_path": None,
            "known_hosts": "none",
        },
        "security": {"services_path": "/srv"},
    }


@pytest.fixture
def config_with_key():
    """SSH configuration with key-based authentication."""
    return {
        "ssh": {
            "host": "localhost",
            "port": 22,
            "username": "test",
            "key_path": "~/.ssh/id_rsa",
            "known_hosts": "none",
        },
        "security": {"services_path": "/srv"},
    }


@pytest.fixture
def config_with_password():
    """SSH configuration with password authentication."""
    return {
        "ssh": {
            "host": "localhost",
            "port": 22,
            "username": "test",
            "password": "secret",
            "known_hosts": "none",
        },
        "security": {"services_path": "/srv"},
    }


@pytest.fixture
def security(config):
    """SecurityValidator instance with basic config."""
    return SecurityValidator(config)
