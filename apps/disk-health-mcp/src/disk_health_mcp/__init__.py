"""
Disk Health MCP

Disk health diagnostics MCP server. Analyzes SMART, NVMe, ZFS, RAID,
and I/O metrics with manufacturer-aware severity assessment.

Uses server-management-lib for SSH management, security validation,
and time-series database clients.
"""

__version__ = "0.4.0"

from .server import cli, main, mcp

__all__ = ["__version__", "cli", "main", "mcp"]

if __name__ == "__main__":
    cli()
