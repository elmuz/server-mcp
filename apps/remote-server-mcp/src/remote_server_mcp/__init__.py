"""
Remote Server MCP - Main entry point
"""

from .server import cli, main, mcp

__version__ = "0.3.0"

__all__ = ["__version__", "cli", "main", "mcp"]

if __name__ == "__main__":
    cli()
