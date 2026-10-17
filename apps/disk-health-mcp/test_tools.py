"""
Disk Health MCP - Tool Verification Script

Lists all registered MCP tools with descriptions.
Run with: uv run python test_tools.py
"""

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent / "src"))

from disk_health_mcp.server import mcp


def list_tools():
    """Print all registered tools with descriptions."""
    tools = mcp._tool_manager._tools
    print(f"Disk Health MCP - {len(tools)} registered tools:\n")
    print(f"{'#':<3} {'Tool Name':<30} {'Description'}")
    print("-" * 80)
    for i, (name, tool) in enumerate(tools.items(), 1):
        desc = tool.description or "(no description)"
        # Truncate long descriptions
        if len(desc) > 70:
            desc = desc[:67] + "..."
        print(f"{i:<3} {name:<30} {desc}")


def verify_security_model():
    """Verify no generic command execution is available."""
    tools = list(mcp._tool_manager._tools.keys())
    dangerous = {"exec_command", "run_command", "shell", "execute"}
    found = dangerous & set(tools)
    if found:
        print(f"\n❌ SECURITY VIOLATION: Generic command tools found: {found}")
        return False
    print("\n✅ Security model verified: no generic command execution")
    return True


if __name__ == "__main__":
    list_tools()
    verify_security_model()
