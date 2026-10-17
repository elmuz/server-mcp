#!/usr/bin/env python3
"""
Generate smartdb.py from smartmontools drivedb.h DEFAULT presets.

Downloads the latest drivedb.h, extracts the DEFAULT entry's -v presets,
and generates a Python module with canonical SMART attribute mappings.

Usage:
    uv run python scripts/generate_smartdb.py

The generated file is committed to the repo so the project works
offline and doesn't depend on network access at runtime.
"""

import re
import urllib.request
from pathlib import Path

DRIVEDB_URL = (
    "https://raw.githubusercontent.com/smartmontools/smartmontools"
    "/master/smartmontools/drivedb.h"
)

OUTPUT = Path(__file__).parent.parent / "src" / "disk_health_mcp" / "smartdb.py"

HEADER = '''\
"""
SMART attribute reference database.

Auto-generated from smartmontools drivedb.h DEFAULT presets.
Do not edit manually — run scripts/generate_smartdb.py to regenerate.

Sources:
- smartmontools drivedb.h: https://github.com/smartmontools/smartmontools/blob/master/smartmontools/drivedb.h
- Seagate composite decoding: smartmontools source (attributes 1, 7, 10 use 48-bit)

Provides:
- SMART_ATTR: dict[int, SMARTAttr] — attribute ID → (name, encoding, type_hint)
- SMART_ATTR_NAMES: dict[int, str] — attribute ID → canonical name
- SEAGATE_COMPOSITE: set[int] — attributes that use 48-bit composite encoding on Seagate
"""

from __future__ import annotations

from dataclasses import dataclass


@dataclass(frozen=True)
class SMARTAttr:
    """Canonical SMART attribute metadata from smartmontools drivedb.h."""

    name: str
    encoding: str  # raw48, raw16, raw24(raw8), raw16(raw16), tempminmax, etc.
    type_hint: str  # HDD, SSD, or ""


SMART_ATTR: dict[int, SMARTAttr] = {}
SMART_ATTR_NAMES: dict[int, str] = {}
SEAGATE_COMPOSITE: set[int] = set()
'''


def fetch_drivedb() -> str:
    """Download the latest drivedb.h from GitHub."""
    print(f"Fetching {DRIVEDB_URL}...")
    with urllib.request.urlopen(DRIVEDB_URL, timeout=30) as resp:
        return resp.read().decode("utf-8")


def extract_default_presets(content: str) -> list[tuple[int, str, str, str]]:
    """Extract -v presets from the DEFAULT entry only.

    The DEFAULT entry is the first { "DEFAULT", ... } block in the file.
    Returns list of (id, encoding, name, type_hint).
    """
    results = []
    in_default = False
    for line in content.splitlines():
        stripped = line.strip()
        # Start of DEFAULT entry
        if stripped.startswith('{ "DEFAULT"'):
            in_default = True
            continue
        # End of DEFAULT entry (next entry starts with {)
        if in_default and stripped.startswith("{ "):
            break
        if not in_default:
            continue

        # Skip lines that are part of the entry header (before presets)
        if not stripped.startswith('"-v '):
            continue

        # Remove surrounding quotes and trailing comment
        line = stripped.strip('"').strip()
        # Remove trailing comment
        if "//" in line:
            line = line[: line.index("//")]
        line = line.strip()

        # Parse: -v ID,ENCODING,NAME[,TYPE]
        match = re.match(r"-v\s+(\d+),([^,]+),([^,\s]+)(?:,\s*(\S+))?", line)
        if match:
            attr_id = int(match.group(1))
            encoding = match.group(2)
            name = match.group(3)
            type_hint = match.group(4) or ""
            results.append((attr_id, encoding, name, type_hint))

    return results


def generate_python_module(
    presets: list[tuple[int, str, str, str]],
) -> str:
    """Generate the smartdb.py module content."""
    lines = [HEADER]
    lines.append("")
    lines.append("# Canonical SMART attribute database")
    lines.append("# Format: ID -> SMARTAttr(name, encoding, type_hint)")
    lines.append("")
    lines.append("SMART_ATTR = {")

    for attr_id, encoding, name, type_hint in sorted(presets):
        lines.append(
            f"    {attr_id}: SMARTAttr({name!r}, {encoding!r}, {type_hint!r}),"
        )

    lines.append("}")
    lines.append("")
    lines.append("# Quick lookup: ID -> name")
    lines.append("SMART_ATTR_NAMES = {k: v.name for k, v in SMART_ATTR.items()}")
    lines.append("")
    lines.append("# Seagate-specific: these attributes use 48-bit composite encoding")
    lines.append("# (upper 24 bits = normalized value, lower 24 bits = raw count)")
    lines.append("# Reference: smartmontools smartctl.cpp parse_seagate_raw_value()")
    lines.append("SEAGATE_COMPOSITE = {")
    lines.append("    1,   # Raw_Read_Error_Rate")
    lines.append("    7,   # Seek_Error_Rate")
    lines.append("    10,  # Spin_Retry_Count")
    lines.append("}")
    lines.append("")

    return "\n".join(lines)


def main():
    content = fetch_drivedb()
    presets = extract_default_presets(content)
    if not presets:
        raise ValueError("No -v presets found in DEFAULT entry")
    module = generate_python_module(presets)
    OUTPUT.write_text(module)
    print(f"Generated {OUTPUT} with {len(presets)} attribute mappings")


if __name__ == "__main__":
    main()
