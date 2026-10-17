#!/usr/bin/env python3
"""
Markdown Link Checker

Validates all links in .md files:
- Relative file links must exist on disk
- Relative directory links must exist on disk
- Anchor links (#heading) must match a heading in the same file
- Cross-file anchors (file.md#heading) - file + anchor must both exist
- Absolute URLs are skipped in local mode

Usage:
    python scripts/check_md_links.py [directory]
"""

import re
import sys
from pathlib import Path
from urllib.parse import unquote

LINK_PATTERN = re.compile(r"\[([^\]]*)\]\(([^)]+)\)")
HEADING_PATTERN = re.compile(r"^(#{1,6})\s+(.+)$", re.MULTILINE)
IMAGE_PATTERN = re.compile(r"!\[([^\]]*)\]\(([^)]+)\)")


def slugify(heading: str) -> str:
    """Convert a heading to a GitHub-style anchor slug."""
    import unicodedata

    slug = heading.strip().lower()
    slug = unicodedata.normalize("NFD", slug)
    slug = re.sub(r"[^\w\s-]", "", slug, flags=re.ASCII)
    slug = re.sub(r"\s+", "-", slug)
    slug = re.sub(r"-+", "-", slug)
    return slug.strip("-")


def get_anchors(content: str) -> set[str]:
    """Extract all anchor slugs from markdown content."""
    anchors = set()
    for match in HEADING_PATTERN.finditer(content):
        heading_text = match.group(2).strip()
        heading_text = re.sub(r"[`*_~]", "", heading_text)
        anchors.add(slugify(heading_text))
    return anchors


def check_link(url: str, source_file: Path, root: Path) -> str | None:
    """Check a single link. Returns error message or None if valid."""
    root = root.resolve()

    if re.match(r"https?://|mailto:|ftp://", url):
        return None

    if url.startswith("#"):
        file_part = ""
        anchor_part = url[1:]
    else:
        file_part, _, anchor_part = url.partition("#")

    file_part = unquote(file_part)

    if file_part:
        target = (source_file.parent / file_part).resolve()

        if not target.exists():
            try:
                rel_source = source_file.resolve().relative_to(root)
            except ValueError:
                rel_source = source_file
            return f"{rel_source}: link to '{url}' - target not found"

        if target.is_dir() and not anchor_part:
            return None

    if anchor_part:
        if file_part:
            if not target.exists():
                return None
            anchor_content = target.read_text(encoding="utf-8", errors="replace")
        else:
            anchor_content = source_file.read_text(encoding="utf-8", errors="replace")

        anchors = get_anchors(anchor_content)
        if anchor_part not in anchors:
            try:
                rel_source = source_file.resolve().relative_to(root)
            except ValueError:
                rel_source = source_file
            return (
                f"{rel_source}: anchor '#{anchor_part}' "
                f"not found in {'.' + file_part if file_part else 'this file'}"
            )

    return None


def check_file(md_file: Path, root: Path) -> list[str]:
    """Check all links in a markdown file. Returns list of errors."""
    errors = []
    try:
        content = md_file.read_text(encoding="utf-8", errors="replace")
    except Exception as e:
        return [f"{md_file}: cannot read file: {e}"]

    for match in LINK_PATTERN.finditer(content):
        url = match.group(2).strip()
        if re.match(r"^\^?[a-zA-Z0-9_-]+$", url):
            continue
        error = check_link(url, md_file, root)
        if error:
            errors.append(error)

    for match in IMAGE_PATTERN.finditer(content):
        url = match.group(2).strip()
        error = check_link(url, md_file, root)
        if error:
            errors.append(error)

    return errors


def find_md_files(root: Path) -> list[Path]:
    """Find all markdown files, respecting .gitignore patterns."""
    md_files = []
    for pattern in ["**/*.md", "*.md"]:
        md_files.extend(root.glob(pattern))

    md_files = sorted(set(md_files))

    skip_dirs = {
        ".git",
        ".venv",
        ".ruff_cache",
        ".pytest_cache",
        "__pycache__",
        "node_modules",
        ".mypy_cache",
    }
    return [f for f in md_files if not any(part in skip_dirs for part in f.parts)]


def main():
    args = sys.argv[1:]
    root = Path.cwd()

    target = root
    if args and not args[0].startswith("--"):
        target = root / args[0]
        if not target.is_dir():
            print(f"Error: {target} is not a directory")
            sys.exit(1)

    md_files = find_md_files(target)
    if not md_files:
        print("No markdown files found.")
        sys.exit(0)

    all_errors = []
    for md_file in md_files:
        errors = check_file(md_file, root)
        all_errors.extend(errors)

    if all_errors:
        print(f"Found {len(all_errors)} broken link(s):\n")
        for error in all_errors:
            print(f"  X {error}")
        print()
        sys.exit(1)
    else:
        print(f"All links valid ({len(md_files)} files checked)")
        sys.exit(0)


if __name__ == "__main__":
    main()
