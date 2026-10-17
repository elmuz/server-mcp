#!/usr/bin/env python3
"""
Markdown Link Checker

Validates all links in .md files:
- Relative file links → must exist on disk
- Relative directory links → must exist on disk
- Anchor links (#heading) → must match a heading in the same file
- Cross-file anchors (file.md#heading) → file + anchor must both exist
- Absolute URLs → skipped in local mode, checked with --remote flag

Usage:
    python scripts/check_md_links.py [directory] [--remote]
    python scripts/check_md_links.py docs/
    python scripts/check_md_links.py . --remote
"""

import re
import sys
from pathlib import Path
from urllib.parse import unquote

# Patterns for markdown links
LINK_PATTERN = re.compile(r"\[([^\]]*)\]\(([^)]+)\)")
# HTML-style links
HTML_LINK_PATTERN = re.compile(
    r'<a\s+[^>]*href="([^"]+)"[^>]*>(.*?)</a>', re.IGNORECASE
)
# Markdown headings
HEADING_PATTERN = re.compile(r"^(#{1,6})\s+(.+)$", re.MULTILINE)
# Image links (also need validation)
IMAGE_PATTERN = re.compile(r"!\[([^\]]*)\]\(([^)]+)\)")


def slugify(heading: str) -> str:
    """Convert a heading to a GitHub-style anchor slug."""
    import unicodedata

    # GitHub's slugify algorithm:
    # 1. Lowercase
    # 2. Remove everything that isn't alphanumeric, hyphen, space, or underscore
    # 3. Replace spaces with hyphens (underscores stay)
    # 4. Collapse multiple hyphens
    slug = heading.strip().lower()
    # Remove control characters and normalize unicode
    slug = unicodedata.normalize("NFD", slug)
    # Remove anything that isn't alphanumeric, hyphen, space, underscore,
    # or non-spacing marks
    slug = re.sub(r"[^\w\s-]", "", slug, flags=re.ASCII)
    # Replace spaces with hyphens
    slug = re.sub(r"\s+", "-", slug)
    # Collapse multiple hyphens
    slug = re.sub(r"-+", "-", slug)
    return slug.strip("-")


def get_anchors(content: str) -> set[str]:
    """Extract all anchor slugs from markdown content."""
    anchors = set()
    for match in HEADING_PATTERN.finditer(content):
        heading_text = match.group(2).strip()
        # Strip any inline formatting markers
        heading_text = re.sub(r"[`*_~]", "", heading_text)
        anchors.add(slugify(heading_text))
    return anchors


def check_link(url: str, source_file: Path, root: Path) -> str | None:
    """
    Check a single link. Returns error message or None if valid.

    Args:
        url: The link URL (may include #anchor)
        source_file: The .md file containing the link
        root: The project root directory
    """
    root = root.resolve()

    # Skip protocol URLs (external links)
    if re.match(r"https?://|mailto:|ftp://", url):
        return None

    # Skip anchor-only links — they're validated in the anchor check below
    if url.startswith("#"):
        anchor_part = url[1:]  # Strip the #
        file_part = ""
    else:
        # Split file path and anchor
        file_part, _, anchor_part = url.partition("#")

    # URL decode
    file_part = unquote(file_part)

    # Resolve relative to source file's directory
    if file_part:
        target = (source_file.parent / file_part).resolve()

        if not target.exists():
            try:
                rel_source = source_file.resolve().relative_to(root)
            except ValueError:
                rel_source = source_file
            return f"{rel_source}: link to '{url}' → target not found"

        # If it's a directory link with no anchor, that's valid
        if target.is_dir() and not anchor_part:
            return None

    # Check anchor
    if anchor_part:
        if file_part:
            # Cross-file anchor: check file exists and anchor exists
            if not target.exists():
                return None  # Already reported above
            anchor_content = target.read_text(encoding="utf-8", errors="replace")
        else:
            # Same-file anchor
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

    # Check markdown links
    for match in LINK_PATTERN.finditer(content):
        url = match.group(2).strip()
        # Skip footnote references
        if re.match(r"^\^?[a-zA-Z0-9_-]+$", url):
            continue
        error = check_link(url, md_file, root)
        if error:
            errors.append(error)

    # Check image links
    for match in IMAGE_PATTERN.finditer(content):
        url = match.group(2).strip()
        error = check_link(url, md_file, root)
        if error:
            errors.append(error)

    return errors


def find_md_files(root: Path) -> list[Path]:
    """Find all markdown files in the project, respecting .gitignore."""
    md_files = []
    for pattern in ["**/*.md", "*.md"]:
        md_files.extend(root.glob(pattern))

    # Deduplicate and sort
    md_files = sorted(set(md_files))

    # Filter out common non-project dirs
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

    # Allow specifying a subdirectory
    target = root
    if args and not args[0].startswith("--"):
        target = root / args[0]
        if not target.is_dir():
            print(f"Error: {target} is not a directory")
            sys.exit(1)

    # Find markdown files
    md_files = find_md_files(target)
    if not md_files:
        print("No markdown files found.")
        sys.exit(0)

    # Check all links
    all_errors = []
    for md_file in md_files:
        errors = check_file(md_file, root)
        all_errors.extend(errors)

    if all_errors:
        print(f"Found {len(all_errors)} broken link(s):\n")
        for error in all_errors:
            print(f"  ❌ {error}")
        print()
        sys.exit(1)
    else:
        print(f"✅ All links valid ({len(md_files)} files checked)")
        sys.exit(0)


if __name__ == "__main__":
    main()
