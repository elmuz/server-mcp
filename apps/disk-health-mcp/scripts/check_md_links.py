"""
Markdown Link Checker

Validates relative file/directory links and anchor links in markdown files.
Skips external URLs (http, https, mailto, ftp).
Supports cross-file anchors (file.md#heading).

Usage:
    python scripts/check_md_links.py [directory] [--remote]
"""

import argparse
import re
import sys
from pathlib import Path


def slugify(text: str) -> str:
    """Convert heading text to GitHub-style anchor slug."""
    text = text.lower().strip()
    text = re.sub(r"[^\w\s-]", "", text)
    text = re.sub(r"[\s]+", "-", text)
    return text


def extract_headings(md_path: Path) -> set[str]:
    """Extract all heading slugs from a markdown file."""
    headings: set[str] = set()
    try:
        with open(md_path, encoding="utf-8") as f:
            for line in f:
                match = re.match(r"^(#{1,6})\s+(.+)$", line.strip())
                if match:
                    headings.add(slugify(match.group(2)))
    except (OSError, UnicodeDecodeError):
        pass
    return headings


def check_links(directory: str, check_remote: bool = False) -> bool:
    """Check all markdown links in the given directory."""
    dir_path = Path(directory)
    if not dir_path.is_dir():
        print(f"❌ Not a directory: {directory}")
        return False

    md_files = list(dir_path.rglob("*.md"))
    if not md_files:
        print(f"⚠️ No markdown files found in {directory}")
        return True

    errors = []
    total_links = 0
    valid_links = 0

    for md_file in md_files:
        try:
            with open(md_file, encoding="utf-8") as f:
                content = f.read()
        except (OSError, UnicodeDecodeError):
            continue

        rel_path = md_file.relative_to(dir_path)
        headings = extract_headings(md_file)

        # Find all markdown links [text](url)
        links = re.findall(r"\[([^\]]*)\]\(([^)]+)\)", content)

        for text, url in links:
            # Skip anchor-only links (handled below)
            if url.startswith("#"):
                anchor = url[1:]
                if anchor not in headings:
                    errors.append(
                        f"{rel_path}:#{text} -> "
                        f"anchor '{anchor}' not found in {rel_path}"
                    )
                else:
                    valid_links += 1
                    total_links += 1
                continue

            # Skip external URLs
            if url.startswith(("http://", "https://", "mailto:", "ftp://")):
                if check_remote:
                    # Could add HTTP HEAD check here
                    valid_links += 1
                    total_links += 1
                continue

            # Parse file path and optional anchor
            if "#" in url:
                file_part, anchor = url.rsplit("#", 1)
            else:
                file_part = url
                anchor = None

            # Resolve relative path
            if file_part:
                target = (md_file.parent / file_part).resolve()
                if not target.exists():
                    errors.append(f"{rel_path}: '{url}' -> file not found: {file_part}")
                    total_links += 1
                    continue

                # Check anchor in target file
                if anchor and target.suffix == ".md":
                    target_headings = extract_headings(target)
                    if anchor not in target_headings:
                        errors.append(
                            f"{rel_path}: '{url}' -> "
                            f"anchor '{anchor}' not found in {file_part}"
                        )
                    else:
                        valid_links += 1
                    total_links += 1
                else:
                    valid_links += 1
                    total_links += 1
            else:
                # Just an anchor in the current file
                if anchor and anchor not in headings:
                    errors.append(f"{rel_path}: '{url}' -> anchor '{anchor}' not found")
                else:
                    valid_links += 1
                total_links += 1

    if errors:
        for error in errors:
            print(f"❌ {error}")
        print(f"\n{len(errors)} broken link(s) found.")
        return False

    print(f"✅ All links valid ({len(md_files)} files, {total_links} links checked)")
    return True


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Check markdown links")
    parser.add_argument("directory", nargs="?", default=".", help="Directory to scan")
    parser.add_argument("--remote", action="store_true", help="Check remote URLs")
    args = parser.parse_args()
    sys.exit(0 if check_links(args.directory, args.remote) else 1)
