#!/usr/bin/env python3
"""List the ``dist/`` artifacts that PyPI does not have yet.

``uv publish --check-url`` compares file hashes, so re-running a partial
release fails with "Local file and index file do not match" instead of
skipping: the sdists are not byte-reproducible, so a rebuild of the same tag
produces different bytes for the same filename.

Selecting the artifacts by filename first makes a re-run idempotent whatever
the build hashes are. ``--check-url`` stays in place as a second guard.

Usage:
    python3 scripts/pypi_missing.py <project> [dist-directory]

Prints one path per line. Empty output means every artifact for that project
and version is already on the index. The version is read from the workspace
``pyproject.toml``, which every package shares.
"""

from __future__ import annotations

import json
import pathlib
import sys
import tomllib
import urllib.error
import urllib.request

PROJECT_JSON = "https://pypi.org/pypi/{project}/{version}/json"


def _published_filenames(project: str, version: str) -> set[str]:
    """Return the filenames PyPI lists for one release, empty if unpublished."""
    try:
        with urllib.request.urlopen(
            PROJECT_JSON.format(project=project, version=version), timeout=30
        ) as response:
            return {item["filename"] for item in json.load(response)["urls"]}
    except urllib.error.HTTPError as error:
        if error.code != 404:  # 404 means the version is not on PyPI yet
            raise
        return set()


def main(argv: list[str]) -> int:
    if len(argv) not in (2, 3):
        print(__doc__, file=sys.stderr)
        return 2

    project = argv[1]
    dist = pathlib.Path(argv[2] if len(argv) == 3 else "dist")
    version = tomllib.loads(pathlib.Path("pyproject.toml").read_text())["project"][
        "version"
    ]

    candidates = sorted(
        path
        for path in dist.iterdir()
        if path.is_file()
        and path.name.startswith(f"{project.replace('-', '_')}-{version}")
    )
    if not candidates:
        print(f"no {project} {version} artifacts in {dist}", file=sys.stderr)
        return 1

    present = _published_filenames(project, version)
    for path in candidates:
        if path.name not in present:
            print(path)
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv))
