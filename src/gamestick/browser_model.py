from __future__ import annotations

import stat
from dataclasses import dataclass
from pathlib import Path
from typing import List

from .fs_safety import (
    ForensicPathError,
    assert_contained_non_reparse,
    bounded_scandir_names,
    lstat_non_reparse,
)


@dataclass(frozen=True)
class BrowserEntry:
    path: Path
    name: str
    is_directory: bool
    is_regular_file: bool
    size: int | None


@dataclass(frozen=True)
class BrowserListing:
    entries: List[BrowserEntry]
    truncated: bool
    entries_enumerated: int
    limit: int


def safe_browser_listing(root: Path, directory: Path, limit: int = 1000) -> BrowserListing:
    """List one browser level with a hard enumeration bound.

    At most ``limit + 1`` directory entries are consumed; the extra item is
    solely a truncation probe.  Only the bounded sample is sorted/presented.
    """
    safe_directory = assert_contained_non_reparse(root, directory)
    sampled = bounded_scandir_names(safe_directory, limit)
    if sampled.error is not None:
        return BrowserListing(
            entries=[],
            truncated=False,
            entries_enumerated=sampled.enumerated,
            limit=limit,
        )

    results: List[BrowserEntry] = []
    for name in sorted(sampled.names, key=str.casefold):
        child = safe_directory / name
        try:
            safe_child = assert_contained_non_reparse(root, child)
            st = lstat_non_reparse(safe_child)
        except (OSError, ForensicPathError):
            continue
        is_directory = stat.S_ISDIR(st.st_mode)
        is_regular_file = stat.S_ISREG(st.st_mode)
        results.append(BrowserEntry(
            path=safe_child,
            name=name,
            is_directory=is_directory,
            is_regular_file=is_regular_file,
            size=st.st_size if is_regular_file else None,
        ))

    results.sort(key=lambda item: (not item.is_directory, item.name.casefold()))
    return BrowserListing(
        entries=results,
        truncated=sampled.truncated,
        entries_enumerated=sampled.enumerated,
        limit=limit,
    )


def safe_browser_children(root: Path, directory: Path, limit: int = 1000) -> List[BrowserEntry]:
    """Compatibility wrapper returning only bounded Browser entries."""
    return safe_browser_listing(root, directory, limit=limit).entries
