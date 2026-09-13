from __future__ import annotations

import os
import stat
from pathlib import Path
from dataclasses import dataclass
from typing import List, Union

PathLike = Union[str, os.PathLike[str], Path]

# FILE_ATTRIBUTE_REPARSE_POINT is available in Python's stat module on Windows,
# but use the documented Win32 value as a compatibility fallback so the same
# code can be unit-tested on non-Windows hosts.
_FILE_ATTRIBUTE_REPARSE_POINT = getattr(stat, "FILE_ATTRIBUTE_REPARSE_POINT", 0x0400)


class ForensicPathError(ValueError):
    """Raised when an untrusted filesystem path crosses the evidence boundary."""


@dataclass(frozen=True)
class BoundedScandirResult:
    """A bounded, non-stat'ing sample of directory entry names.

    ``names`` contains at most ``limit`` entries. ``enumerated`` counts every
    attempt to advance the directory iterator after it has been opened,
    including the final truncation/error/end-of-directory probe.  It is
    therefore at most ``limit + 1``.  ``error`` preserves a mid-enumeration
    OSError so callers can account for partial work without trusting a partial
    listing.  No DirEntry.stat()/is_dir()/is_file() call is made here.
    """

    names: List[str]
    truncated: bool
    enumerated: int
    error: OSError | None = None


def bounded_scandir_names(directory: PathLike, limit: int) -> BoundedScandirResult:
    """Bound directory enumeration even when the filesystem fails mid-stream.

    At most ``limit + 1`` iterator-advance operations are attempted.  The extra
    operation is solely a truncation/end/error probe.  If an OSError occurs
    after entries were yielded, the partial names and exact operation count are
    returned together with the error instead of losing the accounting data.
    """
    if limit < 0:
        raise ValueError("Directory enumeration limit must be non-negative")

    names: List[str] = []
    enumerated = 0
    truncated = False
    error: OSError | None = None

    try:
        with os.scandir(Path(directory)) as iterator:
            while enumerated < limit + 1:
                enumerated += 1
                try:
                    entry = next(iterator)
                except StopIteration:
                    break
                except OSError as exc:
                    error = exc
                    break

                if len(names) >= limit:
                    truncated = True
                    break
                names.append(entry.name)
    except OSError as exc:
        # Failure to open/enter/close the directory does not erase work already
        # accounted above.  Opening failures naturally retain enumerated == 0.
        error = exc

    return BoundedScandirResult(
        names=names,
        truncated=truncated,
        enumerated=enumerated,
        error=error,
    )


def _lstat(path: Path):
    """Small indirection kept intentionally testable for Windows reparse emulation."""
    return os.lstat(path)


def stat_is_reparse_point(st) -> bool:
    """Return True for symlinks and Windows reparse-point filesystem objects.

    Windows junctions are not reliably covered by Path.is_symlink() on the
    project's supported Python 3.10/3.11 floor. st_file_attributes exposes the
    underlying FILE_ATTRIBUTE_REPARSE_POINT bit without following the object.
    """
    if stat.S_ISLNK(st.st_mode):
        return True
    attributes = int(getattr(st, "st_file_attributes", 0) or 0)
    return bool(attributes & _FILE_ATTRIBUTE_REPARSE_POINT)


def is_reparse_point(path: PathLike) -> bool:
    """Inspect one filesystem object without following links/reparse points."""
    return stat_is_reparse_point(_lstat(Path(path)))


def lstat_non_reparse(path: PathLike):
    """lstat an object and reject every symlink/reparse point before traversal."""
    candidate = Path(path)
    st = _lstat(candidate)
    if stat_is_reparse_point(st):
        raise ForensicPathError(f"Reparse point is outside the forensic traversal policy: {candidate}")
    return st


def _absolute_lexical(path: PathLike) -> Path:
    # abspath normalizes '.'/'..' lexically but does not resolve symlinks or
    # junctions. That is important: every existing component is lstat'd before
    # resolve() is allowed to canonicalize the path.
    return Path(os.path.abspath(os.fspath(path)))


def assert_contained_non_reparse(root: PathLike, candidate: PathLike) -> Path:
    """Prove an existing candidate stays below root without crossing reparse points.

    Defence is deliberately two-layered:
      1. lstat every path component from root to candidate and reject *all*
         reparse points before any normal stat/open operation can follow them;
      2. resolve both paths and require canonical containment as defence in depth.

    The function is for existing forensic input objects only. It fails closed.
    """
    root_abs = _absolute_lexical(root)
    candidate_abs = _absolute_lexical(candidate)

    try:
        relative = candidate_abs.relative_to(root_abs)
    except ValueError as exc:
        raise ForensicPathError(
            f"Path escapes selected evidence root lexically: {candidate_abs}"
        ) from exc

    # Reject a selected root that is itself an indirection. Normal Windows drive
    # roots (for example H:\\) are not reparse points.
    lstat_non_reparse(root_abs)

    current = root_abs
    for part in relative.parts:
        current = current / part
        lstat_non_reparse(current)

    try:
        resolved_root = root_abs.resolve(strict=True)
        resolved_candidate = candidate_abs.resolve(strict=True)
    except OSError as exc:
        raise ForensicPathError(f"Could not canonicalize forensic path {candidate_abs}: {exc}") from exc

    try:
        resolved_candidate.relative_to(resolved_root)
    except ValueError as exc:
        raise ForensicPathError(
            f"Resolved path escapes selected evidence root: {candidate_abs} -> {resolved_candidate}"
        ) from exc

    return resolved_candidate
