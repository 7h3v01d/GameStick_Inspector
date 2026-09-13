from __future__ import annotations

from dataclasses import dataclass
import stat
from pathlib import Path
from typing import Iterable, List, Sequence, Tuple

from .fs_safety import (
    ForensicPathError,
    assert_contained_non_reparse,
    bounded_scandir_names,
    lstat_non_reparse,
)
from .models import ProfileMatch


@dataclass(frozen=True)
class DeviceProfile:
    profile_id: str
    display_name: str
    required_markers: Tuple[str, ...]
    optional_markers: Tuple[str, ...] = ()
    notes: str = ""
    max_score: int = 100


# These profiles describe observed filesystem signatures only. They deliberately
# do not claim a chipset/firmware identity until evidence supports that claim.
_MAX_PROFILE_ROOT_ENTRIES = 4_096


PROFILES: Sequence[DeviceProfile] = (
    DeviceProfile(
        profile_id="observed_cubegm_layout",
        display_name="Observed GameStick layout (Roms / cubegm / image)",
        required_markers=("Roms", "cubegm", "image"),
        optional_markers=("bios", "save", "saves", "config"),
        notes="Signature carried forward from the original project's later detector.",
    ),
    DeviceProfile(
        profile_id="legacy_generic_layout",
        display_name="Legacy prototype layout (roms / themes / emus)",
        required_markers=("roms", "themes", "emus"),
        notes="Historic prototype assumption; not considered authoritative.",
    ),
    DeviceProfile(
        profile_id="roms_only_layout",
        display_name="Generic ROM-volume layout",
        required_markers=("roms",),
        optional_markers=("bios", "system", "config", "save", "saves"),
        notes="Low-specificity fallback profile.",
        max_score=55,
    ),
)


def _entry_names(root: Path) -> List[str]:
    """Return a bounded sample of real, non-reparse top-level directories."""
    names: List[str] = []
    try:
        safe_root = assert_contained_non_reparse(root, root)
        sampled = bounded_scandir_names(safe_root, _MAX_PROFILE_ROOT_ENTRIES)
        if sampled.error is not None:
            return []
    except ForensicPathError:
        return []

    for name in sampled.names:
        path = safe_root / name
        try:
            safe_path = assert_contained_non_reparse(root, path)
            st = lstat_non_reparse(safe_path)
            if stat.S_ISDIR(st.st_mode):
                names.append(name)
        except (OSError, ForensicPathError):
            continue
    return names


def _lookup_casefold(names: Iterable[str]) -> dict[str, str]:
    return {name.casefold(): name for name in names}


def _score_profile_from_names(names: Iterable[str], profile: DeviceProfile) -> ProfileMatch:
    folded = _lookup_casefold(names)
    matched: List[str] = []
    missing: List[str] = []

    for marker in profile.required_markers:
        actual = folded.get(marker.casefold())
        if actual is not None:
            matched.append(actual)
        else:
            missing.append(marker)

    optional_hits = sum(1 for marker in profile.optional_markers if marker.casefold() in folded)
    required_hits = len(profile.required_markers) - len(missing)

    if not profile.required_markers:
        score = 0
    else:
        required_ratio = required_hits / len(profile.required_markers)
        optional_ratio = optional_hits / max(1, len(profile.optional_markers))
        score = min(profile.max_score, round((required_ratio * 90) + (optional_ratio * 10)))

    # A profile that misses any required marker is never promoted to medium/high.
    if missing:
        score = min(score, 69)

    if score >= 90:
        confidence = "high"
    elif score >= 70:
        confidence = "medium"
    elif score >= 40:
        confidence = "low"
    else:
        confidence = "none"

    return ProfileMatch(
        profile_id=profile.profile_id,
        display_name=profile.display_name,
        score=score,
        confidence=confidence,
        matched_markers=matched,
        missing_markers=missing,
    )


def score_profile(root: Path, profile: DeviceProfile) -> ProfileMatch:
    return _score_profile_from_names(_entry_names(root), profile)


def profile_matches(root: Path) -> List[ProfileMatch]:
    # Scan the untrusted root once for all profile candidates rather than once
    # per profile. This keeps the total probe work bounded as profiles grow.
    names = _entry_names(root)
    matches = [_score_profile_from_names(names, profile) for profile in PROFILES]
    return sorted(matches, key=lambda match: (-match.score, match.profile_id))


def best_profile_from_matches(matches: Sequence[ProfileMatch]) -> ProfileMatch:
    best = matches[0] if matches else None
    if best is None or best.score < 40:
        return ProfileMatch(
            profile_id="unknown",
            display_name="Unknown / unsupported layout",
            score=best.score if best else 0,
            confidence="none",
            matched_markers=best.matched_markers if best else [],
            missing_markers=best.missing_markers if best else [],
        )
    return best


def best_profile(root: Path) -> ProfileMatch:
    return best_profile_from_matches(profile_matches(root))
