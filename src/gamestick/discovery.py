from __future__ import annotations

import hashlib
import json
from dataclasses import asdict
from pathlib import PurePosixPath
from typing import Iterable, List, Sequence

from .ordering import stable_path_score_key, stable_text_key
from .privacy import canonical_platform_name
from .models import (
    CandidateArtifact,
    ContentRootHint,
    DeviceProfileCandidate,
    DirectorySnapshot,
    LauncherCandidate,
    ProfileMatch,
    NumberedDatProfileCandidate,
)

_LAUNCHER_NAME_TERMS = {
    "game", "games", "gamelist", "rom", "roms", "launcher", "menu",
    "frontend", "index", "catalog", "library",
}
_SCHEMA_TERMS = {
    "game", "games", "rom", "roms", "path", "file", "filename", "title",
    "emulator", "system", "platform", "image", "images", "cover", "boxart",
    "artwork", "preview", "snap", "gamelist", "launcher", "index", "catalog", "library",
}
_ROLE_TERMS = {
    "launcher-index": {"game", "games", "gamelist", "rom", "roms", "launcher", "index", "catalog", "library"},
    "path-map": {"path", "file", "filename", "rom", "roms"},
    "artwork-map": {"image", "images", "cover", "boxart", "artwork", "preview", "snap"},
    "platform-map": {"emulator", "system", "platform", "console"},
}

_CONTENT_ROOTS = {
    "roms": ("rom-library", 95),
    "rom": ("rom-library", 90),
    "games": ("rom-library", 85),
    "image": ("artwork-library", 92),
    "images": ("artwork-library", 92),
    "artwork": ("artwork-library", 92),
    "boxart": ("artwork-library", 90),
    "boxarts": ("artwork-library", 90),
    "covers": ("artwork-library", 88),
    "cover": ("artwork-library", 85),
    "snap": ("artwork-library", 82),
    "snaps": ("artwork-library", 82),
    "cubegm": ("launcher-system", 90),
    "launcher": ("launcher-system", 85),
    "frontend": ("launcher-system", 85),
    "menu": ("launcher-system", 75),
    "bios": ("bios-library", 80),
    "save": ("save-data", 75),
    "saves": ("save-data", 75),
    "config": ("configuration", 65),
    "system": ("system-data", 60),
}

_KNOWN_LAUNCHER_FILENAMES = {
    "games.db": 42,
    "game.db": 40,
    "gamelist.xml": 48,
    "games.csv": 42,
    "game.csv": 42,
    "games.dat": 28,
    "game.dat": 28,
    "roms.db": 38,
    "romlist.db": 40,
    "romlist.csv": 40,
}


def _words(value: str) -> set[str]:
    token = []
    words: set[str] = set()
    for char in value.casefold():
        if char.isalnum():
            token.append(char)
        elif token:
            words.add("".join(token))
            token = []
    if token:
        words.add("".join(token))
    return words


def _detail_names(artifact: CandidateArtifact) -> List[str]:
    """Return only privacy-bounded derived semantic terms.

    Raw schema/key/section names are intentionally excluded. CandidateArtifact
    details may contain counts and allowlisted derived terms, but launcher
    classification must not treat arbitrary media-supplied strings as schema.
    """
    details = artifact.details or {}
    names: List[str] = []
    for key in (
        "recognized_schema_terms",
        "recognized_column_terms",
        "recognized_header_terms",
        "recognized_key_terms",
        "recognized_section_terms",
        "recognized_root_terms",
    ):
        values = details.get(key)
        if isinstance(values, list):
            names.extend(str(value) for value in values[:100])
    return names


def _launcher_candidate(artifact: CandidateArtifact) -> LauncherCandidate | None:
    normalized = artifact.path.replace("\\", "/")
    path = PurePosixPath(normalized)
    basename = path.name.casefold()
    score = 0
    evidence: List[str] = []

    exact = _KNOWN_LAUNCHER_FILENAMES.get(basename)
    if exact:
        score += exact
        evidence.append(f"known launcher/index-style filename: {path.name}")

    basename_words = _words(path.stem)
    name_hits = sorted(basename_words & _LAUNCHER_NAME_TERMS)
    if name_hits:
        increment = min(30, 8 * len(name_hits))
        score += increment
        evidence.append("filename terms: " + ", ".join(name_hits))

    path_words = set()
    for part in path.parts[:-1]:
        path_words.update(_words(part))
    if "cubegm" in path_words:
        score += 12
        evidence.append("located beneath cubegm")
    elif path_words & {"launcher", "frontend", "menu"}:
        score += 8
        evidence.append("located beneath launcher/frontend-style directory")

    format_scores = {
        "sqlite3": 18,
        "csv": 14,
        "xml": 12,
        "json": 8,
        "text-config": 4,
        "opaque-dat": 2,
        "database-extension/non-sqlite": 3,
    }
    format_score = format_scores.get(artifact.format_name or "", 0)
    if format_score:
        score += format_score
        evidence.append(f"structured metadata format: {artifact.format_name}")

    detail_names = _detail_names(artifact)
    detail_words: set[str] = set()
    for name in detail_names:
        detail_words.update(_words(name))
    semantic_hits = sorted(detail_words & _SCHEMA_TERMS, key=stable_text_key)
    # CSV header interpretation remains heuristic until a real GameStick CSV
    # layout has been observed and frozen. CSV-derived terms may rank a
    # candidate, but cannot independently satisfy the probable/high gate.
    csv_heuristic_only = (artifact.format_name or "") == "csv"
    semantic_corroborated = bool(semantic_hits) and not csv_heuristic_only
    if semantic_hits:
        increment = min(36, 6 * len(semantic_hits))
        score += increment
        evidence.append("derived structural terms: " + ", ".join(semantic_hits[:12]))
        if csv_heuristic_only:
            evidence.append("CSV structural terms are heuristic-only until a device format is frozen")

    # Avoid promoting ordinary settings/config files merely because their format is parseable.
    if not exact and not name_hits and not semantic_hits:
        return None

    # Filename/location/format can nominate a candidate, but 'high/probable'
    # requires corroboration from inside the artifact's structural metadata.
    if not semantic_corroborated and score >= 75:
        score = 74
        evidence.append("uncorroborated path/format evidence capped below probable threshold")
    score = min(100, score)
    if score >= 75:
        confidence = "high"
    elif score >= 50:
        confidence = "medium"
    else:
        confidence = "low"

    combined_words = basename_words | detail_words
    role_hints = [
        role for role, terms in _ROLE_TERMS.items()
        if combined_words & terms
    ]
    if not role_hints:
        role_hints = ["metadata-candidate"]

    return LauncherCandidate(
        path=normalized,
        format_name=artifact.format_name or "unknown",
        score=score,
        confidence=confidence,
        role_hints=sorted(role_hints, key=stable_text_key),
        evidence=evidence[:12],
    )


def rank_launcher_candidates(artifacts: Sequence[CandidateArtifact]) -> List[LauncherCandidate]:
    candidates = []
    for artifact in artifacts:
        candidate = _launcher_candidate(artifact)
        if candidate is not None:
            candidates.append(candidate)
    return sorted(candidates, key=lambda item: stable_path_score_key(item.score, item.path))


def identify_content_roots(snapshots: Sequence[DirectorySnapshot]) -> List[ContentRootHint]:
    roots: List[ContentRootHint] = []
    for snapshot in snapshots:
        normalized = snapshot.path.replace("\\", "/").strip("/")
        if not normalized or normalized == ".":
            continue
        leaf = PurePosixPath(normalized).name.casefold()
        role_score = _CONTENT_ROOTS.get(leaf)
        if role_score is None:
            continue
        role, score = role_score
        evidence = [f"directory name matches {role} convention"]
        if snapshot.truncated:
            evidence.append("directory snapshot is a bounded/truncated sample")
        if snapshot.file_names_redacted:
            evidence.append("filenames are privacy-redacted in exported evidence")
        if snapshot.directory_names:
            if role in {"rom-library", "artwork-library"}:
                safe_platforms = sorted(
                    {
                        canonical
                        for value in snapshot.directory_names
                        if (canonical := canonical_platform_name(value)) is not None
                    },
                    key=stable_text_key,
                )
                if safe_platforms:
                    evidence.append(
                        "recognized platform semantics: " + ", ".join(safe_platforms[:32])
                    )
            else:
                evidence.append(f"observed child directories: {len(snapshot.directory_names)}")
        roots.append(
            ContentRootHint(
                path=normalized,
                role=role,
                score=score,
                evidence=evidence,
            )
        )
    return sorted(roots, key=lambda item: stable_path_score_key(item.score, item.path))


def _platform_directories(
    snapshots: Sequence[DirectorySnapshot], roots: Sequence[ContentRootHint]
) -> List[str]:
    rom_paths = {root.path.casefold() for root in roots if root.role == "rom-library"}
    platforms: set[str] = set()
    for snapshot in snapshots:
        normalized = snapshot.path.replace("\\", "/").strip("/")
        if normalized.casefold() not in rom_paths:
            continue
        for name in snapshot.directory_names:
            canonical = canonical_platform_name(name)
            if canonical is not None:
                platforms.add(canonical)
    return sorted(platforms, key=stable_text_key)[:256]


def build_device_profile_candidate(
    *,
    profile: ProfileMatch,
    structure_sha256: str,
    artifacts: Sequence[CandidateArtifact],
    snapshots: Sequence[DirectorySnapshot],
    numbered_dat_profile: NumberedDatProfileCandidate | None = None,
) -> DeviceProfileCandidate:
    launcher_candidates = rank_launcher_candidates(artifacts)

    if numbered_dat_profile is not None and numbered_dat_profile.root_catalog is not None:
        root_catalog = numbered_dat_profile.root_catalog
        dat_candidate: LauncherCandidate | None = None
        if root_catalog.central_directory_valid:
            is_wqw = root_catalog.container_format == "wqw-obfuscated-zip"
            dialect_label = "WQW ZIP-derived" if is_wqw else "standard-ZIP"
            dat_evidence: List[str] = [
                "real-device numbered-DAT catalogue family detected",
                f"root.dat exposes a bounded {dialect_label} central directory",
            ]
            if is_wqw:
                dat_evidence.append("WQW record signatures and XOR-0xE5 member-name decoding corroborated")
            if "fileinfo.txt" in root_catalog.control_members:
                dat_evidence.append("canonical global control member observed: fileinfo.txt")
            if numbered_dat_profile.filelist_control_count:
                dat_evidence.append(
                    f"canonical filelist.txt observed in {numbered_dat_profile.filelist_control_count} numbered catalogue(s)"
                )
            dat_score = numbered_dat_profile.heuristic_score
            if numbered_dat_profile.status == "PROBABLE":
                dat_score = max(90, dat_score)
                dat_confidence = "high"
            else:
                dat_score = min(74, max(50, dat_score))
                dat_confidence = "medium"
            dat_candidate = LauncherCandidate(
                path="root.dat",
                format_name="numbered-dat-wqw-catalog" if is_wqw else "numbered-dat-zip-catalog",
                score=min(100, dat_score),
                confidence=dat_confidence,
                role_hints=["global-catalog", "launcher-index"],
                evidence=dat_evidence,
            )
        elif (
            root_catalog.container_format != "unreadable"
            and root_catalog.binary_fingerprint is not None
            and numbered_dat_profile.heuristic_score >= 50
        ):
            # Real hardware showed the numbered-DAT family while rejecting the
            # standard-ZIP hypothesis.  The layout can therefore outrank generic
            # launcher guesses, but binary fingerprinting alone can never make it
            # probable or claim that the record format is understood.
            dat_evidence = [
                "real-device numbered-DAT catalogue layout detected",
                "root.dat is readable but does not expose the bounded standard-ZIP structure",
                "bounded binary fingerprint evidence available; record format remains unidentified",
            ]
            if numbered_dat_profile.numbered_catalog_common_prefix_bytes:
                dat_evidence.append(
                    "numbered DATs share an exact prefix bucket of "
                    f"{numbered_dat_profile.numbered_catalog_common_prefix_bytes} bytes"
                )
            if numbered_dat_profile.common_sampled_signatures:
                dat_evidence.append(
                    "common allowlisted sampled signatures: "
                    + ", ".join(numbered_dat_profile.common_sampled_signatures)
                )
            dat_candidate = LauncherCandidate(
                path="root.dat",
                format_name="numbered-dat-binary-catalog",
                score=min(74, max(50, numbered_dat_profile.heuristic_score)),
                confidence="medium",
                role_hints=["global-catalog", "launcher-index-candidate"],
                evidence=dat_evidence,
            )

        if dat_candidate is not None:
            launcher_candidates = [dat_candidate, *launcher_candidates]
            launcher_candidates = sorted(
                launcher_candidates,
                key=lambda item: stable_path_score_key(item.score, item.path),
            )
    content_roots = identify_content_roots(snapshots)
    platforms = _platform_directories(snapshots, content_roots)

    top = launcher_candidates[0] if launcher_candidates else None
    if top is None:
        resolution = "unresolved"
    elif top.confidence == "high":
        resolution = "probable"
    else:
        resolution = "candidate"

    notes: List[str] = [
        "Generated from bounded read-only probe evidence.",
        "Generic launcher ranking remains heuristic; numbered-DAT evidence is derived from exact root.dat / NNN/NNN.dat paths with no archive extraction or full-file binary scan.",
    ]
    if numbered_dat_profile is not None:
        notes.append(
            f"Numbered-DAT firmware candidate: {numbered_dat_profile.status.lower()} "
            f"({numbered_dat_profile.confidence}; heuristic score {numbered_dat_profile.heuristic_score}/100)."
        )
    if any(root.role == "rom-library" for root in content_roots):
        notes.append("ROM-library root evidence is present.")
    if any(root.role == "artwork-library" for root in content_roots):
        notes.append("Artwork-library root evidence is present.")
    if top is not None:
        notes.append(f"Top launcher/index candidate: {top.path} ({top.confidence}; heuristic score {top.score}/100).")
    else:
        notes.append("No launcher/index candidate reached the minimum evidence threshold.")

    evidence_payload = {
        "schema_version": 9,
        "base_profile_id": profile.profile_id,
        "base_profile_score": profile.score,
        "structure_sha256": structure_sha256,
        "launcher_candidates": [asdict(item) for item in launcher_candidates],
        "content_roots": [asdict(item) for item in content_roots],
        "platform_directories": platforms,
        "numbered_dat_structural_signature_sha256": (
            numbered_dat_profile.structural_signature_sha256 if numbered_dat_profile is not None else None
        ),
    }
    canonical = json.dumps(
        evidence_payload,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=False,
    ).encode("utf-8")
    profile_signature_sha256 = hashlib.sha256(canonical).hexdigest()

    return DeviceProfileCandidate(
        schema_version=10,
        candidate_id=f"dpv1-candidate-{profile_signature_sha256[:16]}",
        status="CANDIDATE",
        base_profile_id=profile.profile_id,
        base_profile_score=profile.score,
        launcher_resolution=resolution,
        launcher_path=top.path if top else None,
        launcher_format=top.format_name if top else None,
        launcher_confidence=top.confidence if top else "none",
        launcher_candidates=launcher_candidates,
        content_roots=content_roots,
        platform_directories=platforms,
        profile_signature_sha256=profile_signature_sha256,
        notes=notes,
    )
