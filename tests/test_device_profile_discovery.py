import json
import os
from pathlib import Path
import subprocess
import sys

from gamestick.discovery import build_device_profile_candidate, rank_launcher_candidates
from gamestick.models import CandidateArtifact, DirectorySnapshot, ProfileMatch


def _profile():
    return ProfileMatch(
        profile_id="observed_cubegm_layout",
        display_name="Observed GameStick layout",
        score=90,
        confidence="high",
        matched_markers=["Roms", "cubegm", "image"],
        missing_markers=[],
    )


def test_games_sqlite_with_game_schema_ranks_high():
    artifact = CandidateArtifact(
        path="cubegm/games.db",
        kind="launcher/database/config candidate",
        size=4096,
        sha256="a" * 64,
        format_name="sqlite3",
        details={
            "schema_object_counts": {"table": 2, "index": 1},
            "recognized_schema_terms": ["game", "system", "rom", "path"],
            "recognized_column_terms": ["id", "title", "rom", "path"],
        },
    )
    ranked = rank_launcher_candidates([artifact])
    assert len(ranked) == 1
    assert ranked[0].path == "cubegm/games.db"
    assert ranked[0].confidence == "high"
    assert ranked[0].score >= 75
    assert "launcher-index" in ranked[0].role_hints
    assert "path-map" in ranked[0].role_hints


def test_plain_settings_json_without_launcher_semantics_is_not_promoted():
    artifact = CandidateArtifact(
        path="cubegm/settings.json",
        kind="launcher/database/config candidate",
        size=100,
        format_name="json",
        details={"top_level_key_count": 3, "recognized_key_terms": []},
    )
    assert rank_launcher_candidates([artifact]) == []


def test_uncorroborated_games_sqlite_cannot_be_probable():
    artifact = CandidateArtifact(
        path="cubegm/games.db",
        kind="launcher/database/config candidate",
        size=4096,
        format_name="sqlite3",
        details={"schema_object_counts": {"table": 1}, "recognized_schema_terms": [], "recognized_column_terms": []},
    )
    ranked = rank_launcher_candidates([artifact])
    assert len(ranked) == 1
    assert ranked[0].score == 74
    assert ranked[0].confidence == "medium"
    candidate = build_device_profile_candidate(
        profile=_profile(),
        structure_sha256="0" * 64,
        artifacts=[artifact],
        snapshots=[],
    )
    assert candidate.launcher_resolution == "candidate"


def test_content_roots_and_platform_directories_are_derived_from_existing_snapshots():
    snapshots = [
        DirectorySnapshot(
            path="Roms",
            directory_names=["FC", "SFC", "PS1"],
            file_extension_counts={".nes": 10},
            entries_sampled=13,
            file_names_redacted=True,
        ),
        DirectorySnapshot(path="image", directory_names=["FC", "SFC"], entries_sampled=2),
        DirectorySnapshot(path="cubegm", directory_names=[], entries_sampled=1),
    ]
    candidate = build_device_profile_candidate(
        profile=_profile(),
        structure_sha256="b" * 64,
        artifacts=[],
        snapshots=snapshots,
    )
    roles = {item.path: item.role for item in candidate.content_roots}
    assert roles["Roms"] == "rom-library"
    assert roles["image"] == "artwork-library"
    assert roles["cubegm"] == "launcher-system"
    assert candidate.platform_directories == ["FC", "PS1", "SFC"]
    assert candidate.launcher_resolution == "unresolved"


def test_device_profile_candidate_is_deterministic():
    artifact = CandidateArtifact(
        path="cubegm/game.csv",
        kind="launcher/database/config candidate",
        size=80,
        sha256="c" * 64,
        format_name="csv",
        details={"recognized_header_terms": ["id", "title", "rom", "path", "image"], "header_semantics_corroborated": True},
    )
    kwargs = dict(
        profile=_profile(),
        structure_sha256="d" * 64,
        artifacts=[artifact],
        snapshots=[DirectorySnapshot(path="Roms", directory_names=["FC"], file_names_redacted=True)],
    )
    first = build_device_profile_candidate(**kwargs)
    second = build_device_profile_candidate(**kwargs)
    assert first == second
    assert first.schema_version == 3
    assert first.candidate_id.startswith("dpv1-candidate-")
    assert len(first.profile_signature_sha256) == 64
    assert first.launcher_path == "cubegm/game.csv"
    assert first.launcher_format == "csv"


def test_profile_signature_deterministic_across_hash_seeds_with_case_collisions():
    root = Path(__file__).resolve().parents[1]
    code = r'''
import json
from gamestick.discovery import build_device_profile_candidate
from gamestick.models import DirectorySnapshot, ProfileMatch
profile = ProfileMatch("p", "P", 90, "high", [], [])
c = build_device_profile_candidate(
    profile=profile,
    structure_sha256="a"*64,
    artifacts=[],
    snapshots=[DirectorySnapshot(path="Roms", directory_names=list({"FC", "fc", "PS1"}), file_names_redacted=True)],
)
print(json.dumps({"id": c.candidate_id, "sig": c.profile_signature_sha256, "platforms": c.platform_directories}))
'''
    outputs = []
    for seed in ("1", "2", "77", "999"):
        env = os.environ.copy()
        env["PYTHONHASHSEED"] = seed
        env["PYTHONPATH"] = str(root / "src")
        completed = subprocess.run(
            [sys.executable, "-c", code],
            cwd=root,
            env=env,
            check=True,
            capture_output=True,
            text=True,
        )
        outputs.append(json.loads(completed.stdout))
    assert all(item == outputs[0] for item in outputs[1:])
    assert outputs[0]["platforms"] == ["FC", "fc", "PS1"]


def test_device_profile_candidate_contains_no_csv_data_values():
    artifact = CandidateArtifact(
        path="cubegm/game.csv",
        kind="launcher/database/config candidate",
        size=80,
        format_name="csv",
        details={"recognized_header_terms": ["id", "title", "rom", "path"], "header_semantics_corroborated": True},
    )
    candidate = build_device_profile_candidate(
        profile=_profile(),
        structure_sha256="e" * 64,
        artifacts=[artifact],
        snapshots=[],
    )
    rendered = repr(candidate)
    assert "Secret Game Name" not in rendered
    assert "Roms/FC/secret.nes" not in rendered


def test_csv_structural_terms_cannot_independently_elevate_probable():
    artifact = CandidateArtifact(
        path="cubegm/game.csv",
        kind="launcher/database/config candidate",
        size=80,
        format_name="csv",
        details={
            "recognized_header_terms": ["title", "rom", "path"],
            "header_semantics_corroborated": True,
        },
    )
    ranked = rank_launcher_candidates([artifact])
    assert len(ranked) == 1
    assert ranked[0].score == 74
    assert ranked[0].confidence == "medium"
    assert any("heuristic-only" in item for item in ranked[0].evidence)
    candidate = build_device_profile_candidate(
        profile=_profile(),
        structure_sha256="f" * 64,
        artifacts=[artifact],
        snapshots=[],
    )
    assert candidate.launcher_resolution == "candidate"
    assert any("heuristic score 74/100" in note for note in candidate.notes)
