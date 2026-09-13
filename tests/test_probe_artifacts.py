import csv
import json
import sqlite3

from gamestick.probe import inspect_volume


def _make_layout(root):
    for name in ("Roms", "cubegm", "image"):
        (root / name).mkdir()


def test_sqlite_schema_is_discovered_read_only(tmp_path):
    _make_layout(tmp_path)
    db = tmp_path / "cubegm" / "games.db"
    con = sqlite3.connect(db)
    con.execute("create table games(id integer primary key, title text)")
    con.execute("create index idx_games_title on games(title)")
    con.commit()
    con.close()
    before = db.read_bytes()

    report = inspect_volume(tmp_path)

    after = db.read_bytes()
    assert before == after
    artifact = next(a for a in report.candidate_artifacts if a.path.replace("\\", "/") == "cubegm/games.db")
    assert artifact.format_name == "sqlite3"
    assert "games" in artifact.details["schema_objects"]["table"]
    assert "idx_games_title" in artifact.details["schema_objects"]["index"]


def test_csv_header_is_reported_without_data_rows(tmp_path):
    _make_layout(tmp_path)
    csv_path = tmp_path / "cubegm" / "game.csv"
    with csv_path.open("w", encoding="utf-8", newline="") as handle:
        writer = csv.writer(handle)
        writer.writerow(["id", "title", "rom_path"])
        writer.writerow(["1", "Secret Game Name", "Roms/FC/secret.nes"])

    report = inspect_volume(tmp_path)
    artifact = next(a for a in report.candidate_artifacts if a.path.replace("\\", "/") == "cubegm/game.csv")
    assert artifact.format_name == "csv"
    assert artifact.details["header_fields"] == ["id", "title", "rom_path"]
    assert "Secret Game Name" not in json.dumps(artifact.details)


def test_json_reports_keys_not_values(tmp_path):
    _make_layout(tmp_path)
    path = tmp_path / "cubegm" / "settings.json"
    path.write_text(json.dumps({"launcher": "private-value", "version": 3}), encoding="utf-8")

    report = inspect_volume(tmp_path)
    artifact = next(a for a in report.candidate_artifacts if a.path.replace("\\", "/") == "cubegm/settings.json")
    assert artifact.format_name == "json"
    assert artifact.details["top_level_keys"] == ["launcher", "version"]
    assert "private-value" not in json.dumps(artifact.details)


def test_rom_root_snapshot_redacts_file_names_but_keeps_platform_dirs(tmp_path):
    _make_layout(tmp_path)
    (tmp_path / "Roms" / "FC").mkdir()
    (tmp_path / "Roms" / "SFC").mkdir()
    (tmp_path / "Roms" / "do-not-export.nes").write_bytes(b"rom")

    report = inspect_volume(tmp_path)
    snapshot = next(s for s in report.directory_snapshots if s.path.casefold() == "roms")
    assert snapshot.file_names_redacted is True
    assert snapshot.file_names == []
    assert snapshot.directory_names == ["FC", "SFC"]
    assert snapshot.file_extension_counts[".nes"] == 1


def test_probe_schema_v2_and_policy(tmp_path):
    _make_layout(tmp_path)
    report = inspect_volume(tmp_path)
    assert report.schema_version == 3
    assert report.probe_policy["device_write_paths_enabled"] is False
    assert report.probe_policy["raw_device_access_used"] is False
    assert report.probe_policy["rom_tree_recursive_scan"] is False
