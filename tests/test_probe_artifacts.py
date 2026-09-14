import csv
import json
import sqlite3

from gamestick.probe import _sanitized_error_fields, inspect_volume


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
    assert artifact.details["schema_object_counts"]["table"] == 1
    assert artifact.details["schema_object_counts"]["index"] == 1
    assert "game" in artifact.details["recognized_schema_terms"]
    assert "title" in artifact.details["recognized_column_terms"]
    assert "schema_objects" not in artifact.details
    assert "table_columns" not in artifact.details


def test_sqlite_column_names_are_exported_but_row_values_are_not(tmp_path):
    _make_layout(tmp_path)
    db = tmp_path / "cubegm" / "games.db"
    con = sqlite3.connect(db)
    con.execute("create table games(id integer primary key, title text, rom_path text, image text)")
    con.execute(
        "insert into games(title, rom_path, image) values (?, ?, ?)",
        ("Private Game Title", "Roms/FC/private.nes", "image/FC/private.png"),
    )
    con.commit()
    con.close()

    report = inspect_volume(tmp_path)
    artifact = next(a for a in report.candidate_artifacts if a.path.replace("\\", "/") == "cubegm/games.db")
    rendered = json.dumps(artifact.details)
    assert set(artifact.details["recognized_column_terms"]) >= {"id", "title", "rom", "path", "image"}
    assert "table_columns" not in artifact.details
    assert "Private Game Title" not in rendered
    assert "private.nes" not in rendered
    assert report.device_profile_candidate.launcher_resolution == "probable"
    assert report.device_profile_candidate.launcher_path.replace("\\", "/") == "cubegm/games.db"


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
    assert artifact.details["recognized_header_terms"] == ["id", "path", "rom", "title"]
    assert artifact.details["field_count"] == 3
    assert artifact.details["recognized_header_field_count"] == 3
    assert artifact.details["header_semantics_corroborated"] is True
    assert "header_fields" not in artifact.details
    assert "Secret Game Name" not in json.dumps(artifact.details)


def test_json_reports_derived_key_terms_not_raw_keys_or_values(tmp_path):
    _make_layout(tmp_path)
    path = tmp_path / "cubegm" / "settings.json"
    path.write_text(json.dumps({"launcher": "private-value", "version": 3}), encoding="utf-8")

    report = inspect_volume(tmp_path)
    artifact = next(a for a in report.candidate_artifacts if a.path.replace("\\", "/") == "cubegm/settings.json")
    assert artifact.format_name == "json"
    assert artifact.details["top_level_key_count"] == 2
    assert artifact.details["recognized_key_terms"] == ["launcher"]
    assert "top_level_keys" not in artifact.details
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


def test_probe_schema_v7_and_policy(tmp_path):
    _make_layout(tmp_path)
    report = inspect_volume(tmp_path)
    assert report.schema_version == 7
    assert report.probe_policy["device_write_paths_enabled"] is False
    assert report.probe_policy["raw_device_access_used"] is False
    assert report.probe_policy["rom_tree_recursive_scan"] is False
    assert report.probe_policy["device_profile_candidate_read_only"] is True
    assert report.probe_policy["device_profile_candidate_additional_filesystem_traversal"] is False
    assert report.device_profile_candidate is not None
    assert report.device_profile_candidate.schema_version == 3


def test_headerless_csv_does_not_export_first_data_row_or_create_semantic_evidence(tmp_path):
    _make_layout(tmp_path)
    csv_path = tmp_path / "cubegm" / "game.csv"
    csv_path.write_text(
        "1,Secret Game Name,Roms/FC/secret.nes,image/secret.png\n"
        "2,Other Game,Roms/FC/other.nes,image/other.png\n",
        encoding="utf-8",
    )

    report = inspect_volume(tmp_path)
    artifact = next(a for a in report.candidate_artifacts if a.path.replace("\\", "/") == "cubegm/game.csv")
    rendered = json.dumps(report.to_dict(), sort_keys=True)
    assert artifact.details["field_count"] == 4
    assert artifact.details["recognized_header_terms"] == []
    assert artifact.details["recognized_header_field_count"] == 0
    assert artifact.details["header_semantics_corroborated"] is False
    assert "header_fields" not in artifact.details
    assert "Secret Game Name" not in rendered
    assert "Roms/FC/secret.nes" not in rendered
    assert "image/secret.png" not in rendered
    assert report.device_profile_candidate.launcher_resolution == "candidate"
    assert report.device_profile_candidate.launcher_confidence != "high"


def test_headerless_csv_alias_like_first_data_row_cannot_become_probable(tmp_path):
    _make_layout(tmp_path)
    csv_path = tmp_path / "cubegm" / "game.csv"
    csv_path.write_text(
        "title,rom_path\n"
        "Other Game,Roms/FC/other.nes\n",
        encoding="utf-8",
    )
    report = inspect_volume(tmp_path)
    artifact = next(a for a in report.candidate_artifacts if a.path.replace("\\", "/") == "cubegm/game.csv")
    assert artifact.details["recognized_header_terms"] == ["path", "rom", "title"]
    assert artifact.details["header_semantics_corroborated"] is True
    assert report.device_profile_candidate.launcher_resolution == "candidate"
    assert report.device_profile_candidate.launcher_confidence == "medium"


def test_json_game_title_and_rom_path_keys_are_not_exported(tmp_path):
    _make_layout(tmp_path)
    path = tmp_path / "cubegm" / "games.json"
    path.write_text(
        json.dumps({
            "Secret Game Name": {"rom": "Roms/FC/secret.nes"},
            "Roms/FC/private.nes": {"title": "Private Game"},
        }),
        encoding="utf-8",
    )
    report = inspect_volume(tmp_path)
    artifact = next(a for a in report.candidate_artifacts if a.path.replace("\\", "/") == "cubegm/games.json")
    rendered = json.dumps(report.to_dict(), sort_keys=True)
    assert artifact.details["top_level_key_count"] == 2
    assert set(artifact.details["recognized_key_terms"]) >= {"rom", "title"}
    assert "top_level_keys" not in artifact.details
    assert "Secret Game Name" not in rendered
    assert "Roms/FC/private.nes" not in rendered
    assert "Private Game" not in rendered


def test_config_game_title_sections_and_rom_path_keys_are_not_exported(tmp_path):
    _make_layout(tmp_path)
    path = tmp_path / "cubegm" / "games.cfg"
    path.write_text(
        "[Secret Game Name]\n"
        "Roms/FC/private.nes=value\n"
        "[launcher]\n"
        "rom_path=Roms/FC/secret.nes\n",
        encoding="utf-8",
    )
    report = inspect_volume(tmp_path)
    artifact = next(a for a in report.candidate_artifacts if a.path.replace("\\", "/") == "cubegm/games.cfg")
    rendered = json.dumps(report.to_dict(), sort_keys=True)
    assert artifact.details["sampled_section_count"] == 2
    assert artifact.details["sampled_key_count"] == 2
    assert artifact.details["recognized_section_terms"] == ["launcher"]
    assert set(artifact.details["recognized_key_terms"]) >= {"rom", "path"}
    assert "sections" not in artifact.details
    assert "key_names" not in artifact.details
    assert "Secret Game Name" not in rendered
    assert "Roms/FC/private.nes" not in rendered
    assert "Roms/FC/secret.nes" not in rendered


def test_sqlite_arbitrary_schema_names_are_not_exported(tmp_path):
    _make_layout(tmp_path)
    db = tmp_path / "cubegm" / "games.db"
    con = sqlite3.connect(db)
    con.execute('create table "Secret Game Name" ("Roms/FC/private.nes" text, title text)')
    con.commit()
    con.close()
    report = inspect_volume(tmp_path)
    rendered = json.dumps(report.to_dict(), sort_keys=True)
    assert "Secret Game Name" not in rendered
    assert "Roms/FC/private.nes" not in rendered
    artifact = next(a for a in report.candidate_artifacts if a.path.replace("\\", "/") == "cubegm/games.db")
    assert "title" in artifact.details["recognized_column_terms"]


def test_xml_arbitrary_root_name_is_not_exported(tmp_path):
    _make_layout(tmp_path)
    path = tmp_path / "cubegm" / "games.xml"
    path.write_text("<SecretGameName><rom>hidden</rom></SecretGameName>", encoding="utf-8")
    report = inspect_volume(tmp_path)
    rendered = json.dumps(report.to_dict(), sort_keys=True)
    assert "SecretGameName" not in rendered
    artifact = next(a for a in report.candidate_artifacts if a.path.replace("\\", "/") == "cubegm/games.xml")
    assert artifact.details["root_element_present"] is True


def test_malformed_sqlite_error_does_not_export_media_controlled_schema_name(tmp_path):
    _make_layout(tmp_path)
    db = tmp_path / "cubegm" / "games.db"
    con = sqlite3.connect(db)
    con.execute("create table x(a)")
    con.commit()
    con.execute("pragma writable_schema=ON")
    con.execute(
        "update sqlite_master set name='Secret Game Name', "
        "tbl_name='Secret Game Name', "
        "sql='CREATE TABLE \"Secret Game Name\"(' where name='x'"
    )
    con.commit()
    con.close()

    report = inspect_volume(tmp_path)
    artifact = next(a for a in report.candidate_artifacts if a.path.replace("\\", "/") == "cubegm/games.db")
    rendered = json.dumps(report.to_dict(), sort_keys=True)

    assert artifact.details["schema_read_error"] is True
    assert artifact.details["schema_read_error_type"] == "DatabaseError"
    assert artifact.details["schema_read_error_code_name"] == "SQLITE_CORRUPT"
    assert "Secret Game Name" not in rendered
    assert "malformed database schema" not in rendered


def test_xml_doctype_element_like_text_cannot_spoof_root_semantics(tmp_path):
    _make_layout(tmp_path)
    path = tmp_path / "cubegm" / "gamelist.xml"
    path.write_text(
        '<?xml version="1.0"?>\n'
        '<!DOCTYPE root [\n'
        '<!ENTITY bait "<games>">\n'
        ']>\n'
        '<root><item/></root>\n',
        encoding="utf-8",
    )

    report = inspect_volume(tmp_path)
    artifact = next(a for a in report.candidate_artifacts if a.path.replace("\\", "/") == "cubegm/gamelist.xml")

    assert artifact.details["root_element_present"] is True
    assert artifact.details["recognized_root_terms"] == []
    assert artifact.details["xml_root_parser"] == "elementtree-first-start"
    assert report.device_profile_candidate.launcher_resolution == "candidate"
    assert report.device_profile_candidate.launcher_confidence == "medium"
    assert report.device_profile_candidate.launcher_candidates[0].score == 74


def test_malformed_json_error_is_sanitized_in_serialized_evidence(tmp_path):
    _make_layout(tmp_path)
    path = tmp_path / "cubegm" / "games.json"
    path.write_text('{"Secret Game Name": ', encoding="utf-8")

    report = inspect_volume(tmp_path)
    artifact = next(a for a in report.candidate_artifacts if a.path.replace("\\", "/") == "cubegm/games.json")
    rendered = json.dumps(report.to_dict(), sort_keys=True)

    assert artifact.details["analysis_error"] is True
    assert artifact.details["analysis_error_type"] == "JSONDecodeError"
    assert isinstance(artifact.details["analysis_error_line"], int)
    assert isinstance(artifact.details["analysis_error_column"], int)
    assert "Secret Game Name" not in rendered


def test_sanitized_error_helper_never_serializes_raw_exception_text():
    details = _sanitized_error_fields("analysis_error", RuntimeError("Secret Game Name / Roms/FC/private.nes"))
    rendered = json.dumps(details, sort_keys=True)
    assert details == {"analysis_error": True, "analysis_error_type": "RuntimeError"}
    assert "Secret Game Name" not in rendered
    assert "private.nes" not in rendered
