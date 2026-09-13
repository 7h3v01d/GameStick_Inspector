from gamestick.probe import inspect_volume


def test_probe_is_read_only_and_finds_metadata(tmp_path):
    for name in ("Roms", "cubegm", "image"):
        (tmp_path / name).mkdir()
    config = tmp_path / "cubegm" / "games.db"
    config.write_bytes(b"not-a-real-db")
    before = sorted(str(p.relative_to(tmp_path)) for p in tmp_path.rglob("*"))

    report = inspect_volume(tmp_path)

    after = sorted(str(p.relative_to(tmp_path)) for p in tmp_path.rglob("*"))
    assert before == after
    assert report.profile.profile_id == "observed_cubegm_layout"
    assert any(a.path.replace("\\", "/") == "cubegm/games.db" for a in report.candidate_artifacts)
    assert len(report.structure_sha256) == 64
