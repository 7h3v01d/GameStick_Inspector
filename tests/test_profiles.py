from gamestick.profiles import best_profile, profile_matches


def test_observed_cubegm_profile_wins(tmp_path):
    for name in ("Roms", "cubegm", "image"):
        (tmp_path / name).mkdir()
    match = best_profile(tmp_path)
    assert match.profile_id == "observed_cubegm_layout"
    assert match.score >= 90
    assert match.confidence == "high"


def test_profile_matching_is_case_insensitive(tmp_path):
    for name in ("ROMS", "CubeGM", "IMAGE"):
        (tmp_path / name).mkdir()
    match = best_profile(tmp_path)
    assert match.profile_id == "observed_cubegm_layout"
    assert match.confidence == "high"


def test_all_profile_candidates_are_reportable(tmp_path):
    for name in ("Roms", "cubegm", "image"):
        (tmp_path / name).mkdir()
    matches = profile_matches(tmp_path)
    assert matches[0].profile_id == "observed_cubegm_layout"
    assert len(matches) >= 3


def test_unknown_layout(tmp_path):
    (tmp_path / "photos").mkdir()
    match = best_profile(tmp_path)
    assert match.profile_id == "unknown"
