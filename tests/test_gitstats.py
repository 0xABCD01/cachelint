from cachelint.gitstats import GitStats, _parse_log, collect


def test_parse_log_counts_commits_and_paths():
    # Two commits: first touches a.py & b.py, second touches a.py.
    out = "\x00a.py\nb.py\n\x00a.py\n"
    gs = _parse_log(out)
    assert gs.total_commits == 2
    assert gs.commits_with_changes == 2
    assert abs(gs.volatility("a.py") - 1.0) < 1e-9
    assert abs(gs.volatility("b.py") - 0.5) < 1e-9


def test_parse_log_handles_empty_commit():
    # Middle commit has no files (e.g. an empty/merge commit): its record is a
    # lone separator line.
    out = "\x00a.py\n\x00\n\x00b.py\n"
    gs = _parse_log(out)
    assert gs.total_commits == 3
    assert gs.commits_with_changes == 2


def test_volatility_directory_prefix():
    out = "\x00src/app.js\n\x00src/util.js\n\x00README.md\n"
    gs = _parse_log(out)
    assert abs(gs.volatility("src") - (2 / 3)) < 1e-9


def test_volatility_whole_context():
    out = "\x00a.py\n\x00b.py\n"
    gs = _parse_log(out)
    assert abs(gs.volatility(".") - 1.0) < 1e-9


def test_collect_on_non_repo_returns_empty(tmp_path):
    gs = collect(str(tmp_path), enabled=True)
    assert not gs.available
    assert gs.volatility(".") is None


def test_disabled_returns_empty(tmp_path):
    gs = collect(str(tmp_path), enabled=False)
    assert not gs.available
