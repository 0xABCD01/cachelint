import os

from cachelint.analyzer import analyze
from cachelint.model import Severity
from cachelint.parser import parse_dockerfile


def _analyze(src, context_dir, add_dockerignore=False):
    if add_dockerignore:
        with open(os.path.join(context_dir, ".dockerignore"), "w") as fh:
            fh.write(".git\n")
    df = parse_dockerfile(src, path=os.path.join(context_dir, "Dockerfile"),
                          context_dir=str(context_dir))
    return analyze(df, gitstats=None)


def _ids(result):
    return {f.rule_id for f in result.findings}


def test_cl001_fires_for_install_after_broad_copy(tmp_path):
    src = "FROM node:20\nWORKDIR /app\nCOPY . .\nRUN npm ci\n"
    res = _analyze(src, tmp_path, add_dockerignore=True)
    cl001 = [f for f in res.findings if f.rule_id == "CL001"]
    assert len(cl001) == 1
    assert cl001[0].severity is Severity.HIGH
    assert cl001[0].est_waste_seconds > 0
    # primary points at the install, broad copy is related
    assert cl001[0].line == 4
    assert 3 in cl001[0].related_lines


def test_cl001_not_fired_when_install_before_copy(tmp_path):
    src = ("FROM node:20\nWORKDIR /app\nCOPY package.json package-lock.json ./\n"
           "RUN npm ci\nCOPY . .\nRUN npm run build\n")
    res = _analyze(src, tmp_path, add_dockerignore=True)
    assert "CL001" not in _ids(res)


def test_cl001_not_fired_for_build_step_after_copy(tmp_path):
    # go build needs the source; copying source before it is correct.
    src = "FROM golang\nWORKDIR /app\nCOPY . .\nRUN go build -o app .\n"
    res = _analyze(src, tmp_path, add_dockerignore=True)
    assert "CL001" not in _ids(res)


def test_cl001_medium_when_cache_mount_used(tmp_path):
    src = ("FROM node:20\nWORKDIR /app\nCOPY . .\n"
           "RUN --mount=type=cache,target=/root/.npm npm ci\n")
    res = _analyze(src, tmp_path, add_dockerignore=True)
    cl001 = [f for f in res.findings if f.rule_id == "CL001"]
    assert cl001 and cl001[0].severity is Severity.MEDIUM


def test_cl001_attaches_fix(tmp_path):
    (tmp_path / "package.json").write_text("{}")
    (tmp_path / "package-lock.json").write_text("{}")
    src = "FROM node:20\nWORKDIR /app\nCOPY . .\nRUN npm ci\n"
    res = _analyze(src, tmp_path, add_dockerignore=True)
    assert res.fixes  # a reordering was produced
    fixed = res.fixed_text
    # In the fixed file, npm ci comes before the broad COPY . .
    assert fixed.index("npm ci") < fixed.index("COPY . .")


def test_cl001_no_autofix_when_manifest_absent_but_finding_still_reported(tmp_path):
    # No package.json on disk: the finding must still fire, but no unsafe auto-fix.
    src = "FROM node:20\nWORKDIR /app\nCOPY . .\nRUN npm ci\n"
    res = _analyze(src, tmp_path, add_dockerignore=True)
    assert "CL001" in _ids(res)
    assert res.fixes == {}
    assert res.fixed_text is None


def test_cl002_apt_update_split(tmp_path):
    src = "FROM ubuntu\nRUN apt-get update\nRUN apt-get install -y curl\n"
    res = _analyze(src, tmp_path, add_dockerignore=True)
    cl002 = [f for f in res.findings if f.rule_id == "CL002"]
    assert cl002 and cl002[0].severity is Severity.MEDIUM
    assert cl002[0].line == 2


def test_cl002_not_fired_when_combined(tmp_path):
    src = "FROM ubuntu\nRUN apt-get update && apt-get install -y curl && rm -rf /var/lib/apt/lists/*\n"
    res = _analyze(src, tmp_path, add_dockerignore=True)
    assert "CL002" not in _ids(res)


def test_cl003_missing_dockerignore(tmp_path):
    src = "FROM node:20\nCOPY . .\n"
    res = _analyze(src, tmp_path, add_dockerignore=False)
    assert "CL003" in _ids(res)


def test_cl003_absent_when_dockerignore_present(tmp_path):
    src = "FROM node:20\nCOPY . .\n"
    res = _analyze(src, tmp_path, add_dockerignore=True)
    assert "CL003" not in _ids(res)


def test_cl004_cache_mount_suggested_for_well_placed_install(tmp_path):
    src = ("FROM node:20\nWORKDIR /app\nCOPY package.json ./\nRUN npm ci\nCOPY . .\n")
    res = _analyze(src, tmp_path, add_dockerignore=True)
    assert "CL004" in _ids(res)


def test_cl004_absent_when_mount_present(tmp_path):
    src = ("FROM node:20\nCOPY package.json ./\n"
           "RUN --mount=type=cache,target=/root/.npm npm ci\nCOPY . .\n")
    res = _analyze(src, tmp_path, add_dockerignore=True)
    assert "CL004" not in _ids(res)


def test_cl005_apt_install_without_cleanup(tmp_path):
    src = "FROM ubuntu\nRUN apt-get update && apt-get install -y curl\n"
    res = _analyze(src, tmp_path, add_dockerignore=True)
    assert "CL005" in _ids(res)


def test_cl005_absent_with_cleanup(tmp_path):
    src = ("FROM ubuntu\nRUN apt-get update && apt-get install -y curl "
           "&& rm -rf /var/lib/apt/lists/*\n")
    res = _analyze(src, tmp_path, add_dockerignore=True)
    assert "CL005" not in _ids(res)


def test_inline_suppression(tmp_path):
    src = "FROM node:20\nCOPY . .\nRUN npm ci # cachelint:ignore=CL001\n"
    res = _analyze(src, tmp_path, add_dockerignore=True)
    assert "CL001" not in _ids(res)


def test_clean_dockerfile_has_no_findings(tmp_path):
    (tmp_path / ".dockerignore").write_text(".git\n")
    (tmp_path / "package.json").write_text("{}\n")
    src = ("# syntax=docker/dockerfile:1\nFROM node:20-slim AS build\nWORKDIR /app\n"
           "COPY package.json package-lock.json ./\n"
           "RUN --mount=type=cache,target=/root/.npm npm ci\n"
           "COPY . .\nRUN npm run build\n")
    df = parse_dockerfile(src, path=str(tmp_path / "Dockerfile"), context_dir=str(tmp_path))
    res = analyze(df, gitstats=None)
    assert res.findings == []


def test_git_volatility_note_in_message(tmp_path):
    from cachelint.gitstats import GitStats
    src = "FROM node:20\nCOPY . .\nRUN npm ci\n"
    df = parse_dockerfile(src, path=str(tmp_path / "Dockerfile"), context_dir=str(tmp_path))
    gs = GitStats(total_commits=100, commits_with_changes=90, changes_by_path={"a.js": 90})
    res = analyze(df, gitstats=gs)
    cl001 = [f for f in res.findings if f.rule_id == "CL001"][0]
    assert "% of recent commits" in cl001.message
