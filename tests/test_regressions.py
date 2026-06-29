"""Regression tests for issues found in the adversarial code review."""

import os

from cachelint.analyzer import analyze
from cachelint.model import classify_copy, detect_dependency_install
from cachelint.parser import parse_dockerfile
from cachelint import render
from cachelint.model import Severity


def _analyze(src, context_dir, dockerignore=True, manifests=()):
    if dockerignore:
        (context_dir / ".dockerignore").write_text(".git\n")
    for name in manifests:
        (context_dir / name).write_text("{}\n")
    df = parse_dockerfile(src, path=str(context_dir / "Dockerfile"), context_dir=str(context_dir))
    return analyze(df)


def _ids(res):
    return {f.rule_id for f in res.findings}


# --- #1: manifests / dotfiles must not be classified as broad -----------------

def test_manifest_copies_are_not_broad():
    assert classify_copy(["Gemfile", "Gemfile.lock"]) == "manifest"
    assert classify_copy(["Pipfile", "Pipfile.lock"]) == "manifest"
    assert classify_copy([".npmrc"]) == "manifest"
    assert classify_copy(["package*.json"]) == "manifest"


def test_cl001_not_fired_on_canonical_manifest_first_pattern(tmp_path):
    src = ("FROM ruby:3\nWORKDIR /app\nCOPY Gemfile Gemfile.lock ./\n"
           "RUN bundle install\nCOPY . .\n")
    res = _analyze(src, tmp_path)
    assert "CL001" not in _ids(res)


def test_cl001_not_fired_on_pipenv_manifest_first(tmp_path):
    src = ("FROM python:3.12\nWORKDIR /app\nCOPY Pipfile Pipfile.lock ./\n"
           "RUN pipenv install --deploy\nCOPY . .\n")
    res = _analyze(src, tmp_path)
    assert "CL001" not in _ids(res)


# --- #3: yarn matcher must only match real installs ---------------------------

def test_yarn_non_install_subcommands_not_detected():
    for cmd in ["yarn --version", "yarn -v", "yarn config set x y",
                "yarn cache clean", "yarn why react", "yarn info", "yarn add foo"]:
        assert detect_dependency_install(cmd) is None, cmd


def test_yarn_installs_detected():
    assert detect_dependency_install("yarn")[0] == "node"
    assert detect_dependency_install("yarn install")[0] == "node"
    assert detect_dependency_install("yarn install --frozen-lockfile")[0] == "node"
    assert detect_dependency_install("yarn --immutable")[0] == "node"


# --- #4: `<<word` inside a quoted arg is not a heredoc ------------------------

def test_sed_with_angle_brackets_is_not_a_heredoc(tmp_path):
    src = ("FROM alpine\nRUN sed -i 's/<<PLACEHOLDER>>/value/g' /app/config\n"
           "COPY . /app\nRUN npm ci\n")
    df = parse_dockerfile(src, context_dir=str(tmp_path))
    kinds = [i.keyword for i in df.stages[0].instructions]
    assert kinds == ["RUN", "COPY", "RUN"]  # nothing was swallowed


def test_echo_with_angle_brackets_is_not_a_heredoc(tmp_path):
    src = 'FROM alpine\nRUN echo "usage: app <<input>>"\nCOPY a b\n'
    df = parse_dockerfile(src, context_dir=str(tmp_path))
    assert [i.keyword for i in df.stages[0].instructions] == ["RUN", "COPY"]


# --- #8: COPY heredoc body is not parsed as sources --------------------------

def test_copy_heredoc_body_not_classified_broad(tmp_path):
    src = ("# syntax=docker/dockerfile:1\nFROM alpine\nCOPY <<EOF /app/config.txt\n"
           "hello\nworld\nEOF\nRUN echo done\n")
    df = parse_dockerfile(src, context_dir=str(tmp_path))
    copy = [i for i in df.stages[0].instructions if i.keyword == "COPY"][0]
    assert copy.sources == []
    assert classify_copy(copy.sources) == "narrow"


# --- #9: plain <<EOF must not close on an indented delimiter line -------------

def test_plain_heredoc_not_closed_by_indented_delimiter(tmp_path):
    src = ("FROM alpine\nRUN <<EOF\necho hi\n    EOF\necho done\nEOF\nRUN npm ci\n")
    df = parse_dockerfile(src, context_dir=str(tmp_path))
    kinds = [i.keyword for i in df.stages[0].instructions]
    # The whole heredoc is one RUN, then the trailing RUN npm ci.
    assert kinds == ["RUN", "RUN"]


def test_dash_heredoc_closes_on_tab_indented_delimiter(tmp_path):
    src = "FROM alpine\nRUN <<-EOF\n\techo hi\n\tEOF\nCOPY a b\n"
    df = parse_dockerfile(src, context_dir=str(tmp_path))
    assert [i.keyword for i in df.stages[0].instructions] == ["RUN", "COPY"]


# --- #6: COPY --from is never the broad pivot --------------------------------

def test_copy_from_stage_not_treated_as_broad(tmp_path):
    src = ("FROM node:20 AS deps\nRUN npm ci\n"
           "FROM node:20\nWORKDIR /app\nCOPY package.json package-lock.json /app/\n"
           "RUN npm ci --omit=dev\nCOPY --from=deps /app/node_modules ./node_modules\n"
           "COPY . .\n")
    res = _analyze(src, tmp_path, manifests=("package.json", "package-lock.json"))
    # The cross-stage COPY must not trigger CL001 on the npm ci above it.
    cl001 = [f for f in res.findings if f.rule_id == "CL001"]
    assert cl001 == []


# --- #5 / #7: refuse to auto-fix when reordering is unsafe --------------------

def test_no_autofix_when_workdir_between_copy_and_install(tmp_path):
    src = "FROM python:3.12\nCOPY . /app\nWORKDIR /app\nRUN pip install -r requirements.txt\n"
    res = _analyze(src, tmp_path, manifests=("requirements.txt",))
    assert "CL001" in _ids(res)   # still reported
    assert res.fixes == {}        # but not auto-fixed (unsafe)


def test_no_autofix_when_setup_run_between(tmp_path):
    src = ("FROM python:3.12\nCOPY . .\nRUN ./scripts/build-deps.sh\n"
           "RUN pip install -r requirements.txt\n")
    res = _analyze(src, tmp_path, manifests=("requirements.txt",))
    assert "CL001" in _ids(res)
    assert res.fixes == {}


# --- #12: inline suppression also disables --fix -----------------------------

def test_suppressed_cl001_produces_no_fix(tmp_path):
    src = "FROM node:20\nWORKDIR /app\nCOPY . .\nRUN npm ci # cachelint:ignore=CL001\n"
    res = _analyze(src, tmp_path, manifests=("package.json", "package-lock.json"))
    assert "CL001" not in _ids(res)
    assert res.fixes == {}
    assert res.fixed_text is None


# --- #11: pretty output never raises on a non-UTF-8 stream -------------------

def test_ascii_only_render_has_no_unicode(tmp_path):
    src = "FROM node:20\nWORKDIR /app\nCOPY . .\nRUN npm ci\n"
    res = _analyze(src, tmp_path)
    out = render.render_pretty([res], color=False, fail_on=Severity.HIGH, ascii_only=True)
    out.encode("ascii")  # must not raise


def test_stream_ascii_detection():
    class FakeAscii:
        encoding = "ascii"

    class FakeUtf8:
        encoding = "utf-8"

    assert render.stream_is_ascii_only(FakeAscii()) is True
    assert render.stream_is_ascii_only(FakeUtf8()) is False
