import json

from cachelint.analyzer import analyze
from cachelint.model import Severity
from cachelint.parser import parse_dockerfile
from cachelint import render


def _result(tmp_path):
    (tmp_path / ".dockerignore").write_text(".git\n")
    src = "FROM node:20\nWORKDIR /app\nCOPY . .\nRUN npm ci\n"
    df = parse_dockerfile(src, path=str(tmp_path / "Dockerfile"), context_dir=str(tmp_path))
    return analyze(df, gitstats=None)


def test_summarize_counts(tmp_path):
    res = _result(tmp_path)
    s = render.summarize([res])
    assert s["high"] >= 1
    assert s["findings"] == len(res.findings)


def test_pretty_no_ansi_when_color_off(tmp_path):
    out = render.render_pretty([_result(tmp_path)], color=False, fail_on=Severity.HIGH)
    assert "\033[" not in out
    assert "CL001" in out
    assert "HIGH" in out
    assert "suggested fix:" in out


def test_pretty_has_ansi_when_color_on(tmp_path):
    out = render.render_pretty([_result(tmp_path)], color=True, fail_on=Severity.HIGH)
    assert "\033[" in out


def test_json_is_valid_and_complete(tmp_path):
    out = render.render_json([_result(tmp_path)], fail_on=Severity.HIGH)
    data = json.loads(out)
    assert data["tool"] == "cachelint"
    assert data["summary"]["high"] >= 1
    assert data["results"][0]["findings"][0]["rule"] == "CL001"


def test_sarif_is_valid(tmp_path):
    out = render.render_sarif([_result(tmp_path)])
    data = json.loads(out)
    assert data["version"] == "2.1.0"
    run = data["runs"][0]
    assert run["tool"]["driver"]["name"] == "cachelint"
    assert run["results"][0]["ruleId"] == "CL001"
    assert run["results"][0]["level"] == "error"


def test_clean_pretty_reports_success(tmp_path):
    (tmp_path / ".dockerignore").write_text(".git\n")
    src = "FROM alpine:3.19\nCMD [\"sh\"]\n"
    df = parse_dockerfile(src, path=str(tmp_path / "Dockerfile"), context_dir=str(tmp_path))
    out = render.render_pretty([analyze(df)], color=False, fail_on=Severity.HIGH)
    assert "no cache problems found" in out
    assert "passing" in out
