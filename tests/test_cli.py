import json
import os

from cachelint import cli


def _write(tmp_path, name, content, ignore=True):
    p = tmp_path / name
    p.write_text(content)
    if ignore:
        (tmp_path / ".dockerignore").write_text(".git\n")
    return str(p)


BAD = "FROM node:20\nWORKDIR /app\nCOPY . .\nRUN npm ci\n"
CLEAN = "FROM alpine:3.19\nCMD [\"sh\"]\n"


def test_exit_1_on_high_finding(tmp_path, capsys):
    path = _write(tmp_path, "Dockerfile", BAD)
    rc = cli.run([path, "--no-git"])
    assert rc == 1
    assert "CL001" in capsys.readouterr().out


def test_exit_0_on_clean(tmp_path, capsys):
    path = _write(tmp_path, "Dockerfile", CLEAN)
    rc = cli.run([path, "--no-git"])
    assert rc == 0


def test_fail_on_none_never_fails(tmp_path):
    path = _write(tmp_path, "Dockerfile", BAD)
    assert cli.run([path, "--no-git", "--fail-on", "none"]) == 0


def test_json_format(tmp_path, capsys):
    path = _write(tmp_path, "Dockerfile", BAD)
    cli.run([path, "--no-git", "--format", "json"])
    data = json.loads(capsys.readouterr().out)
    assert data["results"][0]["findings"][0]["rule"] == "CL001"


def test_sarif_format(tmp_path, capsys):
    path = _write(tmp_path, "Dockerfile", BAD)
    cli.run([path, "--no-git", "--format", "sarif"])
    data = json.loads(capsys.readouterr().out)
    assert data["version"] == "2.1.0"


def test_missing_file_is_error(tmp_path, capsys):
    rc = cli.run([str(tmp_path / "nope.Dockerfile"), "--no-git"])
    assert rc == 2
    assert "cannot read" in capsys.readouterr().err


def test_no_dockerfile_in_cwd_is_error(tmp_path, monkeypatch, capsys):
    monkeypatch.chdir(tmp_path)
    rc = cli.run(["--no-git"])
    assert rc == 2
    assert "no Dockerfile found" in capsys.readouterr().err


def test_directory_target_resolves_dockerfile(tmp_path, capsys):
    _write(tmp_path, "Dockerfile", BAD)
    rc = cli.run([str(tmp_path), "--no-git"])
    assert rc == 1


def test_fix_writes_backup_and_rewrites(tmp_path, capsys):
    (tmp_path / "package.json").write_text("{}")
    (tmp_path / "package-lock.json").write_text("{}")
    path = _write(tmp_path, "Dockerfile", BAD)
    rc = cli.run([path, "--no-git", "--fix"])
    assert os.path.isfile(path + ".bak")
    fixed = open(path).read()
    assert fixed.index("npm ci") < fixed.index("COPY . .")
    original = open(path + ".bak").read()
    assert original == BAD
    capsys.readouterr()  # drain output from the --fix run
    # After fixing, a re-run should be clean of CL001.
    rc2 = cli.run([path, "--no-git", "--format", "json"])
    data = json.loads(capsys.readouterr().out)
    rules = {f["rule"] for f in data["results"][0]["findings"]}
    assert "CL001" not in rules


def test_version_flag(capsys):
    import pytest
    with pytest.raises(SystemExit) as exc:
        cli.run(["--version"])
    assert exc.value.code == 0
    assert "cachelint" in capsys.readouterr().out
