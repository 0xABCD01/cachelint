"""Tests for the rules added after the initial release (CL006, CL007) and for
end-to-end behavior of the new ecosystems."""

import os

from cachelint.analyzer import analyze
from cachelint.model import Severity
from cachelint.parser import parse_dockerfile


def _analyze(src, context_dir, dockerignore=True, files=()):
    if dockerignore:
        (context_dir / ".dockerignore").write_text(".git\n")
    for name in files:
        (context_dir / name).write_text("x\n")
    df = parse_dockerfile(src, path=str(context_dir / "Dockerfile"), context_dir=str(context_dir))
    return analyze(df)


def _ids(res):
    return {f.rule_id for f in res.findings}


# --- CL006: mutable base tag --------------------------------------------------

def test_cl006_flags_latest(tmp_path):
    res = _analyze("FROM node:latest\nCMD [\"node\"]\n", tmp_path)
    cl006 = [f for f in res.findings if f.rule_id == "CL006"]
    assert cl006 and cl006[0].severity is Severity.MEDIUM
    assert "latest" in cl006[0].message


def test_cl006_flags_untagged(tmp_path):
    res = _analyze("FROM ubuntu\nCMD [\"bash\"]\n", tmp_path)
    assert "CL006" in _ids(res)


def test_cl006_ok_for_pinned_tag(tmp_path):
    res = _analyze("FROM node:20.11-slim\nCMD [\"node\"]\n", tmp_path)
    assert "CL006" not in _ids(res)


def test_cl006_ok_for_digest(tmp_path):
    res = _analyze("FROM node@sha256:abc123\nCMD [\"node\"]\n", tmp_path)
    assert "CL006" not in _ids(res)


def test_cl006_ok_for_uppercase_digest(tmp_path):
    res = _analyze("FROM node@SHA256:" + "0" * 64 + "\nCMD [\"node\"]\n", tmp_path)
    assert "CL006" not in _ids(res)


def test_cl006_ok_for_scratch(tmp_path):
    res = _analyze("FROM scratch\nCOPY app /app\n", tmp_path)
    assert "CL006" not in _ids(res)


def test_cl006_skips_stage_reference(tmp_path):
    src = "FROM golang:1.22 AS build\nRUN go build\nFROM build\nCMD [\"/app\"]\n"
    res = _analyze(src, tmp_path)
    # only the real base (golang:1.22, pinned) matters; "FROM build" is a stage ref
    assert "CL006" not in _ids(res)


def test_cl006_skips_arg_templated_tag(tmp_path):
    src = "ARG TAG=20\nFROM node:${TAG}\nCMD [\"node\"]\n"
    res = _analyze(src, tmp_path)
    assert "CL006" not in _ids(res)


def test_cl006_registry_port_not_confused(tmp_path):
    # host:5000/app:1.2 is pinned; the ":5000" is a port, not a tag.
    res = _analyze("FROM registry.local:5000/app:1.2\nCMD [\"x\"]\n", tmp_path)
    assert "CL006" not in _ids(res)


# --- CL007: volatile metadata before a cached layer --------------------------

def test_cl007_flags_build_date_before_install(tmp_path):
    src = ("FROM node:20\nWORKDIR /app\nARG BUILD_DATE\n"
           "COPY package.json ./\nRUN npm ci\n")
    res = _analyze(src, tmp_path, files=("package.json",))
    cl007 = [f for f in res.findings if f.rule_id == "CL007"]
    assert cl007 and cl007[0].severity is Severity.LOW
    assert cl007[0].line == 3


def test_cl007_flags_env_commit_sha(tmp_path):
    src = ("FROM python:3.12\nENV GIT_COMMIT=abc\nCOPY requirements.txt ./\n"
           "RUN pip install -r requirements.txt\n")
    res = _analyze(src, tmp_path, files=("requirements.txt",))
    assert "CL007" in _ids(res)


def test_cl007_not_flagged_after_install(tmp_path):
    src = ("FROM node:20\nCOPY package.json ./\nRUN npm ci\nARG BUILD_DATE\nCOPY . .\n")
    res = _analyze(src, tmp_path, files=("package.json",))
    assert "CL007" not in _ids(res)


def test_cl007_not_flagged_without_install(tmp_path):
    src = "FROM node:20\nARG BUILD_DATE\nCOPY . .\n"
    res = _analyze(src, tmp_path)
    assert "CL007" not in _ids(res)


def test_cl007_ignores_normal_args(tmp_path):
    src = ("FROM node:20\nARG NODE_ENV=production\nCOPY package.json ./\nRUN npm ci\n")
    res = _analyze(src, tmp_path, files=("package.json",))
    assert "CL007" not in _ids(res)


def test_cl007_legacy_env_form_detects_real_name(tmp_path):
    # Legacy "ENV KEY VALUE": BUILD_DATE is the variable -> must flag.
    src = "FROM node:20\nENV BUILD_DATE 2024-01-01\nCOPY package.json ./\nRUN npm ci\n"
    res = _analyze(src, tmp_path, files=("package.json",))
    assert "CL007" in _ids(res)


def test_cl007_legacy_env_value_with_equals_not_misparsed(tmp_path):
    # "ENV JAVA_OPTS -Dx=y": the var is JAVA_OPTS (not "-Dx") -> must NOT flag.
    src = "FROM node:20\nENV JAVA_OPTS -Dx=y\nCOPY package.json ./\nRUN npm ci\n"
    res = _analyze(src, tmp_path, files=("package.json",))
    assert "CL007" not in _ids(res)


def test_cl007_legacy_env_config_not_false_positive(tmp_path):
    # "ENV CONFIG COMMIT=abc" is legacy form: var is CONFIG, value "COMMIT=abc".
    src = "FROM node:20\nENV CONFIG COMMIT=abc\nCOPY package.json ./\nRUN npm ci\n"
    res = _analyze(src, tmp_path, files=("package.json",))
    assert "CL007" not in _ids(res)


# --- CL008: ADD instead of COPY ----------------------------------------------

def test_cl008_flags_add_local_file(tmp_path):
    res = _analyze("FROM alpine:3.19\nADD app.py /app/app.py\n", tmp_path)
    cl008 = [f for f in res.findings if f.rule_id == "CL008"]
    assert cl008 and cl008[0].severity is Severity.LOW


def test_cl008_ok_for_remote_url(tmp_path):
    res = _analyze("FROM alpine:3.19\nADD https://example.com/x.bin /x.bin\n", tmp_path)
    assert "CL008" not in _ids(res)


def test_cl008_ok_for_local_archive(tmp_path):
    res = _analyze("FROM alpine:3.19\nADD release.tar.gz /opt/\n", tmp_path)
    assert "CL008" not in _ids(res)


def test_cl008_not_for_copy(tmp_path):
    res = _analyze("FROM alpine:3.19\nCOPY app.py /app/app.py\n", tmp_path)
    assert "CL008" not in _ids(res)


# --- CL009: package upgrade --------------------------------------------------

def test_cl009_flags_apt_upgrade(tmp_path):
    res = _analyze("FROM debian:12\nRUN apt-get update && apt-get upgrade -y\n", tmp_path)
    assert "CL009" in _ids(res)


def test_cl009_flags_apk_upgrade(tmp_path):
    res = _analyze("FROM alpine:3.19\nRUN apk upgrade\n", tmp_path)
    assert "CL009" in _ids(res)


def test_cl002_defers_to_cl009_when_upgrade_present(tmp_path):
    # `apt-get update && apt-get upgrade` is CL009, not a CL002 (update-only) finding.
    res = _analyze("FROM debian:12\nRUN apt-get update && apt-get upgrade -y\n", tmp_path)
    assert "CL009" in _ids(res)
    assert "CL002" not in _ids(res)


def test_cl009_absent_for_plain_install(tmp_path):
    src = "FROM debian:12\nRUN apt-get update && apt-get install -y curl && rm -rf /var/lib/apt/lists/*\n"
    res = _analyze(src, tmp_path)
    assert "CL009" not in _ids(res)


# --- CL010: pip --no-cache-dir -----------------------------------------------

def test_cl010_flags_pip_without_no_cache_dir(tmp_path):
    src = "FROM python:3.12\nCOPY requirements.txt ./\nRUN pip install -r requirements.txt\n"
    res = _analyze(src, tmp_path, files=("requirements.txt",))
    cl010 = [f for f in res.findings if f.rule_id == "CL010"]
    assert cl010 and cl010[0].severity is Severity.LOW


def test_cl010_ok_with_no_cache_dir(tmp_path):
    src = ("FROM python:3.12\nCOPY requirements.txt ./\n"
           "RUN pip install --no-cache-dir -r requirements.txt\n")
    res = _analyze(src, tmp_path, files=("requirements.txt",))
    assert "CL010" not in _ids(res)


def test_cl010_ok_with_cache_mount(tmp_path):
    src = ("FROM python:3.12\nCOPY requirements.txt ./\n"
           "RUN --mount=type=cache,target=/root/.cache/pip pip install -r requirements.txt\n")
    res = _analyze(src, tmp_path, files=("requirements.txt",))
    assert "CL010" not in _ids(res)


def test_cl004_does_not_double_with_cl010_on_pip(tmp_path):
    # A well-placed pip install without a mount: CL010 owns it, CL004 must not also fire.
    src = "FROM python:3.12\nCOPY requirements.txt ./\nRUN pip install -r requirements.txt\nCOPY . .\n"
    res = _analyze(src, tmp_path, files=("requirements.txt",))
    ids = _ids(res)
    assert "CL010" in ids
    assert "CL004" not in ids


# --- New ecosystems end-to-end (CL001 + auto-fix) ----------------------------

def test_dotnet_cl001_and_autofix(tmp_path):
    (tmp_path / "App.csproj").write_text("<Project/>\n")
    src = "FROM mcr.microsoft.com/dotnet/sdk:8.0\nWORKDIR /src\nCOPY . .\nRUN dotnet restore\n"
    res = _analyze(src, tmp_path)
    assert "CL001" in _ids(res)
    assert res.fixes  # App.csproj detected on disk -> safe auto-fix
    assert "App.csproj" in res.fixed_text


def test_elixir_cl001(tmp_path):
    (tmp_path / "mix.exs").write_text("defmodule X\n")
    (tmp_path / "mix.lock").write_text("%{}\n")
    src = "FROM elixir:1.16\nWORKDIR /app\nCOPY . .\nRUN mix deps.get\n"
    res = _analyze(src, tmp_path)
    assert "CL001" in _ids(res)
    assert "mix.exs" in res.fixed_text


def test_conda_cl001(tmp_path):
    (tmp_path / "environment.yml").write_text("name: app\n")
    src = ("FROM continuumio/miniconda3\nWORKDIR /app\nCOPY . .\n"
           "RUN conda env create -f environment.yml\n")
    res = _analyze(src, tmp_path)
    assert "CL001" in _ids(res)
    assert "environment.yml" in res.fixed_text
