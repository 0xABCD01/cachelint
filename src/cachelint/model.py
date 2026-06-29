"""Core domain types and Docker cache-classification knowledge.

This module holds the *facts* about Dockerfiles that the analyzer reasons over:
how Docker's layer cache behaves, which RUN commands are dependency
installations (and therefore cacheable on a manifest), which COPY/ADD
instructions are "broad" (and therefore invalidate the cache on almost every
commit), and which files are dependency manifests for each ecosystem.

Keeping this knowledge in one place makes the rules in ``analyzer.py`` short and
auditable, and makes the catalog easy for the community to extend.
"""

from __future__ import annotations

import enum
import fnmatch
import os
import re
from dataclasses import dataclass, field
from typing import List, Optional, Tuple


class Severity(enum.IntEnum):
    """Ordered severity levels. Higher is worse; comparable with ``>=``."""

    NONE = 0
    LOW = 1
    MEDIUM = 2
    HIGH = 3

    @classmethod
    def parse(cls, name: str) -> "Severity":
        try:
            return cls[name.strip().upper()]
        except KeyError:  # pragma: no cover - guarded by argparse choices
            raise ValueError(f"unknown severity: {name!r}")

    def __str__(self) -> str:  # nicer rendering than "Severity.HIGH"
        return self.name.lower()


# --------------------------------------------------------------------------- #
# Parsed Dockerfile structure
# --------------------------------------------------------------------------- #


@dataclass
class Instruction:
    """A single logical Dockerfile instruction (continuations already joined)."""

    keyword: str  # uppercased, e.g. "RUN", "COPY", "FROM"
    args: str  # argument text with line continuations collapsed to spaces
    raw: str  # original source text block (verbatim, including newlines)
    start_line: int  # 1-based line of the first physical line
    end_line: int  # 1-based line of the last physical line
    flags: dict = field(default_factory=dict)  # parsed --flags (e.g. from, mount)
    sources: List[str] = field(default_factory=list)  # COPY/ADD source paths
    dest: Optional[str] = None  # COPY/ADD destination
    suppressed_rules: set = field(default_factory=set)  # from inline # cachelint:ignore

    @property
    def is_copy_like(self) -> bool:
        return self.keyword in ("COPY", "ADD")


@dataclass
class Stage:
    """A build stage: everything from one ``FROM`` up to the next."""

    index: int
    base: str  # image reference in FROM
    name: Optional[str]  # AS <name>, if any
    from_instruction: Instruction
    instructions: List[Instruction] = field(default_factory=list)  # excludes FROM


@dataclass
class Dockerfile:
    path: str
    escape: str
    syntax: Optional[str]
    stages: List[Stage]
    pre_from: List[Instruction]  # global ARGs/comments before the first FROM
    all_instructions: List[Instruction]
    source: str  # full original text
    context_dir: str  # directory used as the build context (for manifest/.dockerignore checks)


# --------------------------------------------------------------------------- #
# Findings
# --------------------------------------------------------------------------- #


@dataclass
class Finding:
    rule_id: str
    severity: Severity
    title: str
    message: str
    path: str
    line: int
    end_line: int
    related_lines: List[int] = field(default_factory=list)
    suggestion: Optional[str] = None
    est_waste_seconds: int = 0
    stage_index: Optional[int] = None  # set for stage-scoped rules (e.g. CL001)

    def to_dict(self) -> dict:
        return {
            "rule": self.rule_id,
            "severity": str(self.severity),
            "title": self.title,
            "message": self.message,
            "path": self.path,
            "line": self.line,
            "endLine": self.end_line,
            "relatedLines": self.related_lines,
            "suggestion": self.suggestion,
            "estWasteSeconds": self.est_waste_seconds,
        }


# --------------------------------------------------------------------------- #
# Dependency-install knowledge
# --------------------------------------------------------------------------- #

# A dependency *installation/resolution* command: its result depends only on the
# project's manifest files, never on application source. These are the commands
# that should run *before* a broad ``COPY . .`` so their (expensive) layer stays
# cached across code changes. Build/compile commands (go build, npm run build,
# cargo build, make, mvn package) are deliberately excluded: they legitimately
# need the full source, so flagging them would be a false positive.
#
# Each entry: (compiled regex, ecosystem key, typical seconds wasted per build).
_DEP_INSTALL_RULES: List[Tuple["re.Pattern[str]", str, int]] = [
    (re.compile(r"\bnpm\s+ci\b"), "node", 35),
    # bare `npm install` / `npm i` (project install) but not `npm install -g foo`.
    # (A `\b` before `-g` fails because `-` is non-word, so anchor on whitespace.)
    (re.compile(r"\bnpm\s+(install|i)\b(?![^\n|&;]*\s(?:-g|--global)(?:\s|$))"), "node", 35),
    (re.compile(r"\bpnpm\s+(install|i)\b"), "node", 35),
    (re.compile(r"\bbun\s+install\b"), "node", 20),
    # yarn: only bare `yarn` (end of command) / `yarn install` / `yarn` with a
    # known install flag is a project install. Everything else (yarn --version,
    # config, cache, why, info, list, run/add/global/exec/dlx, node) installs
    # nothing and must not match.
    (re.compile(
        r"\byarn(?:\s+install\b"
        r"|\s*(?:$|[|&;])"
        r"|\s+--(?:frozen-lockfile|immutable|immutable-cache|production|prod"
        r"|prefer-offline|ignore-scripts|non-interactive|check-files|silent)\b)"
    ), "node", 35),
    (re.compile(r"\bpip3?\s+install\b"), "python", 45),
    (re.compile(r"\bpython[0-9.]*\s+-m\s+pip\s+install\b"), "python", 45),
    (re.compile(r"\bpoetry\s+install\b"), "python", 50),
    (re.compile(r"\bpipenv\s+install\b"), "python", 50),
    (re.compile(r"\buv\s+(pip\s+)?(install|sync)\b"), "python", 25),
    (re.compile(r"\bgo\s+mod\s+download\b"), "go", 25),
    (re.compile(r"\bgo\s+get\b"), "go", 25),
    (re.compile(r"\bcargo\s+fetch\b"), "rust", 40),
    (re.compile(r"\bbundle\s+install\b"), "ruby", 40),
    (re.compile(r"\bcomposer\s+(install|update)\b"), "php", 35),
    (re.compile(r"\bmvn\b[^\n]*\bdependency:(go-offline|resolve)\b"), "java", 60),
    (re.compile(r"\b(\./)?gradlew?\b[^\n]*\b(dependencies|resolveDependencies)\b"), "java", 60),
    (re.compile(r"\bdotnet\s+restore\b"), "dotnet", 40),
    (re.compile(r"\bnuget\s+restore\b"), "dotnet", 40),
    (re.compile(r"\bmix\s+deps\.get\b"), "elixir", 30),
    (re.compile(r"\b(?:conda|mamba|micromamba)\s+env\s+(?:create|update)\b"), "conda", 70),
    (re.compile(r"\bpnpm\s+fetch\b"), "node", 30),
    (re.compile(r"\b(?:flutter|dart)\s+pub\s+get\b"), "dart", 30),
    (re.compile(r"\bswift\s+package\s+resolve\b"), "swift", 45),
    (re.compile(r"\bshards\s+install\b"), "crystal", 25),
    (re.compile(r"\bPkg\.instantiate\b"), "julia", 45),
    (re.compile(r"\b(?:lein\s+deps|(?:clojure|clj)\b[^\n|&;]*\s-P)\b"), "clojure", 35),
    (re.compile(r"\b(?:cpanm\b[^\n|&;]*--installdeps|carton\s+install)\b"), "perl", 30),
    (re.compile(r"\b(?:stack|cabal)\b[^\n|&;]*--(?:only-dependencies|dependencies-only)\b"), "haskell", 90),
    (re.compile(r"\bcabal\s+update\b"), "haskell", 30),
    (re.compile(r"\bsbt\s+update\b"), "scala", 60),
    (re.compile(r"\brenv::restore\b"), "r", 40),
    (re.compile(r"\bpdm\s+(?:install|sync)\b"), "python", 40),
    (re.compile(r"\bpip-sync\b"), "python", 40),
    (re.compile(r"\bnimble\s+install\b"), "nim", 30),
    (re.compile(r"\bgleam\s+deps\s+download\b"), "gleam", 25),
    (re.compile(r"\bopam\b[^\n|&;]*--deps-only\b"), "ocaml", 60),
    (re.compile(r"\brebar3\s+get-deps\b"), "erlang", 35),
    (re.compile(r"\bconan\s+install\b"), "cpp", 50),
    (re.compile(r"\bvcpkg\s+install\b"), "cpp", 50),
    # System package managers: never depend on app source, must come early.
    (re.compile(r"\bapt(?:-get)?\s+install\b"), "apt", 20),
    (re.compile(r"\baptitude\s+install\b"), "apt", 20),
    (re.compile(r"\bapk\s+add\b"), "apk", 15),
    (re.compile(r"\b(?:yum|dnf|microdnf)\s+install\b"), "rpm", 20),
    # zypper's -n/--non-interactive is a global option that precedes the
    # subcommand and is needed in nearly every Docker build, so allow flags
    # between `zypper` and install/in (still rejects info/search/update).
    (re.compile(r"\bzypper\b[^\n|&;]*\s(?:install|in)\b"), "zypper", 20),
    (re.compile(r"\bpacman\s+-S(?:yy?u?)?\b"), "pacman", 20),
]

# Ecosystems whose installs are reproducible from manifests copied beforehand.
LANGUAGE_ECOSYSTEMS = {"node", "python", "go", "rust", "ruby", "php", "java",
                       "dotnet", "elixir", "conda", "dart", "swift", "crystal",
                       "julia", "clojure", "perl", "haskell", "scala", "r",
                       "nim", "gleam", "ocaml", "erlang", "cpp"}
SYSTEM_ECOSYSTEMS = {"apt", "apk", "rpm", "zypper", "pacman"}

# Manifest filename patterns per ecosystem, ordered by preference. The first
# group are the files Docker should COPY before installing.
MANIFESTS = {
    "node": ["package.json", "package-lock.json", "npm-shrinkwrap.json",
             "yarn.lock", "pnpm-lock.yaml", ".npmrc", "bun.lockb"],
    "python": ["requirements.txt", "requirements*.txt", "pyproject.toml",
               "poetry.lock", "Pipfile", "Pipfile.lock", "setup.py",
               "setup.cfg", "uv.lock", "pdm.lock", "constraints.txt"],
    "go": ["go.mod", "go.sum"],
    "rust": ["Cargo.toml", "Cargo.lock"],
    "ruby": ["Gemfile", "Gemfile.lock", ".ruby-version"],
    "php": ["composer.json", "composer.lock"],
    "java": ["pom.xml", "build.gradle", "build.gradle.kts", "settings.gradle",
             "settings.gradle.kts", "gradle.lockfile"],
    "dotnet": ["*.csproj", "*.fsproj", "*.vbproj", "*.sln", "packages.config",
               "nuget.config", "Directory.Packages.props", "Directory.Build.props",
               "global.json"],
    "elixir": ["mix.exs", "mix.lock"],
    "conda": ["environment.yml", "environment.yaml", "conda-lock.yml"],
    "dart": ["pubspec.yaml", "pubspec.lock"],
    "swift": ["Package.swift", "Package.resolved"],
    "crystal": ["shard.yml", "shard.lock"],
    "julia": ["Project.toml", "Manifest.toml", "JuliaProject.toml", "JuliaManifest.toml"],
    "clojure": ["deps.edn", "project.clj", "bb.edn", "shadow-cljs.edn"],
    "perl": ["cpanfile", "cpanfile.snapshot"],
    "haskell": ["*.cabal", "cabal.project", "cabal.project.freeze",
                "stack.yaml", "stack.yaml.lock", "package.yaml"],
    "scala": ["build.sbt", "build.properties", "plugins.sbt"],
    "r": ["renv.lock", "DESCRIPTION"],
    "nim": ["*.nimble", "nimble.lock"],
    "gleam": ["gleam.toml", "manifest.toml"],
    "ocaml": ["*.opam", "dune-project", "opam.locked"],
    "erlang": ["rebar.config", "rebar.lock"],
    "cpp": ["conanfile.txt", "conanfile.py", "conan.lock", "vcpkg.json",
            "vcpkg-configuration.json"],
}

# Flat set of all manifest patterns, for "is this COPY just manifests?" checks.
_ALL_MANIFEST_PATTERNS = sorted({p for pats in MANIFESTS.values() for p in pats})


def detect_dependency_install(run_args: str) -> Optional[Tuple[str, int]]:
    """Return ``(ecosystem, est_seconds)`` if ``run_args`` installs dependencies.

    Returns ``None`` for build/compile commands and everything else.
    """
    for pattern, ecosystem, seconds in _DEP_INSTALL_RULES:
        if pattern.search(run_args):
            return ecosystem, seconds
    return None


def uses_cache_mount(instruction: Instruction) -> bool:
    """True if a RUN uses BuildKit ``--mount=type=cache`` (mitigates re-fetch)."""
    mounts = instruction.flags.get("mount", [])
    if isinstance(mounts, str):
        mounts = [mounts]
    return any("type=cache" in m for m in mounts)


# --------------------------------------------------------------------------- #
# COPY/ADD classification
# --------------------------------------------------------------------------- #

CopyKind = str  # one of: "broad", "manifest", "narrow"

# Bare directory names that, when copied, bring in a whole source tree. Used only
# as a fallback for tokens without a trailing slash or extension. Kept conservative
# so a lone manifest/config filename is never mistaken for a directory.
KNOWN_SOURCE_DIRS = {
    "src", "app", "lib", "source", "sources", "cmd", "internal", "pkg",
    "server", "client", "web", "frontend", "backend", "code", "apps", "packages",
}


def _clean(src: str) -> str:
    return src.strip().strip('"').strip("'")


def is_manifest_source(src: str) -> bool:
    """True if a COPY source refers only to dependency manifest file(s)."""
    base = os.path.basename(_clean(src).rstrip("/"))
    if not base:
        return False
    if any(fnmatch.fnmatch(base, pat) for pat in _ALL_MANIFEST_PATTERNS):
        return True
    # The source may itself be a glob that matches a concrete manifest filename,
    # e.g. `COPY package*.json ./` covers package.json / package-lock.json.
    if any(ch in base for ch in "*?["):
        concrete = [p for p in _ALL_MANIFEST_PATTERNS if not any(c in p for c in "*?[")]
        if any(fnmatch.fnmatch(name, base) for name in concrete):
            return True
    return False


def _is_broad_source(src: str) -> bool:
    """A source that pulls in (most of) the build context or a whole directory."""
    s = _clean(src)
    if is_manifest_source(s):
        return False  # dependency manifests are never the cache-busting broad copy
    had_trailing_slash = s.endswith("/")
    core = s.rstrip("/")
    if core in ("", ".", "*", "./.", "*/*"):
        return True
    if core.endswith("/*") or core.endswith("/."):
        return True
    if had_trailing_slash:
        return True  # an explicit directory copy (e.g. "src/")
    if "*" in core:
        return True  # a glob over (non-manifest) files behaves like a broad copy
    base = os.path.basename(core)
    if base in KNOWN_SOURCE_DIRS:
        return True
    return False


def classify_copy(sources: List[str]) -> CopyKind:
    """Classify a COPY/ADD by how often its cache key is likely to change.

    - ``broad``    : copies the whole context or a source tree (changes most commits)
    - ``manifest`` : copies only dependency manifests (changes rarely)
    - ``narrow``   : copies a few specific files
    """
    if not sources:
        return "narrow"
    if any(_is_broad_source(s) for s in sources):
        return "broad"
    if all(is_manifest_source(s) for s in sources):
        return "manifest"
    return "narrow"


def manifest_ecosystems(sources: List[str]) -> set:
    """Which ecosystems' manifests appear among these COPY sources."""
    found = set()
    for src in sources:
        base = os.path.basename(src.rstrip("/"))
        for eco, pats in MANIFESTS.items():
            if any(fnmatch.fnmatch(base, pat) for pat in pats):
                found.add(eco)
    return found
