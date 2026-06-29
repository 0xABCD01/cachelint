"""The rule engine: turns a parsed Dockerfile into cache findings.

Rules (stable IDs so they can be referenced in CI configs and suppressions):

* CL001 broad-copy-before-install  (HIGH)   - the flagship: a dependency install
  runs *after* a broad ``COPY . .``, so its expensive layer is rebuilt on every
  code change.
* CL002 apt-update-not-combined    (MEDIUM) - ``apt-get update`` in its own layer
  leads to stale package indexes once that layer is cached.
* CL003 missing-dockerignore       (MEDIUM) - ``COPY . .`` with no ``.dockerignore``
  drags ``.git``/``node_modules``/build output into the context and busts cache.
* CL004 cache-mount-suggested      (LOW)    - a well-placed install that could be
  sped up further with BuildKit ``--mount=type=cache``.
* CL005 package-cache-not-cleaned  (LOW)    - system installs that leave package
  index files behind, bloating the layer.
* CL006 mutable-base-tag           (MEDIUM) - ``FROM`` on ``:latest`` / untagged:
  the base layer and everything after it rebuild when the tag moves upstream.
* CL007 volatile-metadata-early    (LOW)    - a build-date / commit-SHA ARG or ENV
  declared before the dependency install, invalidating it on every build.
* CL008 add-instead-of-copy        (LOW)    - ``ADD`` of a plain local file/dir,
  which has surprising extraction/URL-cache semantics; prefer ``COPY``.
* CL009 package-upgrade            (LOW)    - a distribution-wide package upgrade,
  which makes the layer non-deterministic.
* CL010 pip-no-cache-dir           (LOW)    - ``pip install`` without
  ``--no-cache-dir`` (and no cache mount) keeps the pip cache in the layer.
"""

from __future__ import annotations

import os
import re
import shlex
from dataclasses import dataclass, field
from typing import Dict, List, Optional

from . import optimizer
from .gitstats import GitStats
from .model import (
    LANGUAGE_ECOSYSTEMS,
    Dockerfile,
    Finding,
    Instruction,
    Severity,
    Stage,
    classify_copy,
    detect_dependency_install,
    uses_cache_mount,
)

_APT_UPDATE_RE = re.compile(r"\bapt(?:-get)?\s+update\b")
_APT_INSTALL_RE = re.compile(r"\bapt(?:-get)?\s+install\b")
_APT_CLEAN_RE = re.compile(r"rm\s+-rf\s+/var/lib/apt/lists")
_APK_ADD_RE = re.compile(r"\bapk\s+add\b")
_APK_NOCACHE_RE = re.compile(r"\bapk\s+add\b[^\n|&;]*--no-cache|--update-cache")
_YUM_INSTALL_RE = re.compile(r"\b(?:yum|dnf|microdnf)\s+install\b")
_YUM_CLEAN_RE = re.compile(r"\b(?:yum|dnf|microdnf)\s+clean\s+all\b")

# Names that signal volatile, per-build values (timestamps, commit hashes, cache
# busters). When declared before a cached layer they invalidate it every build.
_CACHEBUST_NAME_RE = re.compile(
    r"^(?:BUILD_?DATE|BUILD_?TIME(?:STAMP)?|BUILD_?NUMBER|BUILD_?ID"
    r"|VCS_?REF|VCS_?REVISION|GIT_?SHA|GIT_?REV|GIT_?REF|GIT_?COMMIT"
    r"|COMMIT_?SHA|COMMIT|SOURCE_DATE_EPOCH|CACHE_?BUST(?:ER)?"
    r"|CI_COMMIT_[A-Z0-9_]+|TIMESTAMP|EPOCH)$",
    re.IGNORECASE,
)

# A full package upgrade makes the layer non-deterministic.
_PKG_UPGRADE_RE = re.compile(
    r"\b(?:apt-get|apt)\s+(?:upgrade|dist-upgrade)\b"
    r"|\bapk\s+upgrade\b"
    r"|\b(?:yum|dnf|microdnf)\s+(?:upgrade|update)\b"
    r"|\bzypper\s+(?:update|up|dup|dist-upgrade)\b"
)

# ADD is appropriate for remote URLs and local archives (which it auto-extracts);
# for plain files/dirs, COPY is clearer and cache-predictable.
_URL_RE = re.compile(r"^(?:https?|ftp|ssh|git|git\+https?)://|^git@")
_ARCHIVE_EXTS = (".tar", ".tar.gz", ".tgz", ".gz", ".bz2", ".tbz2", ".tar.bz2",
                 ".xz", ".tar.xz", ".txz", ".zip", ".tar.zst", ".tzst", ".tar.z")

# pip-specific install (gets a dedicated --no-cache-dir rule; see CL010).
_PIP_INSTALL_RE = re.compile(r"\bpip3?\s+install\b|\bpython[0-9.]*\s+-m\s+pip\s+install\b")
_NO_CACHE_DIR_RE = re.compile(r"--no-cache-dir\b")


@dataclass
class AnalysisResult:
    path: str
    dockerfile: Dockerfile
    findings: List[Finding] = field(default_factory=list)
    fixes: Dict[int, List[str]] = field(default_factory=dict)

    @property
    def fixed_text(self) -> Optional[str]:
        if not self.fixes:
            return None
        return optimizer.regenerate_file(self.dockerfile, self.fixes)


def analyze(dockerfile: Dockerfile, gitstats: Optional[GitStats] = None) -> AnalysisResult:
    result = AnalysisResult(path=dockerfile.path, dockerfile=dockerfile)
    findings: List[Finding] = []

    for stage in dockerfile.stages:
        findings.extend(_rule_broad_copy_before_install(dockerfile, stage, gitstats, result))
        findings.extend(_rule_apt_update_split(dockerfile, stage))
        findings.extend(_rule_cache_mount(dockerfile, stage, result))
        findings.extend(_rule_package_cache_cleanup(dockerfile, stage))
        findings.extend(_rule_volatile_metadata(dockerfile, stage))
        findings.extend(_rule_package_upgrade(dockerfile, stage))
        findings.extend(_rule_add_instead_of_copy(dockerfile, stage))
        findings.extend(_rule_pip_no_cache(dockerfile, stage))

    findings.extend(_rule_missing_dockerignore(dockerfile))
    findings.extend(_rule_mutable_base_tag(dockerfile))

    # Apply inline suppressions and sort by file position.
    findings = [f for f in findings if not _is_suppressed(dockerfile, f)]
    findings.sort(key=lambda f: (f.line, _SEV_ORDER.index(f.severity)))
    result.findings = findings

    # Drop auto-fixes for stages whose CL001 finding was suppressed, so --fix
    # never rewrites a file the user explicitly silenced.
    live_fix_stages = {f.stage_index for f in findings if f.rule_id == "CL001"}
    result.fixes = {idx: body for idx, body in result.fixes.items() if idx in live_fix_stages}
    return result


_SEV_ORDER = [Severity.HIGH, Severity.MEDIUM, Severity.LOW, Severity.NONE]


# --------------------------------------------------------------------------- #
# Rules
# --------------------------------------------------------------------------- #


def _first_broad_copy(stage: Stage) -> Optional[int]:
    for idx, ins in enumerate(stage.instructions):
        # A cross-stage copy (COPY --from=...) is not context-dependent, so it is
        # never the cache-busting "broad" copy and must not be the reorder pivot.
        if ins.is_copy_like and not ins.flags.get("from") and classify_copy(ins.sources) == "broad":
            return idx
    return None


def _rule_broad_copy_before_install(
    dockerfile: Dockerfile, stage: Stage, gitstats: Optional[GitStats],
    result: AnalysisResult,
) -> List[Finding]:
    b = _first_broad_copy(stage)
    if b is None:
        return []
    broad_copy = stage.instructions[b]

    offending: List[Instruction] = []
    total_seconds = 0
    mitigated = True
    for ins in stage.instructions[b + 1:]:
        if ins.keyword != "RUN":
            continue
        info = detect_dependency_install(ins.args)
        if info is None:
            continue
        _, seconds = info
        offending.append(ins)
        total_seconds += seconds
        if not uses_cache_mount(ins):
            mitigated = False

    if not offending:
        return []

    # Build the canonical reordering for this stage, but only when it is safe.
    body = optimizer.try_reorder(stage, broad_copy, offending, dockerfile.context_dir)
    if body is not None:
        result.fixes[stage.index] = body
        suggestion = optimizer.render_stage(stage.from_instruction.raw, body)
    else:
        suggestion = (
            "Copy only the dependency manifests first, run the install, then COPY "
            "the rest of the source so the install layer stays cached. (Auto-fix "
            "skipped here: there are setup steps between the COPY and the install, "
            "or the manifest files were not found in the build context -- reorder "
            "manually.)"
        )

    severity = Severity.MEDIUM if mitigated else Severity.HIGH
    primary = offending[0]
    related = [broad_copy.start_line] + [i.start_line for i in offending[1:]]

    vol_note = ""
    if gitstats is not None and gitstats.available:
        vols = [gitstats.volatility(s) for s in broad_copy.sources]
        vols = [v for v in vols if v is not None]
        if vols:
            pct = int(round(max(vols) * 100))
            vol_note = (f" Git history shows the copied paths change in ~{pct}% "
                        f"of recent commits, so this layer rebuilds that often.")

    verb = "already uses a cache mount but is still mis-ordered" if mitigated else "rebuilds on every code change"
    msg = (
        f"The broad '{broad_copy.keyword} {_short(broad_copy.args)}' on line "
        f"{broad_copy.start_line} happens before the dependency install on line "
        f"{primary.start_line}. Because any change to the copied files invalidates "
        f"every later layer, the install {verb}."
        f"{vol_note} Copy only the dependency manifests first, install, then copy "
        f"the rest of the source."
    )

    return [Finding(
        rule_id="CL001",
        severity=severity,
        title="Dependency install runs after a broad COPY",
        message=msg,
        path=dockerfile.path,
        line=primary.start_line,
        end_line=primary.end_line,
        related_lines=related,
        suggestion=suggestion,
        est_waste_seconds=total_seconds,
        stage_index=stage.index,
    )]


def _rule_apt_update_split(dockerfile: Dockerfile, stage: Stage) -> List[Finding]:
    out: List[Finding] = []
    for ins in stage.instructions:
        if ins.keyword != "RUN":
            continue
        if (_APT_UPDATE_RE.search(ins.args)
                and not _APT_INSTALL_RE.search(ins.args)
                and not _PKG_UPGRADE_RE.search(ins.args)):
            out.append(Finding(
                rule_id="CL002",
                severity=Severity.MEDIUM,
                title="apt-get update is not combined with install",
                message=(
                    "'apt-get update' runs in its own layer. Once cached, later "
                    "'apt-get install' layers reuse a stale package index and can "
                    "install outdated or missing packages. Combine them in a single "
                    "RUN: 'apt-get update && apt-get install -y --no-install-recommends ...'."
                ),
                path=dockerfile.path,
                line=ins.start_line,
                end_line=ins.end_line,
            ))
    return out


def _rule_missing_dockerignore(dockerfile: Dockerfile) -> List[Finding]:
    has_ignore = os.path.isfile(os.path.join(dockerfile.context_dir, ".dockerignore"))
    if has_ignore:
        return []
    for stage in dockerfile.stages:
        for ins in stage.instructions:
            if ins.is_copy_like and not ins.flags.get("from") and any(
                s.strip().strip('"').strip("'").rstrip("/") in (".", "") for s in ins.sources
            ):
                return [Finding(
                    rule_id="CL003",
                    severity=Severity.MEDIUM,
                    title="No .dockerignore next to a 'COPY . .'",
                    message=(
                        "This build copies the whole context but no .dockerignore "
                        "was found. Files like .git, node_modules, and build output "
                        "are sent to the daemon and become part of the cache key, so "
                        "the COPY layer busts whenever any of them change. Add a "
                        ".dockerignore excluding them."
                    ),
                    path=dockerfile.path,
                    line=ins.start_line,
                    end_line=ins.end_line,
                )]
    return []


def _rule_cache_mount(dockerfile: Dockerfile, stage: Stage, result: AnalysisResult) -> List[Finding]:
    # Only suggest cache mounts for installs placed *before* the broad copy;
    # installs after it are CL001's domain (avoid stacking two findings on one line).
    out: List[Finding] = []
    b = _first_broad_copy(stage)
    for idx, ins in enumerate(stage.instructions):
        if ins.keyword != "RUN":
            continue
        info = detect_dependency_install(ins.args)
        if info is None:
            continue
        eco = info[0]
        if eco not in LANGUAGE_ECOSYSTEMS:
            continue
        if uses_cache_mount(ins):
            continue
        # pip has its own dedicated rule (CL010, --no-cache-dir); don't double up.
        if _PIP_INSTALL_RE.search(ins.args):
            continue
        # Skip installs that are after a broad copy (those are CL001's domain).
        if b is not None and idx > b:
            continue
        out.append(Finding(
            rule_id="CL004",
            severity=Severity.LOW,
            title="Dependency install could use a BuildKit cache mount",
            message=(
                "Adding '--mount=type=cache' lets the package manager reuse its "
                "download cache across builds, so even a cache miss on this layer "
                "stays fast. Example: "
                "'RUN --mount=type=cache,target=/root/.cache ...'. Requires the "
                "BuildKit builder (default in modern Docker)."
            ),
            path=dockerfile.path,
            line=ins.start_line,
            end_line=ins.end_line,
        ))
    return out


def _rule_package_cache_cleanup(dockerfile: Dockerfile, stage: Stage) -> List[Finding]:
    out: List[Finding] = []
    for ins in stage.instructions:
        if ins.keyword != "RUN":
            continue
        args = ins.args
        problem = None
        if _APT_INSTALL_RE.search(args) and not _APT_CLEAN_RE.search(args):
            problem = ("apt", "'&& rm -rf /var/lib/apt/lists/*'")
        elif _APK_ADD_RE.search(args) and not _APK_NOCACHE_RE.search(args):
            problem = ("apk", "the '--no-cache' flag")
        elif _YUM_INSTALL_RE.search(args) and not _YUM_CLEAN_RE.search(args):
            problem = ("yum/dnf", "'&& yum clean all' (or 'dnf clean all')")
        if problem:
            mgr, fix = problem
            out.append(Finding(
                rule_id="CL005",
                severity=Severity.LOW,
                title=f"{mgr} install leaves its package cache in the layer",
                message=(
                    f"This {mgr} install does not clean its package index. The leftover "
                    f"files bloat the image layer and enlarge its cache footprint. Add "
                    f"{fix} within the same RUN."
                ),
                path=dockerfile.path,
                line=ins.start_line,
                end_line=ins.end_line,
            ))
    return out


def _rule_pip_no_cache(dockerfile: Dockerfile, stage: Stage) -> List[Finding]:
    out: List[Finding] = []
    for ins in stage.instructions:
        if ins.keyword != "RUN" or not _PIP_INSTALL_RE.search(ins.args):
            continue
        if _NO_CACHE_DIR_RE.search(ins.args) or uses_cache_mount(ins):
            continue
        out.append(Finding(
            rule_id="CL010",
            severity=Severity.LOW,
            title="pip install keeps its download cache in the layer",
            message=(
                "pip install without '--no-cache-dir' leaves pip's download cache in "
                "the image layer, enlarging it. Add '--no-cache-dir', or mount a cache "
                "with '--mount=type=cache,target=/root/.cache/pip' to keep it out of "
                "the layer."
            ),
            path=dockerfile.path,
            line=ins.start_line,
            end_line=ins.end_line,
        ))
    return out


def _rule_package_upgrade(dockerfile: Dockerfile, stage: Stage) -> List[Finding]:
    out: List[Finding] = []
    for ins in stage.instructions:
        if ins.keyword != "RUN":
            continue
        if _PKG_UPGRADE_RE.search(ins.args):
            out.append(Finding(
                rule_id="CL009",
                severity=Severity.LOW,
                title="Full package upgrade makes the layer non-deterministic",
                message=(
                    "This RUN performs a distribution-wide package upgrade. The layer's "
                    "result changes whenever upstream packages change, so it busts the "
                    "cache unpredictably and builds are not reproducible. Pin the base "
                    "image and install specific package versions instead of upgrading."
                ),
                path=dockerfile.path,
                line=ins.start_line,
                end_line=ins.end_line,
            ))
    return out


def _rule_add_instead_of_copy(dockerfile: Dockerfile, stage: Stage) -> List[Finding]:
    out: List[Finding] = []
    for ins in stage.instructions:
        if ins.keyword != "ADD" or not ins.sources:
            continue
        if all(_add_is_justified(s) for s in ins.sources):
            continue  # remote URL or local archive: legitimate ADD use
        out.append(Finding(
            rule_id="CL008",
            severity=Severity.LOW,
            title="Use COPY instead of ADD for local files",
            message=(
                "ADD has surprising behavior: it auto-extracts local tar archives and "
                "fetches remote URLs (cached by URL only, never re-validated). For plain "
                "files and directories, COPY is clearer and has predictable cache "
                "semantics. Replace this ADD with COPY."
            ),
            path=dockerfile.path,
            line=ins.start_line,
            end_line=ins.end_line,
        ))
    return out


def _add_is_justified(src: str) -> bool:
    s = src.strip().strip('"').strip("'")
    if _URL_RE.match(s):
        return True
    low = s.lower()
    return any(low.endswith(ext) for ext in _ARCHIVE_EXTS)


def _rule_volatile_metadata(dockerfile: Dockerfile, stage: Stage) -> List[Finding]:
    # Only meaningful when there is an expensive cached layer to protect.
    install_idx: Optional[int] = None
    for idx, ins in enumerate(stage.instructions):
        if ins.keyword == "RUN" and detect_dependency_install(ins.args) is not None:
            install_idx = idx
            break
    if install_idx is None:
        return []
    install = stage.instructions[install_idx]

    out: List[Finding] = []
    for ins in stage.instructions[:install_idx]:
        if ins.keyword not in ("ARG", "ENV"):
            continue
        hit = next((n for n in _declared_var_names(ins.keyword, ins.args)
                    if _CACHEBUST_NAME_RE.match(n)), None)
        if not hit:
            continue
        out.append(Finding(
            rule_id="CL007",
            severity=Severity.LOW,
            title="Volatile build metadata declared before a cached layer",
            message=(
                f"'{hit}' looks like per-build metadata (a timestamp, commit SHA, or "
                f"cache-buster). It is declared on line {ins.start_line}, before the "
                f"dependency install on line {install.start_line}. If its value changes "
                f"between builds it invalidates that install layer and everything after "
                f"it. Declare such {ins.keyword} values after the install and build steps."
            ),
            path=dockerfile.path,
            line=ins.start_line,
            end_line=ins.end_line,
            related_lines=[install.start_line],
        ))
    return out


def _rule_mutable_base_tag(dockerfile: Dockerfile) -> List[Finding]:
    out: List[Finding] = []
    stage_names: set = set()
    for stage in dockerfile.stages:
        reason = _mutable_base_reason(stage.base, stage_names)
        if reason:
            out.append(Finding(
                rule_id="CL006",
                severity=Severity.MEDIUM,
                title="Base image uses a mutable tag",
                message=(
                    f"Base image '{stage.base}' is {reason}. The base layer (and every "
                    f"layer after it) is rebuilt whenever that tag is republished "
                    f"upstream, and builds are not reproducible. Pin a specific version "
                    f"(e.g. 'node:20.11-slim') or a digest ('image@sha256:...')."
                ),
                path=dockerfile.path,
                line=stage.from_instruction.start_line,
                end_line=stage.from_instruction.end_line,
            ))
        if stage.name:
            stage_names.add(stage.name.lower())
    return out


def _mutable_base_reason(base: str, stage_names: set) -> Optional[str]:
    """Why ``base`` is a mutable/unpinned image reference, or None if it is fine."""
    b = (base or "").strip()
    if not b or b == "scratch":
        return None
    if b.lower() in stage_names:
        return None  # a reference to an earlier build stage
    if "$" in b:
        return None  # ARG-templated tag; cannot judge statically
    name_and_digest = b.split("@", 1)
    if len(name_and_digest) == 2 and name_and_digest[1].lower().startswith("sha"):
        return None  # digest-pinned
    name_part = name_and_digest[0]
    last = name_part.rsplit("/", 1)[-1]  # drop registry/namespace (avoids host:port)
    if ":" in last:
        tag = last.split(":", 1)[1]
        if tag.lower() == "latest":
            return "pinned to the moving ':latest' tag"
        return None
    return "untagged, so it resolves to ':latest'"


def _declared_var_names(keyword: str, args: str) -> List[str]:
    """Variable names declared by an ARG or ENV instruction."""
    if keyword == "ARG":
        first = args.strip().split()
        return [first[0].split("=", 1)[0]] if first else []
    # ENV has two forms. Docker picks by whether the first token contains '=':
    #   modern:  ENV KEY=VALUE [KEY2=VALUE2 ...]
    #   legacy:  ENV KEY VALUE...   (the whole rest is the value)
    try:
        toks = shlex.split(args, posix=True)
    except ValueError:
        toks = args.split()
    if not toks:
        return []
    if "=" in toks[0]:
        return [t.split("=", 1)[0] for t in toks if "=" in t]
    return [toks[0]]


# --------------------------------------------------------------------------- #
# Helpers
# --------------------------------------------------------------------------- #


def _is_suppressed(dockerfile: Dockerfile, finding: Finding) -> bool:
    for ins in dockerfile.all_instructions:
        if ins.start_line == finding.line:
            return "*" in ins.suppressed_rules or finding.rule_id in ins.suppressed_rules
    return False


def _short(text: str, width: int = 40) -> str:
    text = " ".join(text.split())
    return text if len(text) <= width else text[: width - 3] + "..."
