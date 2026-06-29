"""Generates the canonical cache-friendly reordering for a stage.

The transform we apply is the well-known "copy manifests, install, then copy
the rest" pattern. For a stage that installs dependencies *after* a broad
``COPY . .``, we:

1. Keep all setup before the broad copy (FROM, ARG, ENV, WORKDIR, system deps).
2. Insert a narrow ``COPY <manifests>`` (one per language ecosystem) and move
   the dependency-install ``RUN`` up, right before the broad copy.
3. Keep the broad copy and everything after it (build steps) in place.

We prefer manifest files that actually exist next to the Dockerfile; otherwise
we emit a sensible default with a comment asking the user to verify it.
"""

from __future__ import annotations

import glob
import os
from typing import Dict, List, Optional, Tuple

from .model import (
    LANGUAGE_ECOSYSTEMS,
    MANIFESTS,
    Dockerfile,
    Instruction,
    Stage,
    classify_copy,
    detect_dependency_install,
    manifest_ecosystems,
)

def _select_manifests(ecosystem: str, context_dir: str) -> Tuple[List[str], bool]:
    """Return (filenames, detected_on_disk) for manifest files that exist on disk.

    We never guess a manifest name: synthesizing a COPY of a file that is not in
    the build context would turn a working build into a hard failure, so callers
    rely on the boolean and skip the auto-fix when nothing was detected.
    """
    detected: List[str] = []
    seen = set()
    for pattern in MANIFESTS.get(ecosystem, []):
        if any(ch in pattern for ch in "*?["):
            for match in sorted(glob.glob(os.path.join(context_dir, pattern))):
                base = os.path.basename(match)
                if base not in seen:
                    seen.add(base)
                    detected.append(base)
        else:
            if os.path.isfile(os.path.join(context_dir, pattern)):
                if pattern not in seen:
                    seen.add(pattern)
                    detected.append(pattern)
    return detected, bool(detected)


def _infer_dest(prefix: List[Instruction], broad_copy: Instruction) -> str:
    workdir: Optional[str] = None
    for ins in prefix:
        if ins.keyword == "WORKDIR":
            workdir = ins.args.strip()
    dest = workdir or (broad_copy.dest or "./")
    dest = dest.strip().strip('"').strip("'")
    if not dest.endswith("/"):
        dest += "/"
    return dest


# Instructions that may safely sit between the broad copy and an install without
# affecting it (image metadata only). Anything else changes build state the
# install might depend on, so we refuse to auto-reorder across it.
_SAFE_BETWEEN = {
    "CMD", "LABEL", "EXPOSE", "ENTRYPOINT", "VOLUME", "STOPSIGNAL",
    "HEALTHCHECK", "MAINTAINER", "ONBUILD",
}


def _carry_flags(copy_ins: Instruction) -> str:
    """Ownership/permission flags to propagate onto a synthesized manifest COPY."""
    parts: List[str] = []
    for key in ("chown", "chmod", "link"):
        if key in copy_ins.flags:
            val = copy_ins.flags[key]
            parts.append(f"--{key}" if val is True else f"--{key}={val}")
    return (" ".join(parts) + " ") if parts else ""


def try_reorder(
    stage: Stage,
    broad_copy: Instruction,
    offending_installs: List[Instruction],
    context_dir: str,
) -> Optional[List[str]]:
    """Return a safe reordered stage body, or ``None`` if no safe fix exists.

    We only auto-fix when (a) nothing build-state-changing sits between the broad
    copy and the installs, and (b) every language manifest we would COPY actually
    exists in the build context. Otherwise we refuse rather than emit a Dockerfile
    that could fail to build or behave differently.
    """
    body = stage.instructions
    b = body.index(broad_copy)
    offending_ids = {id(ins) for ins in offending_installs}
    last_idx = max(body.index(ins) for ins in offending_installs)

    # (a) Safety: no state-changing instruction between the broad copy and the
    # last install (other than the installs themselves).
    for ins in body[b + 1:last_idx + 1]:
        if id(ins) in offending_ids:
            continue
        if ins.keyword not in _SAFE_BETWEEN:
            return None

    prefix = body[:b]
    already_copied: set = set()
    for ins in prefix:
        if ins.is_copy_like and not ins.flags.get("from") and classify_copy(ins.sources) in ("manifest", "narrow"):
            already_copied |= manifest_ecosystems(ins.sources)

    dest = _infer_dest(prefix, broad_copy)
    flag_prefix = _carry_flags(broad_copy)

    moved: List[str] = []
    emitted_eco: set = set()
    for ins in offending_installs:
        eco = (detect_dependency_install(ins.args) or ("", 0))[0]
        if eco in LANGUAGE_ECOSYSTEMS and eco not in emitted_eco and eco not in already_copied:
            files, detected = _select_manifests(eco, context_dir)
            # (b) Never synthesize a COPY of files we cannot confirm exist in the
            # context, which would turn a working build into a hard failure.
            if not detected:
                return None
            moved.append("COPY " + flag_prefix + " ".join(files) + " " + dest)
            emitted_eco.add(eco)
        elif eco in LANGUAGE_ECOSYSTEMS:
            emitted_eco.add(eco)
        moved.append(ins.raw)

    new_body: List[str] = []
    new_body.extend(ins.raw for ins in prefix)
    new_body.extend(moved)
    new_body.append(broad_copy.raw)
    new_body.extend(ins.raw for ins in body[b + 1:] if id(ins) not in offending_ids)
    return new_body


def render_stage(from_raw: str, body_blocks: List[str]) -> str:
    return "\n".join([from_raw] + body_blocks)


def regenerate_file(dockerfile: Dockerfile, fixes: Dict[int, List[str]]) -> str:
    """Rebuild the whole Dockerfile, applying reordered bodies for fixed stages.

    Note: standalone comment lines between instructions are not preserved; each
    instruction block is emitted verbatim. A ``.bak`` backup is written by the
    caller before any file is overwritten.
    """
    out: List[str] = []
    if dockerfile.syntax:
        out.append(f"# syntax={dockerfile.syntax}")
    if dockerfile.escape != "\\":
        out.append(f"# escape={dockerfile.escape}")
    for ins in dockerfile.pre_from:
        out.append(ins.raw)
        out.append("")
    for stage in dockerfile.stages:
        if stage.index in fixes:
            body = fixes[stage.index]
        else:
            body = [ins.raw for ins in stage.instructions]
        out.append(stage.from_instruction.raw)
        out.extend(body)
        out.append("")
    text = "\n".join(out).rstrip("\n") + "\n"
    return text
