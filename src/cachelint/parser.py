"""A pragmatic Dockerfile parser (standard library only).

It is intentionally tolerant: it never raises on unusual-but-valid Dockerfiles.
It handles the things that matter for cache analysis:

* parser directives (``# syntax=``, ``# escape=``)
* the configurable escape character and line continuations
* whole-line comments (including comments inside a continued instruction)
* inline ``# cachelint:ignore`` / ``# cachelint:ignore=CL001,CL002`` suppressions
* heredocs (``RUN <<EOF`` ... ``EOF``) used by modern BuildKit files
* multi-stage builds (``FROM x AS y``) and ``COPY --from=``
* COPY/ADD in both shell and JSON-array form, with ``--flags``
* ``RUN --mount=...`` flags

It does not try to be a full BuildKit frontend; it extracts structure, not
semantics.
"""

from __future__ import annotations

import json
import re
import shlex
from typing import List, Optional, Tuple

from .model import Dockerfile, Instruction, Stage

_DIRECTIVE_RE = re.compile(r"^#\s*([A-Za-z]+)\s*=\s*(\S+)\s*$")
_KEYWORD_RE = re.compile(r"^\s*([A-Za-z][A-Za-z0-9_]*)\b(.*)$", re.DOTALL)
_IGNORE_RE = re.compile(r"#\s*cachelint:ignore(?:=([A-Za-z0-9_,\s]+))?", re.IGNORECASE)
# A heredoc opener must be a *standalone shell token* (e.g. <<EOF, <<-EOF,
# <<"EOF"), not any "<<word" substring inside a quoted argument such as
# `sed 's/<<X>>/y/'`. We therefore match whole tokens after shell-tokenizing.
_HEREDOC_TOKEN_RE = re.compile(r"^<<([-~]?)([\"']?)([A-Za-z_][A-Za-z0-9_]*)\2$")
_HEREDOC_STRIP_RE = re.compile(r"(?<!\S)<<[-~]?[\"']?[A-Za-z_][A-Za-z0-9_]*[\"']?(?!\S)")

_KNOWN_KEYWORDS = {
    "FROM", "RUN", "CMD", "LABEL", "MAINTAINER", "EXPOSE", "ENV", "ADD",
    "COPY", "ENTRYPOINT", "VOLUME", "USER", "WORKDIR", "ARG", "ONBUILD",
    "STOPSIGNAL", "HEALTHCHECK", "SHELL",
}


def _read_parser_directives(lines: List[str]) -> Tuple[str, Optional[str], int]:
    """Read leading parser directives. Returns (escape, syntax, next_index)."""
    escape = "\\"
    syntax: Optional[str] = None
    i = 0
    while i < len(lines):
        m = _DIRECTIVE_RE.match(lines[i])
        if not m:
            break
        key = m.group(1).lower()
        val = m.group(2)
        if key == "escape" and val in ("\\", "`"):
            escape = val
        elif key == "syntax":
            syntax = val
        elif key not in ("check",):
            # Unknown directive ends the directive block per Docker semantics.
            break
        i += 1
    return escape, syntax, i


def _heredoc_markers(text: str, keyword: str) -> List[Tuple[str, bool]]:
    """Heredoc terminators opened on this instruction line.

    Only RUN/COPY/ADD can open heredocs. Each result is ``(name, is_dash)`` where
    the dash form (``<<-`` / ``<<~``) allows leading whitespace before the
    closing delimiter.
    """
    if keyword not in ("RUN", "COPY", "ADD"):
        return []
    try:
        tokens = shlex.split(text, posix=True)
    except ValueError:
        tokens = text.split()
    markers: List[Tuple[str, bool]] = []
    for tok in tokens:
        m = _HEREDOC_TOKEN_RE.match(tok)
        if m:
            markers.append((m.group(3), m.group(1) in ("-", "~")))
    return markers


def _strip_heredoc_markers(text: str) -> str:
    return " ".join(_HEREDOC_STRIP_RE.sub(" ", text).split())


def _logical_instructions(lines: List[str], start: int, escape: str):
    """Yield (raw_block, joined_text, start_line, end_line, is_heredoc) (1-based)."""
    i = start
    n = len(lines)
    while i < n:
        line = lines[i]
        stripped = line.strip()
        if stripped == "" or stripped.startswith("#"):
            i += 1
            continue

        block_start = i  # 0-based
        raw_lines = [line]
        joined_parts: List[str] = []

        # Collect continuation lines.
        cur = line
        while True:
            rstr = cur.rstrip()
            if rstr.endswith(escape):
                joined_parts.append(rstr[: -len(escape)])
                i += 1
                # Skip blank / comment-only lines within a continuation.
                while i < n and (lines[i].strip() == "" or lines[i].strip().startswith("#")):
                    raw_lines.append(lines[i])
                    i += 1
                if i >= n:
                    break
                cur = lines[i]
                raw_lines.append(cur)
                continue
            else:
                joined_parts.append(cur)
                break

        joined = " ".join(p.strip() for p in joined_parts if p.strip() != "")

        keyword, _ = _parse_keyword(joined)
        markers = _heredoc_markers(joined, keyword)
        is_heredoc = bool(markers)
        if markers:
            opener_lines = len(raw_lines)
            pending = list(markers)
            i += 1
            while i < n and pending:
                body = lines[i]
                raw_lines.append(body)
                name, dash = pending[0]
                candidate = body.rstrip("\r\n")
                if dash:
                    candidate = candidate.lstrip(" \t")
                if candidate == name:
                    pending.pop(0)
                i += 1
            if keyword == "RUN":
                # Append the heredoc body so RUN content stays searchable.
                body_text = "\n".join(raw_lines[opener_lines:])
                joined = joined + "\n" + body_text
            else:
                # COPY/ADD heredoc: the body is inline file content, not source
                # paths; drop the <<MARKER tokens so they are not parsed as paths.
                joined = _strip_heredoc_markers(joined)
        else:
            i += 1

        yield ("\n".join(raw_lines), joined, block_start + 1,
               block_start + len(raw_lines), is_heredoc)


def _parse_keyword(joined: str) -> Tuple[str, str]:
    m = _KEYWORD_RE.match(joined)
    if not m:
        return "", joined
    return m.group(1).upper(), m.group(2).strip()


def _split_flags(tokens: List[str]) -> Tuple[dict, List[str]]:
    """Peel leading ``--key=value`` / ``--key`` flags off a token list."""
    flags: dict = {}
    rest: List[str] = []
    consuming = True
    for tok in tokens:
        if consuming and tok.startswith("--"):
            body = tok[2:]
            if "=" in body:
                key, val = body.split("=", 1)
            else:
                key, val = body, True
            if key == "mount":
                flags.setdefault("mount", []).append(val if isinstance(val, str) else "")
            else:
                flags[key] = val
        else:
            consuming = False
            rest.append(tok)
    return flags, rest


def _parse_copy_add(args: str) -> Tuple[dict, List[str], Optional[str]]:
    """Parse COPY/ADD args into (flags, sources, dest)."""
    args = args.strip()
    # JSON-array form: COPY ["src", "dest"]
    bracket = args.find("[")
    if bracket != -1 and args[bracket:].lstrip().startswith("["):
        # Flags may precede the array.
        prefix = args[:bracket]
        flags, _ = _split_flags(prefix.split()) if prefix.strip() else ({}, [])
        try:
            arr = json.loads(args[bracket:])
            if isinstance(arr, list) and len(arr) >= 2:
                return flags, [str(x) for x in arr[:-1]], str(arr[-1])
        except (ValueError, TypeError):
            pass
    # Shell form.
    try:
        tokens = shlex.split(args, posix=True)
    except ValueError:
        tokens = args.split()
    flags, rest = _split_flags(tokens)
    if len(rest) >= 2:
        return flags, rest[:-1], rest[-1]
    if len(rest) == 1:
        return flags, rest, None
    return flags, [], None


def _parse_run_flags(args: str) -> dict:
    """Extract leading RUN flags (--mount, --network, --security)."""
    flags: dict = {}
    # Only inspect the first physical line for flags.
    first = args.split("\n", 1)[0]
    try:
        tokens = shlex.split(first, posix=True)
    except ValueError:
        tokens = first.split()
    flags, _ = _split_flags(tokens)
    return flags


def _suppressed_rules(raw: str) -> set:
    out: set = set()
    for m in _IGNORE_RE.finditer(raw):
        group = m.group(1)
        if group is None:
            out.add("*")  # suppress everything on this instruction
        else:
            for rid in group.replace(" ", "").split(","):
                if rid:
                    out.add(rid.upper())
    return out


def parse_dockerfile(text: str, path: str = "Dockerfile", context_dir: Optional[str] = None) -> Dockerfile:
    import os

    lines = text.split("\n")
    escape, syntax, start = _read_parser_directives(lines)

    all_instructions: List[Instruction] = []
    for raw, joined, sline, eline, is_heredoc in _logical_instructions(lines, start, escape):
        keyword, args = _parse_keyword(joined)
        if not keyword:
            continue
        ins = Instruction(
            keyword=keyword,
            args=args,
            raw=raw,
            start_line=sline,
            end_line=eline,
            suppressed_rules=_suppressed_rules(raw),
        )
        if keyword in ("COPY", "ADD"):
            if is_heredoc:
                # Inline heredoc content is not a context source path.
                ins.sources = []
                ins.dest = None
            else:
                flags, sources, dest = _parse_copy_add(args)
                ins.flags = flags
                ins.sources = sources
                ins.dest = dest
        elif keyword == "RUN":
            ins.flags = _parse_run_flags(args)
        all_instructions.append(ins)

    # Group into stages.
    stages: List[Stage] = []
    pre_from: List[Instruction] = []
    current: Optional[Stage] = None
    for ins in all_instructions:
        if ins.keyword == "FROM":
            base, name = _parse_from(ins.args)
            current = Stage(
                index=len(stages),
                base=base,
                name=name,
                from_instruction=ins,
                instructions=[],
            )
            stages.append(current)
        elif current is None:
            pre_from.append(ins)
        else:
            current.instructions.append(ins)

    if context_dir is None:
        context_dir = os.path.dirname(os.path.abspath(path)) or "."

    return Dockerfile(
        path=path,
        escape=escape,
        syntax=syntax,
        stages=stages,
        pre_from=pre_from,
        all_instructions=all_instructions,
        source=text,
        context_dir=context_dir,
    )


def _parse_from(args: str) -> Tuple[str, Optional[str]]:
    tokens = args.split()
    # Drop platform flag if present: FROM --platform=... image AS name
    tokens = [t for t in tokens if not t.startswith("--")]
    if not tokens:
        return "", None
    base = tokens[0]
    name = None
    for idx, tok in enumerate(tokens):
        if tok.upper() == "AS" and idx + 1 < len(tokens):
            name = tokens[idx + 1]
            break
    return base, name
