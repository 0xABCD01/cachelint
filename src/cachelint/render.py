"""Output formatters: a colorized terminal report, JSON, and SARIF."""

from __future__ import annotations

import json
import textwrap
from typing import List, Optional

from .analyzer import AnalysisResult
from .model import Finding, Severity

__all__ = ["render_pretty", "render_json", "render_sarif", "summarize"]

_RESET = "\033[0m"
_BOLD = "\033[1m"
_DIM = "\033[2m"
_RED = "\033[31m"
_YELLOW = "\033[33m"
_CYAN = "\033[36m"
_GREEN = "\033[32m"
_GREY = "\033[90m"

_SEV_COLOR = {
    Severity.HIGH: _RED,
    Severity.MEDIUM: _YELLOW,
    Severity.LOW: _CYAN,
}

# Glyphs, with ASCII fallbacks for terminals whose encoding cannot represent the
# Unicode set (e.g. an ``ascii``/C locale), avoiding UnicodeEncodeError on print.
_GLYPHS_UNICODE = {"point": "▸", "ok": "✔", "fail": "✖", "waste": "≈", "sep": "·", "bar": "│"}
_GLYPHS_ASCII = {"point": ">", "ok": "OK", "fail": "x", "waste": "~", "sep": "-", "bar": "|"}


def stream_is_ascii_only(stream) -> bool:
    """True if ``stream``'s encoding cannot represent the Unicode glyph set."""
    enc = getattr(stream, "encoding", None) or "ascii"
    try:
        "".join(_GLYPHS_UNICODE.values()).encode(enc)
        return False
    except (UnicodeEncodeError, LookupError):
        return True


class _Palette:
    def __init__(self, enabled: bool):
        self.enabled = enabled

    def __call__(self, code: str, text: str) -> str:
        if not self.enabled or not code:
            return text
        return f"{code}{text}{_RESET}"


def summarize(results: List[AnalysisResult]) -> dict:
    counts = {Severity.HIGH: 0, Severity.MEDIUM: 0, Severity.LOW: 0}
    waste = 0
    total = 0
    for r in results:
        for f in r.findings:
            total += 1
            if f.severity in counts:
                counts[f.severity] += 1
            waste += f.est_waste_seconds
    return {
        "files": len(results),
        "findings": total,
        "high": counts[Severity.HIGH],
        "medium": counts[Severity.MEDIUM],
        "low": counts[Severity.LOW],
        "estWasteSeconds": waste,
    }


# --------------------------------------------------------------------------- #
# Pretty terminal report
# --------------------------------------------------------------------------- #


def render_pretty(results: List[AnalysisResult], color: bool, fail_on: Severity,
                  ascii_only: bool = False) -> str:
    c = _Palette(color)
    g = _GLYPHS_ASCII if ascii_only else _GLYPHS_UNICODE
    lines: List[str] = []

    for r in results:
        header = c(_BOLD, "cachelint") + "  " + c(_GREY, r.path)
        lines.append(header)
        if not r.findings:
            lines.append("  " + c(_GREEN, f"{g['ok']} no cache problems found"))
            lines.append("")
            continue
        src_lines = r.dockerfile.source.split("\n")
        for f in r.findings:
            lines.extend(_render_finding(f, src_lines, c, g))
        lines.append("")

    summary = summarize(results)
    lines.append(_render_summary(summary, fail_on, c, g))
    return "\n".join(lines)


def _render_finding(f: Finding, src_lines: List[str], c: _Palette, g: dict) -> List[str]:
    sev_color = _SEV_COLOR.get(f.severity, "")
    badge = c(sev_color + _BOLD, f"{str(f.severity).upper():<6}")
    out = [f"  {badge} {c(_GREY, f.rule_id)}  {c(_BOLD, f.title)}"]

    # Code snippet: related lines (context) + primary line (pointer).
    snippet_lines = sorted(set(f.related_lines + [f.line]))
    width = max((len(str(n)) for n in snippet_lines), default=1)
    for n in snippet_lines:
        text = src_lines[n - 1] if 0 < n <= len(src_lines) else ""
        pointer = g["point"] if n == f.line else " "
        ln = c(sev_color, pointer) + " " + c(_GREY, f"{n:>{width}} {g['bar']} ") + text.rstrip()
        out.append("      " + ln)

    for para in _wrap(f.message, 92):
        out.append("      " + c(_DIM, para))

    if f.est_waste_seconds:
        out.append("      " + c(sev_color, f"{g['waste']} {f.est_waste_seconds}s wasted per build that touches the copied files"))

    if f.suggestion:
        out.append("      " + c(_GREEN, "suggested fix:"))
        for s in f.suggestion.split("\n"):
            out.append("        " + c(_GREY, f"{g['bar']} ") + s)
    out.append("")
    return out


def _render_summary(summary: dict, fail_on: Severity, c: _Palette, g: dict) -> str:
    parts = []
    if summary["high"]:
        parts.append(c(_RED, f"{summary['high']} high"))
    if summary["medium"]:
        parts.append(c(_YELLOW, f"{summary['medium']} medium"))
    if summary["low"]:
        parts.append(c(_CYAN, f"{summary['low']} low"))
    if not parts:
        body = c(_GREEN, "no findings")
    else:
        body = ", ".join(parts)
    waste = summary["estWasteSeconds"]
    waste_str = f"  {g['sep']}  est. ~{waste}s wasted per affected build" if waste else ""
    line = f"  {c(_BOLD, 'Summary:')} {body}{waste_str}"

    fails = _count_at_or_above(summary, fail_on)
    if fail_on != Severity.NONE and fails:
        verdict = c(_RED + _BOLD, f"  {g['fail']} {fails} finding(s) at or above '{fail_on}' (exit 1)")
    else:
        verdict = c(_GREEN + _BOLD, f"  {g['ok']} passing")
    return line + "\n" + verdict


def _count_at_or_above(summary: dict, level: Severity) -> int:
    n = 0
    if level <= Severity.HIGH:
        n += summary["high"]
    if level <= Severity.MEDIUM:
        n += summary["medium"]
    if level <= Severity.LOW:
        n += summary["low"]
    return n


def _wrap(text: str, width: int) -> List[str]:
    return textwrap.wrap(" ".join(text.split()), width=width) or [""]


# --------------------------------------------------------------------------- #
# JSON
# --------------------------------------------------------------------------- #


def render_json(results: List[AnalysisResult], fail_on: Severity) -> str:
    payload = {
        "tool": "cachelint",
        "version": _version(),
        "summary": summarize(results),
        "failOn": str(fail_on),
        "results": [
            {
                "path": r.path,
                "findings": [f.to_dict() for f in r.findings],
            }
            for r in results
        ],
    }
    return json.dumps(payload, indent=2)


# --------------------------------------------------------------------------- #
# SARIF 2.1.0 (for GitHub code scanning)
# --------------------------------------------------------------------------- #

_SARIF_LEVEL = {
    Severity.HIGH: "error",
    Severity.MEDIUM: "warning",
    Severity.LOW: "note",
}


def render_sarif(results: List[AnalysisResult]) -> str:
    rules = {}
    sarif_results = []
    for r in results:
        for f in r.findings:
            rules.setdefault(f.rule_id, {
                "id": f.rule_id,
                "name": f.title,
                "shortDescription": {"text": f.title},
                "defaultConfiguration": {"level": _SARIF_LEVEL.get(f.severity, "note")},
            })
            sarif_results.append({
                "ruleId": f.rule_id,
                "level": _SARIF_LEVEL.get(f.severity, "note"),
                "message": {"text": f.message},
                "locations": [{
                    "physicalLocation": {
                        "artifactLocation": {"uri": r.path},
                        "region": {"startLine": f.line, "endLine": f.end_line},
                    }
                }],
            })
    sarif = {
        "$schema": "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json",
        "version": "2.1.0",
        "runs": [{
            "tool": {
                "driver": {
                    "name": "cachelint",
                    "informationUri": "https://github.com/0xABCD01/cachelint",
                    "version": _version(),
                    "rules": list(rules.values()),
                }
            },
            "results": sarif_results,
        }],
    }
    return json.dumps(sarif, indent=2)


def _version() -> str:
    from . import __version__
    return __version__
