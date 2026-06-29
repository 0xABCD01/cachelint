"""Command-line interface for cachelint."""

from __future__ import annotations

import argparse
import os
import sys
from typing import List, Optional

from . import __version__
from .analyzer import AnalysisResult, analyze
from .gitstats import collect as collect_gitstats
from .model import Severity
from .parser import parse_dockerfile
from . import render

EXIT_OK = 0
EXIT_FINDINGS = 1
EXIT_ERROR = 2

_DEFAULT_NAMES = ["Dockerfile"]


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="cachelint",
        description="Predict Docker build-cache invalidation and suggest a faster layer order.",
        epilog="Exit code 1 when findings reach --fail-on; 2 on usage errors.",
    )
    p.add_argument("paths", nargs="*", default=None,
                   help="Dockerfile paths (default: ./Dockerfile). Directories are scanned for a Dockerfile.")
    p.add_argument("--format", choices=["pretty", "json", "sarif"], default="pretty",
                   help="output format (default: pretty)")
    p.add_argument("--fail-on", choices=["none", "low", "medium", "high"], default="high",
                   help="minimum severity that makes the command exit 1 (default: high)")
    p.add_argument("--fix", action="store_true",
                   help="rewrite Dockerfiles with the suggested order (writes a .bak backup)")
    p.add_argument("--no-git", action="store_true",
                   help="disable the git change-frequency heuristic")
    p.add_argument("--git-commits", type=int, default=200, metavar="N",
                   help="how many recent commits to inspect for volatility (default: 200)")
    p.add_argument("--color", choices=["auto", "always", "never"], default="auto",
                   help="colorize the pretty output (default: auto)")
    p.add_argument("--version", action="version", version=f"cachelint {__version__}")
    return p


def _resolve_targets(paths: Optional[List[str]]) -> List[str]:
    targets: List[str] = []
    explicit = bool(paths)
    candidates = paths if paths else _DEFAULT_NAMES
    for c in candidates:
        if os.path.isdir(c):
            found = os.path.join(c, "Dockerfile")
            if os.path.isfile(found):
                targets.append(found)
            else:
                # also accept *.Dockerfile / Dockerfile.* in the directory
                extra = [
                    os.path.join(c, n) for n in sorted(os.listdir(c))
                    if n.endswith(".Dockerfile") or n.startswith("Dockerfile.")
                ]
                targets.extend(extra)
        elif explicit or os.path.isfile(c):
            # Explicit paths are kept even if missing (so the user gets a clear
            # "cannot read" error); default names are only used when they exist.
            targets.append(c)
    return targets


def _want_color(mode: str, stream) -> bool:
    if mode == "never":
        return False
    if mode == "always":
        return True
    if os.environ.get("NO_COLOR") is not None:
        return False
    return bool(getattr(stream, "isatty", lambda: False)())


def _analyze_path(path: str, args) -> AnalysisResult:
    with open(path, "r", encoding="utf-8") as fh:
        text = fh.read()
    context_dir = os.path.dirname(os.path.abspath(path)) or "."
    dockerfile = parse_dockerfile(text, path=path, context_dir=context_dir)
    gitstats = collect_gitstats(context_dir, max_commits=args.git_commits, enabled=not args.no_git)
    return analyze(dockerfile, gitstats)


def run(argv: Optional[List[str]] = None) -> int:
    args = build_parser().parse_args(argv)
    fail_on = Severity.parse(args.fail_on)

    targets = _resolve_targets(args.paths)
    if not targets:
        print("cachelint: no Dockerfile found (looked for ./Dockerfile)", file=sys.stderr)
        return EXIT_ERROR

    results: List[AnalysisResult] = []
    had_error = False
    for path in targets:
        try:
            results.append(_analyze_path(path, args))
        except OSError as exc:
            print(f"cachelint: cannot read {path}: {exc}", file=sys.stderr)
            had_error = True

    if not results:
        return EXIT_ERROR

    if args.fix:
        _apply_fixes(results)
        # Re-analyze the rewritten files so the report and exit code reflect the
        # post-fix state (eslint-style: only remaining findings count).
        refreshed: List[AnalysisResult] = []
        for r in results:
            try:
                refreshed.append(_analyze_path(r.path, args))
            except OSError:
                refreshed.append(r)
        results = refreshed

    _emit(results, args, fail_on)

    findings_hit = any(
        f.severity >= fail_on
        for r in results for f in r.findings
    ) if fail_on != Severity.NONE else False

    if had_error:
        return EXIT_ERROR
    return EXIT_FINDINGS if findings_hit else EXIT_OK


def _emit(results: List[AnalysisResult], args, fail_on: Severity) -> None:
    if args.format == "json":
        print(render.render_json(results, fail_on))
    elif args.format == "sarif":
        print(render.render_sarif(results))
    else:
        color = _want_color(args.color, sys.stdout)
        ascii_only = render.stream_is_ascii_only(sys.stdout)
        print(render.render_pretty(results, color=color, fail_on=fail_on, ascii_only=ascii_only))


def _apply_fixes(results: List[AnalysisResult]) -> None:
    for r in results:
        fixed = r.fixed_text
        if not fixed or fixed == r.dockerfile.source:
            continue
        backup = r.path + ".bak"
        try:
            with open(backup, "w", encoding="utf-8") as fh:
                fh.write(r.dockerfile.source)
            with open(r.path, "w", encoding="utf-8") as fh:
                fh.write(fixed)
            print(f"cachelint: rewrote {r.path} (backup at {backup}) -- review the diff before committing",
                  file=sys.stderr)
        except OSError as exc:  # pragma: no cover - filesystem dependent
            print(f"cachelint: could not write {r.path}: {exc}", file=sys.stderr)


def main() -> None:  # console_scripts entry point
    sys.exit(run())


if __name__ == "__main__":  # pragma: no cover
    main()
