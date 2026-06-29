"""Optional git-history heuristic for COPY volatility.

If the Dockerfile lives in a git repository, we can measure how often the files
a COPY pulls in actually change. A ``COPY . .`` in a repo where every commit
touches source code is a far stronger signal than the same line in static
analysis alone. The heuristic is best-effort: if git is unavailable, the path
is not a repo, or anything fails, we degrade gracefully to ``None``.
"""

from __future__ import annotations

import os
import subprocess
from typing import Dict, List, Optional


class GitStats:
    """Per-path change frequency over the last N commits (0.0 .. 1.0)."""

    def __init__(self, total_commits: int, commits_with_changes: int,
                 changes_by_path: Dict[str, int]):
        self.total_commits = total_commits
        self.commits_with_changes = commits_with_changes
        self._changes = changes_by_path

    @property
    def available(self) -> bool:
        return self.total_commits > 0

    def volatility(self, path: str) -> Optional[float]:
        """Fraction of recent commits that touched anything under ``path``.

        ``path`` may be ``.`` (whole context), a directory, or a file.
        Returns ``None`` when git data is unavailable.
        """
        if not self.available:
            return None
        norm = path.strip().strip('"').strip("'").lstrip("./").rstrip("/")
        if norm in ("", "."):
            return min(1.0, self.commits_with_changes / self.total_commits)
        prefix = norm + "/"
        hits = sum(
            count for changed, count in self._changes.items()
            if changed == norm or changed.startswith(prefix)
        )
        return min(1.0, hits / self.total_commits)


_EMPTY = GitStats(0, 0, {})


def collect(context_dir: str, max_commits: int = 200, enabled: bool = True) -> GitStats:
    """Collect change counts per path. Never raises."""
    if not enabled or not _is_git_repo(context_dir):
        return _EMPTY
    try:
        # A unique record separator lets us count commits even when a commit
        # changed no files (merges/empty commits).
        log = subprocess.run(
            ["git", "-C", context_dir, "log", f"-{max_commits}",
             "--no-merges", "--pretty=format:%x00", "--name-only"],
            capture_output=True, text=True, timeout=30,
        )
        if log.returncode != 0:
            return _EMPTY
        return _parse_log(log.stdout)
    except (subprocess.SubprocessError, OSError):
        return _EMPTY


def _parse_log(output: str) -> GitStats:
    counts: Dict[str, int] = {}
    total = 0
    with_changes = 0
    current_has_change = False
    started = False
    for line in output.split("\n"):
        if line.startswith("\x00"):
            if started:
                total += 1
                if current_has_change:
                    with_changes += 1
            started = True
            current_has_change = False
            # A commit's first changed file may share the separator line.
            line = line.lstrip("\x00")
        p = line.strip()
        if p:
            counts[p] = counts.get(p, 0) + 1
            current_has_change = True
    if started:  # flush the final commit
        total += 1
        if current_has_change:
            with_changes += 1
    return GitStats(total, with_changes, counts)


def _is_git_repo(path: str) -> bool:
    if not os.path.isdir(path):
        return False
    try:
        r = subprocess.run(
            ["git", "-C", path, "rev-parse", "--is-inside-work-tree"],
            capture_output=True, text=True, timeout=10,
        )
        return r.returncode == 0 and r.stdout.strip() == "true"
    except (subprocess.SubprocessError, OSError):
        return False
