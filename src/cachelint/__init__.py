"""cachelint: predict Docker build-cache invalidation and suggest a faster order.

Public API:

    from cachelint import analyze, parse_dockerfile
    result = analyze(parse_dockerfile(open("Dockerfile").read()))
    for finding in result.findings:
        print(finding.rule_id, finding.title)
"""

from __future__ import annotations

__version__ = "0.1.0"

from .analyzer import AnalysisResult, analyze  # noqa: E402
from .model import Finding, Severity  # noqa: E402
from .parser import parse_dockerfile  # noqa: E402

__all__ = [
    "__version__",
    "analyze",
    "AnalysisResult",
    "parse_dockerfile",
    "Finding",
    "Severity",
]
