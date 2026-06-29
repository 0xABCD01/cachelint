# Security Policy

cachelint is a static analyzer that reads Dockerfiles; it does not execute them
and has no runtime dependencies. The main security consideration is that
`--fix` rewrites files on disk. It always writes a `.bak` backup first and
refuses to produce a Dockerfile it cannot prove still builds.

## Reporting a vulnerability

Please report suspected vulnerabilities privately via GitHub's "Report a
vulnerability" feature (Security tab) rather than opening a public issue. You can
expect an initial response within a few days.

## Supported versions

The latest released version on the `main` branch receives fixes.
