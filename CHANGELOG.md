# Changelog

All notable changes to this project are documented here. The format is based on
[Keep a Changelog](https://keepachangelog.com/) and this project adheres to
[Semantic Versioning](https://semver.org/).

## [0.1.0] - 2026-06-28

### Added
- Initial release.
- Dockerfile parser handling continuations, heredocs, multi-stage builds,
  JSON-array `COPY`, `RUN --mount`, and parser directives.
- Rules CL001 to CL010 covering broad-copy-before-install, split `apt-get update`,
  missing `.dockerignore`, missing BuildKit cache mounts, uncleaned package
  caches, mutable/unpinned base image tags, volatile build metadata
  (`ARG`/`ENV`) before cached layers, `ADD`-instead-of-`COPY`, distribution-wide
  package upgrades, and `pip install` without `--no-cache-dir`.
- Dependency-install detection for 24 language ecosystems (Node, Python, Go,
  Rust, Ruby, PHP, Java, .NET, Elixir, Conda, Dart/Flutter, Swift, Crystal,
  Julia, Clojure, Perl, Haskell, Scala, R, Nim, Gleam, OCaml, Erlang, C/C++ via
  Conan/vcpkg) plus system package managers (apt/apk/yum/dnf/zypper/pacman).
- Git change-frequency heuristic for sharper waste estimates.
- Canonical "copy manifests → install → copy source" reordering, shown in the
  report and applied with `--fix` (writes a `.bak` backup). The auto-fix refuses
  to run when it cannot guarantee a still-valid build (manifest not in context,
  or build-state-changing steps between the copy and the install).
- `pretty` (with ASCII fallback), `json`, and SARIF 2.1.0 output formats.
- CI gating via `--fail-on` and inline `# cachelint:ignore` suppression.
- Zero runtime dependencies (pure standard library).
