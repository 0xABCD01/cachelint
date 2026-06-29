<div align="center">

# 🐳 cachelint

### Predict Docker build-cache invalidation before it slows your CI, and get the fix.

[![CI](https://github.com/0xABCD01/cachelint/actions/workflows/ci.yml/badge.svg)](https://github.com/0xABCD01/cachelint/actions/workflows/ci.yml)
[![PyPI](https://img.shields.io/pypi/v/cachelint.svg)](https://pypi.org/project/cachelint/)
[![Python versions](https://img.shields.io/pypi/pyversions/cachelint.svg)](https://pypi.org/project/cachelint/)
[![License: MIT](https://img.shields.io/badge/license-MIT-blue.svg)](LICENSE)
<br>
[![Rules](https://img.shields.io/badge/cache_rules-10-orange.svg)](#-rules)
[![Ecosystems](https://img.shields.io/badge/ecosystems-24-success.svg)](#-supported-ecosystems)
[![Dependencies](https://img.shields.io/badge/runtime_deps-0-blueviolet.svg)](pyproject.toml)
[![PRs welcome](https://img.shields.io/badge/PRs-welcome-brightgreen.svg)](CONTRIBUTING.md)

**Find the layer that re-runs `npm ci` / `pip install` on every commit, see how much time it wastes, and paste back a faster Dockerfile.**

</div>

---

`cachelint` is a static analyzer for Dockerfiles that reasons about Docker's
layer cache. It tells you which instruction will bust the cache on your next
commit, how much build time that wastes, and how to reorder the file so your
expensive `npm ci` / `pip install` / `go mod download` layer stays cached. It
skips style linting and never builds an image.

## ⚡ Demo

```console
$ cachelint Dockerfile
cachelint  Dockerfile
  HIGH   CL001  Dependency install runs after a broad COPY
         8 │ COPY . .
      ▸ 10 │ RUN npm ci
      The broad 'COPY . .' on line 8 happens before the dependency install on line 10. Because any
      change to the copied files invalidates every later layer, the install rebuilds on every code
      change. Git history shows the copied paths change in ~94% of recent commits, so this layer
      rebuilds that often. Copy only the dependency manifests first, install, then copy the rest.
      ≈ 35s wasted per build that touches the copied files
      suggested fix:
        │ FROM node:20-slim
        │ WORKDIR /app
        │ COPY package.json package-lock.json /app/
        │ RUN npm ci
        │ COPY . .
        │ RUN npm run build

  Summary: 1 high  ·  est. ~35s wasted per affected build
  ✖ 1 finding(s) at or above 'high' (exit 1)
```

> [!TIP]
> Record your own demo GIF with [vhs](https://github.com/charmbracelet/vhs) or
> [asciinema](https://asciinema.org/) and drop it here for an animated preview.

## ✨ Features

- 🔍 **Catches the most common mistake:** installing dependencies after `COPY . .`, so the install layer rebuilds on every code change.
- 🛠️ **Writes the fix for you:** prints a reordered Dockerfile, or applies it with `--fix` (safely, with a `.bak` backup).
- 📉 **Quantifies the waste:** estimates the seconds lost per build, informed by your git history.
- 🌍 **Broad coverage:** 24 language ecosystems plus 6 system package managers.
- 🤖 **CI-native:** exit codes, `--fail-on`, and JSON / SARIF output for GitHub code scanning.
- 🪶 **Zero dependencies:** pure Python standard library, installs in a second.

## 🧩 The problem it solves

Docker caches each instruction as a layer. The moment one layer's inputs change,
Docker rebuilds **every layer after it**. Take this common Dockerfile:

```dockerfile
FROM node:20-slim
WORKDIR /app
COPY . .          # ← changes on almost every commit
RUN npm ci        # ← therefore re-runs on almost every commit (slow!)
RUN npm run build
```

It reinstalls every dependency whenever you touch a source file, because the
`COPY . .` above invalidates the cache. The fix is easy to forget: copy the
dependency manifests first, install, then copy the rest.

```dockerfile
FROM node:20-slim
WORKDIR /app
COPY package.json package-lock.json ./   # changes only when deps change
RUN npm ci                               # now cached across code changes
COPY . .
RUN npm run build
```

`cachelint` detects this across every supported ecosystem and writes the fix for
you.

## 📦 Install

```bash
pipx install cachelint     # recommended (isolated)
# or
pip install cachelint
```

`cachelint` adds no other packages. It is pure standard library.

## 🚀 Usage

```bash
cachelint                       # analyze ./Dockerfile
cachelint path/to/Dockerfile    # a specific file
cachelint services/             # find the Dockerfile in a directory
cachelint --fix                 # rewrite in place (a .bak backup is written)
cachelint --format json         # machine-readable output
cachelint --format sarif        # upload to GitHub code scanning
cachelint --fail-on medium      # also fail CI on medium findings
cachelint --no-git              # skip the git change-frequency heuristic
```

Exit codes: `0` clean, `1` findings at or above `--fail-on` (default `high`),
`2` usage/IO error.

### In CI

```yaml
# .github/workflows/docker.yml
- run: pipx install cachelint
- run: cachelint Dockerfile          # fails the job on a HIGH finding
```

Upload findings to the GitHub Security tab:

```yaml
- run: cachelint Dockerfile --format sarif --fail-on none > cachelint.sarif
- uses: github/codeql-action/upload-sarif@v3
  with:
    sarif_file: cachelint.sarif
```

### As a pre-commit hook

```yaml
# .pre-commit-config.yaml
- repo: https://github.com/0xABCD01/cachelint
  rev: v0.1.0
  hooks:
    - id: cachelint
```

## 📋 Rules

| ID    | Severity | What it catches |
|-------|:--------:|-----------------|
| CL001 | 🔴 high   | A dependency install runs after a broad `COPY . .`, so its expensive layer rebuilds on every code change. (Downgraded to medium when a BuildKit cache mount is present.) |
| CL002 | 🟠 medium | `apt-get update` in its own layer, so later installs reuse a stale package index once that layer is cached. |
| CL003 | 🟠 medium | `COPY . .` with no `.dockerignore` next to it, so `.git`, `node_modules`, and build output enter the context and keep busting the copy layer. |
| CL004 | 🟡 low    | A well-placed install that could be sped up further with `--mount=type=cache`. |
| CL005 | 🟡 low    | A system package install that leaves its package index in the layer, bloating it. |
| CL006 | 🟠 medium | `FROM` on `:latest` or an untagged image, so the base layer (and everything after) rebuilds whenever the tag moves upstream, and builds aren't reproducible. |
| CL007 | 🟡 low    | A volatile `ARG`/`ENV` (build date, commit SHA, cache-buster) declared before the dependency install, invalidating it on every build. |
| CL008 | 🟡 low    | `ADD` used for a plain local file or directory; use `COPY` instead (ADD auto-extracts archives and caches URLs by URL only). |
| CL009 | 🟡 low    | A distribution-wide package upgrade (`apt-get upgrade`, `apk upgrade`, and similar) makes the layer non-deterministic. |
| CL010 | 🟡 low    | `pip install` without `--no-cache-dir` (and no cache mount) keeps pip's download cache in the layer, bloating it. |

Suppress a finding inline:

```dockerfile
RUN npm ci   # cachelint:ignore=CL001
```

(or `# cachelint:ignore` to silence every rule on that instruction.)

## 🌍 Supported ecosystems

Dependency-install detection and auto-fix work across:

<div align="center">

<kbd>Node</kbd> <kbd>Python</kbd> <kbd>Go</kbd> <kbd>Rust</kbd> <kbd>Ruby</kbd> <kbd>PHP</kbd> <kbd>Java</kbd> <kbd>.NET</kbd> <kbd>Elixir</kbd> <kbd>Conda</kbd> <kbd>Dart / Flutter</kbd> <kbd>Swift</kbd> <kbd>Crystal</kbd> <kbd>Julia</kbd> <kbd>Clojure</kbd> <kbd>Perl</kbd> <kbd>Haskell</kbd> <kbd>Scala</kbd> <kbd>R</kbd> <kbd>Nim</kbd> <kbd>Gleam</kbd> <kbd>OCaml</kbd> <kbd>Erlang</kbd> <kbd>C / C++ (Conan / vcpkg)</kbd>

**System package managers:** <kbd>apt</kbd> <kbd>apk</kbd> <kbd>yum</kbd> <kbd>dnf</kbd> <kbd>zypper</kbd> <kbd>pacman</kbd>

</div>

## 🧠 How it works

1. A tolerant Dockerfile parser builds the stage/instruction tree (handling
   continuations, heredocs, multi-stage builds, JSON-array COPY, `--mount`, and
   parser directives).
2. Each `COPY`/`ADD` is classified as broad (whole context or a source tree),
   manifest (only lockfiles), or narrow.
3. Each `RUN` is classified as a dependency *install* (cacheable on manifests) or
   not. It excludes build and compile steps, which need the full source.
4. If a stage installs dependencies after a broad copy, that's the cache bug.
5. In a git repo, cachelint reads recent history to estimate how often the copied
   paths change.
6. The optimizer rewrites the stage to copy the manifests, install, then copy the
   source, using whichever manifest files exist in the build context.

## 🔍 How it compares

- **hadolint** lints Dockerfile style and shell. It does not model the cache or
  reorder instructions.
- **dive** inspects the layers of an already-built image. `cachelint` works on the
  source before you build and tells you what to change.

The three tools complement each other; run all three.

## ⚠️ Limitations

- `--fix` reorders instruction blocks. It applies only the manifest-split
  transform and drops standalone comment lines between instructions. It always
  writes a `.bak` backup, so review the diff.
- Cache-time estimates are typical per-ecosystem figures, not measurements.

## 🛠️ Development

```bash
git clone https://github.com/0xABCD01/cachelint && cd cachelint
pip install -e ".[dev]"
pytest
```

## 🤝 Contributing

Issues and pull requests are welcome. See [CONTRIBUTING.md](CONTRIBUTING.md) for
how to add a rule or an ecosystem, and [CODE_OF_CONDUCT.md](CODE_OF_CONDUCT.md)
for community guidelines.

## 📄 License

[MIT](LICENSE) © cachelint contributors
