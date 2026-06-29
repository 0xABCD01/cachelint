# Contributing to cachelint

Thanks for your interest! cachelint is a small, dependency-free Python project, so
getting started is quick.

## Development setup

```bash
git clone https://github.com/0xABCD01/cachelint && cd cachelint
python -m venv .venv && source .venv/bin/activate
pip install -e ".[dev]"
pytest
```

The whole test suite runs in well under a second and must stay green.

## Project layout

```
src/cachelint/
  parser.py      # Dockerfile -> stages / instructions (stdlib only)
  model.py       # types + cache knowledge: ecosystems, manifests, classification
  gitstats.py    # optional git change-frequency heuristic
  analyzer.py    # the rules (CL001..CL009) -> findings
  optimizer.py   # the safe "copy manifests first" reordering for --fix
  render.py      # pretty / json / sarif output
  cli.py         # argument handling, exit codes
tests/           # one file per module + test_rules.py / test_regressions.py
examples/        # demo Dockerfiles
```

## Adding a new ecosystem

1. Add a detection pattern to `_DEP_INSTALL_RULES` in `model.py`. Match a
   *dependency resolution* command only, never a build/compile step (those need
   the full source).
2. Add its manifest filenames to `MANIFESTS` and the key to `LANGUAGE_ECOSYSTEMS`
   (or `SYSTEM_ECOSYSTEMS`).
3. Add positive **and** negative cases to `tests/test_model.py`.

## Adding a new rule

1. Write a `_rule_*` function in `analyzer.py` returning `List[Finding]` with a
   stable `CLxxx` id, and register it in `analyze()`.
2. Document it in the module docstring and the README rules table.
3. Add tests in `tests/test_rules.py`. A rule must be **conservative**: prefer a
   false negative over a false positive. If you produce an auto-fix, it must never
   emit a Dockerfile that could fail to build (see `optimizer.try_reorder`).

## Style

- Standard library only; no runtime dependencies.
- Match the surrounding code: type hints, dataclasses, short docstrings.
- Keep output ASCII-safe (there is an ASCII glyph fallback in `render.py`).

## Commit messages

This repo follows [Conventional Commits](https://www.conventionalcommits.org/):
`feat:`, `fix:`, `docs:`, `test:`, `refactor:`, `chore:`, etc.
