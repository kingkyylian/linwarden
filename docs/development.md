# Development

## Requirements

- Python 3.9 or newer.
- `make` for convenience targets.
- No runtime services.

## Commands

```bash
make test
make compile
make lint
make typecheck
make smoke
make smoke-sarif
make package
make check
```

Install development tools with:

```bash
python -m pip install -e ".[dev]"
```

To run checks with a project virtualenv:

```bash
make check PYTHON=.venv/bin/python
```

`make compile` writes bytecode under the project-local `.pycache` directory so local sandboxed environments do not need access to user-level Python cache directories.

## Test Strategy

The test suite does not inspect the developer machine. It uses `tests/fixtures/linux-root` as a deterministic Linux root and passes that root into the collector.

Additional distro fixture roots live under `tests/fixtures/*-root`; their origin and sanitization notes are documented in [fixture-roots.md](fixture-roots.md).

This keeps tests stable on macOS, Linux, and CI.

## Release Checklist

1. Update `CHANGELOG.md`.
2. Confirm `pyproject.toml` version matches `src/linwarden/__init__.py`.
3. Run `make test`.
4. Run `make compile`.
5. Run `make package PYTHON=.venv/bin/python`.
6. Tag the release after CI passes.

## Release Workflow

Pushing a tag like `v0.13.1` runs tests, compile, Ruff, and mypy, builds source and wheel artifacts, creates `dist/SHA256SUMS`, optionally signs that checksum manifest when GPG secrets are configured, then creates a GitHub Release with generated notes.

Set repository variable `PUBLISH_PYPI=true` only after PyPI trusted publishing is configured for this repository.
