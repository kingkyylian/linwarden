# Contributing

Thanks for improving Linwarden. The project favors small, reviewable changes with tests and clear operational behavior.

## Development Setup

```bash
python3 -m venv .venv
. .venv/bin/activate
python -m pip install -e .
make test
```

## Change Guidelines

- Keep runtime dependencies at zero unless there is a strong reason.
- Add fixture-based tests for every new parser, collector, rule, or reporter behavior.
- Keep rules explainable: every finding needs evidence, impact, remediation, and severity.
- Avoid host writes. Linwarden should remain read-only unless a future command is explicitly designed otherwise.
- Preserve JSON schema compatibility or document a schema version bump.

## Adding a Rule

1. Add or update fixture files under `tests/fixtures/linux-root`.
2. Add a failing test that expects the rule ID and severity.
3. Implement the rule in `src/linwarden/rules.py`.
4. Document the rule in `docs/rules.md`.
5. Run `make test` and `make compile`.

Good starter tasks are collected in [docs/contributor-ideas.md](docs/contributor-ideas.md).

## Pull Request Checklist

- Tests cover the changed behavior.
- Documentation is updated when output, rules, or CLI flags change.
- `make check` passes.
- The change does not require root privileges to test.
