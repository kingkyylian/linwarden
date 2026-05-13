# Release Process

Linwarden releases are tag-driven.

```bash
git tag v0.8.0
git push origin v0.8.0
```

The release workflow validates the project, builds source and wheel artifacts, and writes `dist/SHA256SUMS`.

## Release Checklist

1. Confirm `CHANGELOG.md` has a dated section for the version.
2. Run `make check PYTHON=.venv/bin/python`.
3. Run `make package PYTHON=.venv/bin/python`.
4. Run `python scripts/release_assets.py dist`.
5. Confirm `dist/SHA256SUMS` contains only the intended release files.
6. Push the version tag.
7. Link the release notes to [github-actions.md](github-actions.md), [comparison.md](comparison.md), and [launch.md](launch.md).

## Optional GPG Signing

Configure these repository secrets to add a detached signature for `SHA256SUMS`:

| Secret | Purpose |
| --- | --- |
| `GPG_PRIVATE_KEY` | ASCII-armored private signing key. |
| `GPG_PASSPHRASE` | Optional key passphrase. |

When configured, the release includes `SHA256SUMS.asc`.

## Optional PyPI Publishing

Configure PyPI trusted publishing for this repository, then set repository variable `PUBLISH_PYPI=true`.

Without that variable, the workflow only creates GitHub release artifacts.
