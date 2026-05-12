# Release Process

Linwarden releases are tag-driven.

```bash
git tag v0.6.0
git push origin v0.6.0
```

The release workflow validates the project, builds source and wheel artifacts, and writes `dist/SHA256SUMS`.

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
