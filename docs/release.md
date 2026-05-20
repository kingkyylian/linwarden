# Release Process

Linwarden releases are tag-driven.

```bash
git tag v0.13.1
git push origin v0.13.1
```

The release workflow validates the project, builds source and wheel artifacts, writes `dist/SHA256SUMS`, and emits GitHub artifact attestations for `dist/*`. The GitHub release body is written from the matching `CHANGELOG.md` section.

## Release Checklist

1. Confirm `CHANGELOG.md` has a dated section for the version.
2. Run `make check PYTHON=.venv/bin/python`.
3. Run `make package PYTHON=.venv/bin/python`.
4. Run `python scripts/release_assets.py dist`.
5. Confirm `dist/SHA256SUMS` contains only the intended release files.
6. Run `python scripts/verify_release_version.py --ref-name v0.13.1 --dist-dir dist --changelog CHANGELOG.md`.
7. Run `python scripts/changelog_release_notes.py --ref-name v0.13.1 --changelog CHANGELOG.md --output release-notes.md`.
8. Push the version tag.
9. Verify each published artifact attestation with `gh attestation verify`.
10. If PyPI publishing is enabled, run `python scripts/smoke_pypi_release.py v0.13.1`; it installs the released version from PyPI in a fresh environment, runs `linwarden --version`, runs `linwarden --help`, and runs a fixture scan.
11. Link the release notes to [github-actions.md](github-actions.md), [comparison.md](comparison.md), and [launch.md](launch.md).

## Release Dry Run

Use the manual workflow trigger to build and checksum release artifacts without creating a GitHub release or publishing to PyPI:

```bash
gh workflow run release.yml --repo kingkyylian/linwarden --ref main
```

The dry run uploads `release-dry-run-artifacts` for inspection. It does not create a GitHub release, does not emit release attestations, and does not publish to PyPI. Tag pushes remain the only path that can create GitHub releases, attestations, or PyPI uploads.

## PyPI Smoke Workflow

After a PyPI publish, run the reusable smoke workflow:

```bash
gh workflow run pypi-smoke.yml --repo kingkyylian/linwarden --ref main -f version=v0.13.1
```

The workflow run verifies that the requested version installs from PyPI, reports the expected `linwarden --version`, prints `linwarden --help`, and completes a fixture scan.

## Release Version Guard

The tag release workflow runs `scripts/verify_release_version.py` before signing, attestations, GitHub release creation, or PyPI publishing. The guard checks that the tag name matches `pyproject.toml`, runtime `__version__` matches `pyproject.toml`, distribution filenames match that version, and `CHANGELOG.md` has a dated section for the release version with at least one entry.

## Optional GPG Signing

Configure these repository secrets to add a detached signature for `SHA256SUMS`:

| Secret | Purpose |
| --- | --- |
| `GPG_PRIVATE_KEY` | ASCII-armored private signing key. |
| `GPG_PASSPHRASE` | Optional key passphrase. |

When configured, the release includes `SHA256SUMS.asc`.

## Artifact Attestations

Every tag release creates GitHub artifact attestations for the files in `dist/*` after checksum generation and optional GPG signing. Download release assets locally, then verify them with:

```bash
for artifact in dist/*; do
  gh attestation verify "$artifact" --repo kingkyylian/linwarden
done
```

The attestations complement `SHA256SUMS` and optional `SHA256SUMS.asc`; they do not replace those release assets.

## Optional PyPI Publishing

The release workflow has a separate `publish-pypi` job. GitHub release artifacts are still produced by the `build` job before PyPI publishing starts.

Configure PyPI trusted publishing with these values:

- PyPI project: `linwarden`
- Owner: `kingkyylian`
- Repository: `linwarden`
- Workflow: `release.yml`
- Environment name: `pypi`

If the PyPI project does not exist yet, create a pending publisher with the same values so the first trusted publish can create the project. If the project already exists, add a trusted publisher from the existing project's publishing settings.

Then configure the GitHub repository environment and variable:

1. Create or review the GitHub Actions environment named `pypi`.
2. Add any required reviewers or deployment protections on that environment.
3. Repository variable: `PUBLISH_PYPI=true`.

Without `PUBLISH_PYPI=true`, the `publish-pypi` job is skipped and the workflow only creates GitHub release artifacts. To roll back PyPI publishing, set `PUBLISH_PYPI=false` or remove the variable; do not add a PyPI API token or password secret.

After enabling, verify the next tag release by confirming:

- the `build` job created the GitHub release, checksums, optional signature, and attestations
- the `publish-pypi` job ran under the `pypi` environment
- PyPI shows the uploaded source distribution and wheel for the release version
- `python scripts/smoke_pypi_release.py v0.13.1` confirms a fresh install from PyPI runs the released CLI version and a fixture scan

References: [PyPI trusted publisher setup](https://docs.pypi.org/trusted-publishers/adding-a-publisher/), [pending publisher setup](https://docs.pypi.org/trusted-publishers/creating-a-project-through-oidc/), and [publishing with a trusted publisher](https://docs.pypi.org/trusted-publishers/using-a-publisher/).
