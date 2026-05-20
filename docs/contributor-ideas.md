# Contributor Ideas

These are scoped issues that help Linwarden become more useful without changing its rootless, read-only model.

## Open Scoped Issues

Use the GitHub issues as the source of truth for active contributor work. Keep new candidates small, fixture-backed, and compatible with Linwarden's rootless, read-only model.

| Issue | Area | Scope | Acceptance focus |
| --- | --- | --- | --- |
| [#19](https://github.com/kingkyylian/linwarden/issues/19) | Docs | Add a short PyPI install smoke transcript. | Fresh environment, PyPI install for an explicit released version, `linwarden --version`, and one minimal CLI proof. |
| [#20](https://github.com/kingkyylian/linwarden/issues/20) | Fixtures | Add one supported-distro package metadata freshness fixture. | Deterministic local fixture, no network/package manager calls, and a test proving metadata age/source behavior. |
| [#21](https://github.com/kingkyylian/linwarden/issues/21) | Containers | Expand static container runtime posture from reliable local evidence. | Fixture-backed signal from local files only; no Docker/Podman/Kubernetes/systemctl calls and no safety inference from missing files. |
| [#18](https://github.com/kingkyylian/linwarden/issues/18) | Rules | Refactor `rules.py` as checks grow. | Keep rule metadata stable while reducing the pressure to add more logic to one large evaluator. |

## Completed Or Retired Candidates

| Area | Original idea | Resolution |
| --- | --- | --- |
| Release | Add automated post-release install smoke guidance or workflow support. | Covered by `scripts/smoke_pypi_release.py`, `.github/workflows/pypi-smoke.yml`, and the release dry-run notes artifact flow. |
| Rules | Add a narrow firewall posture edge case only when local files prove the state. | Covered by `680bca4`, which prevents disabled UFW config from hiding enabled nftables/firewalld markers. |

## Rule Quality Bar

Every rule should include:

- stable rule ID
- severity
- clear evidence
- operational impact
- remediation
- fixture-backed test
- docs entry in [rules.md](rules.md)

Rules should avoid claiming a host is unsafe when Linwarden only has incomplete evidence. Unknown state is better than false confidence.
