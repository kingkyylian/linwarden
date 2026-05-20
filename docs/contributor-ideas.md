# Contributor Ideas

These are scoped issues that help Linwarden become more useful without changing its rootless, read-only model.

## Good First Issues

Keep new candidates small, fixture-backed, and compatible with Linwarden's rootless, read-only model.

| Area | Idea | Acceptance criteria |
| --- | --- | --- |
| Docs | Add a short PyPI install smoke transcript after the next release. | The transcript uses a fresh environment, shows `linwarden --version`, and does not rely on editable installs. |
| Fixtures | Add one focused package metadata freshness fixture for a supported distro. | The fixture is deterministic, rootless, and covered by a rule test. |
| Rules | Add a narrow firewall posture edge case only when local files prove the state. | The rule or parser change avoids treating missing files as safe and updates `docs/rules.md`. |

## Larger Tasks

| Issue | Area | Idea | Acceptance criteria |
| --- | --- | --- | --- |
| Candidate | Release | Add automated post-release install smoke guidance or workflow support. | A released version can be installed from PyPI in a fresh environment and run against a fixture without using local source files. |
| Candidate | Containers | Expand static container runtime posture only from reliable local evidence. | New checks are fixture-backed and never infer safety from missing runtime files. |

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
