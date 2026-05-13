# Contributor Ideas

These are scoped issues that help Linwarden become more useful without changing its rootless, read-only model.

## Good First Issues

| Issue | Area | Idea | Acceptance criteria |
| --- | --- | --- | --- |
| - | - | No good first issues are currently queued. | Add new scoped items as issues before listing them here. |

## Larger Tasks

| Issue | Area | Idea | Acceptance criteria |
| --- | --- | --- | --- |
| [#6](https://github.com/kingkyylian/linwarden/issues/6) | Networking | Add bridge and forwarding posture checks for container hosts. | Works from procfs/sysfs-style fixtures. |
| [#7](https://github.com/kingkyylian/linwarden/issues/7) | Packages | Add optional package vulnerability feed ingestion from a local file. | No network call; documented JSON input contract. |

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
