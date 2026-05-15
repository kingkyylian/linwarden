# Contributor Ideas

These are scoped issues that help Linwarden become more useful without changing its rootless, read-only model.

## Good First Issues

| Issue | Area | Idea | Acceptance criteria |
| --- | --- | --- | --- |
| [#14](https://github.com/kingkyylian/linwarden/issues/14) | Vulnerability feeds | Import OSV Scanner JSON as another local feed format. | Add an OSV fixture, map entries into `LNX-PKG-004`, document the mapping, and pass `make check`. |

## Larger Tasks

| Issue | Area | Idea | Acceptance criteria |
| --- | --- | --- | --- |
| [#13](https://github.com/kingkyylian/linwarden/issues/13) | Fixtures | Add realistic Linux integration fixtures for common distributions. | Add sanitized distro fixture roots with documented origin and fixture-backed collector/rule coverage. |
| [#15](https://github.com/kingkyylian/linwarden/issues/15) | Profiles | Refine profile suppressions using fixture feedback. | Any suppression change has fixture-backed tests, explicit reasons, and updated configuration docs. |
| [#16](https://github.com/kingkyylian/linwarden/issues/16) | Container posture | Add rootless container runtime posture checks. | New rules include stable IDs, tests, docs, and conservative handling for missing runtime files. |
| [#17](https://github.com/kingkyylian/linwarden/issues/17) | Release | Configure PyPI trusted publishing. | Tag releases keep GitHub artifacts working and publish to PyPI only after trusted publishing is configured. |

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
