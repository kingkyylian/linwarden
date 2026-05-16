# Contributor Ideas

These are scoped issues that help Linwarden become more useful without changing its rootless, read-only model.

## Good First Issues

No good-first issues are currently scoped. Keep new candidates small, fixture-backed, and compatible with Linwarden's rootless, read-only model.

## Larger Tasks

| Issue | Area | Idea | Acceptance criteria |
| --- | --- | --- | --- |
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
