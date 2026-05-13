# Contributor Ideas

These are scoped issues that help Linwarden become more useful without changing its rootless, read-only model.

## Good First Issues

| Issue | Area | Idea | Acceptance criteria |
| --- | --- | --- | --- |
| [#1](https://github.com/kingkyylian/linwarden/issues/1) | Docs | Add a real-world GitHub Actions example for scanning an unpacked container root. | New docs section with copy-paste workflow. |
| [#2](https://github.com/kingkyylian/linwarden/issues/2) | Fixtures | Add richer Fedora root fixture data for firewalld and DNF metadata. | Collector tests cover provider and package metadata behavior. |
| [#4](https://github.com/kingkyylian/linwarden/issues/4) | Fixtures | Add richer Arch root fixture data for Pacman metadata. | Distro fixture test validates metadata source selection. |

## Larger Tasks

| Issue | Area | Idea | Acceptance criteria |
| --- | --- | --- | --- |
| [#3](https://github.com/kingkyylian/linwarden/issues/3) | Systemd | Detect enabled externally listening services from rootless unit files. | No systemctl calls; fixture-backed parser and rules. |
| [#6](https://github.com/kingkyylian/linwarden/issues/6) | Networking | Add bridge and forwarding posture checks for container hosts. | Works from procfs/sysfs-style fixtures. |
| [#7](https://github.com/kingkyylian/linwarden/issues/7) | Packages | Add optional package vulnerability feed ingestion from a local file. | No network call; documented JSON input contract. |
| [#5](https://github.com/kingkyylian/linwarden/issues/5) | Release | Add Sigstore or GitHub artifact attestation support. | Tag workflow emits attestations without weakening current checksum flow. |

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
