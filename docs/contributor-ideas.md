# Contributor Ideas

These are scoped issues that help Linwarden become more useful without changing its rootless, read-only model.

## Good First Issues

| Area | Idea | Acceptance criteria |
| --- | --- | --- |
| Rules | Add a rule for SSH `MaxAuthTries` above a conservative threshold. | Fixture, rule test, docs entry, JSON/SARIF smoke unchanged. |
| Rules | Add a rule for SSH `AllowTcpForwarding yes`. | Effective and static SSH paths remain covered. |
| Docs | Add a real-world GitHub Actions example for scanning an unpacked container root. | New docs section with copy-paste workflow. |
| Fixtures | Add richer Fedora root fixture data for firewalld and DNF metadata. | Collector tests cover provider and package metadata behavior. |
| Fixtures | Add richer Arch root fixture data for Pacman metadata. | Distro fixture test validates metadata source selection. |

## Larger Tasks

| Area | Idea | Acceptance criteria |
| --- | --- | --- |
| Systemd | Detect enabled externally listening services from rootless unit files. | No systemctl calls; fixture-backed parser and rules. |
| Networking | Add bridge and forwarding posture checks for container hosts. | Works from procfs/sysfs-style fixtures. |
| Packages | Add optional package vulnerability feed ingestion from a local file. | No network call; documented JSON input contract. |
| Release | Add Sigstore or GitHub artifact attestation support. | Tag workflow emits attestations without weakening current checksum flow. |
| Packaging | Publish a reusable GitHub Action wrapper. | Users can run Linwarden without writing Python install steps. |

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
