# Linwarden

[![CI](https://github.com/kingkyylian/linwarden/actions/workflows/ci.yml/badge.svg)](https://github.com/kingkyylian/linwarden/actions/workflows/ci.yml)
[![Python](https://img.shields.io/badge/python-3.9%2B-blue.svg)](pyproject.toml)
[![License](https://img.shields.io/badge/license-MIT-green.svg)](LICENSE)

Linwarden is a rootless Linux hardening scanner for CI and fleet triage. It reads ordinary system files such as `/etc/os-release`, `/etc/ssh/sshd_config`, and selected `/proc/sys` values, then produces Markdown, JSON, or SARIF artifacts without installing an agent, daemon, privileged helper, database, or network service.

The project goal is practical: give maintainers a small, auditable tool that explains risky Linux defaults without needing an agent, daemon, privileged service, external database, or network access.

## Why Linwarden

Use Linwarden when you need a fast security posture signal, not a heavyweight compliance platform.

| Need | Linwarden approach |
| --- | --- |
| CI-friendly output | JSON, Markdown, and SARIF for GitHub code scanning. |
| Low operational risk | Read-only collection from ordinary Linux files. |
| Offline analysis | Scan mounted roots, image extracts, containers, and fixtures. |
| Explainable findings | Every rule includes evidence, impact, remediation, and references. |
| Small supply chain | Zero runtime dependencies beyond Python 3.9+. |

Linwarden is not a CIS or STIG replacement. It is the lightweight first pass that tells operators what deserves attention before they reach for heavier scanners.

## Features

- Rootless collection from `/etc`, `/proc`, and procfs sysctl paths.
- Deterministic JSON output for CI pipelines and scheduled host scans.
- Markdown output suitable for GitHub job summaries and issue attachments.
- SARIF output suitable for GitHub-native security ingestion.
- JSON config support for profiles, disabled rules, and justified suppressions.
- Optional effective OpenSSH config collection through `sshd -T`, including Match context.
- Package update and host firewall posture signals where rootless files expose them.
- Package metadata freshness checks for common package manager cache markers.
- Release checksum manifests with optional detached GPG signatures.
- Severity scoring with `critical`, `high`, `medium`, and `low` buckets.
- CI-friendly exit thresholds through `--fail-on`.
- Composite GitHub Action wrapper through `uses: kingkyylian/linwarden@v0.10.1`.
- Fixture-root scanning for tests, containers, forensic copies, and offline analysis.
- Zero runtime dependencies beyond Python 3.9+.

## Quick Start

From a checkout:

```bash
python3 -m venv .venv
. .venv/bin/activate
python -m pip install -e .
linwarden scan --format markdown
```

Run against the included fixture:

```bash
PYTHONPATH=src python3 -m linwarden scan \
  --root tests/fixtures/linux-root \
  --format json \
  --fail-on high
```

Exit code `2` means at least one finding matched the selected threshold.

## Common Workflows

| Workflow | Command or doc |
| --- | --- |
| Local triage | `linwarden scan --format markdown` |
| CI failure threshold | `linwarden scan --format json --fail-on high` |
| GitHub code scanning | `uses: kingkyylian/linwarden@v0.10.1` |
| Mounted image scan | `linwarden scan --root /mnt/server-image --format json` |
| Effective SSH scan | `linwarden scan --sshd-mode effective --sshd-match user=deploy` |
| Tool positioning | [docs/comparison.md](docs/comparison.md) |

## CLI

```text
linwarden scan [--root PATH] [--proc-root PATH] [--etc-root PATH]
               [--config PATH] [--format markdown|json|sarif]
               [--sshd-mode static|effective|auto] [--sshd-binary PATH]
               [--sshd-match KEY=VALUE]
               [--output PATH]
               [--fail-on off|low|medium|high|critical]
```

Common examples:

```bash
linwarden scan --format markdown --output linwarden-report.md
linwarden scan --format json --fail-on high
linwarden scan --config linwarden.json --format sarif --output linwarden.sarif
linwarden scan --sshd-mode effective --format json
linwarden scan --sshd-mode effective --sshd-match user=deploy --sshd-match addr=203.0.113.10
linwarden scan --root /mnt/server-image --format json
linwarden scan --proc-root /host/proc --etc-root /host/etc --format markdown
```

## Configuration

Linwarden accepts a zero-dependency JSON config file:

```json
{
  "profile": "router",
  "disabled_rules": ["LNX-NET-002"],
  "suppressions": [
    {
      "rule_id": "LNX-SSH-002",
      "reason": "Temporary migration host; password auth removed after cutover."
    }
  ]
}
```

Profiles:

| Profile | Behavior |
| --- | --- |
| `server` | Default. No profile suppressions. |
| `workstation` | No profile suppressions yet. |
| `router` | Suppresses IPv4 and IPv6 forwarding findings. |
| `container` | Suppresses selected host-kernel findings that may be inherited. |

Suppressed findings remain visible in JSON and Markdown reports. SARIF output includes active findings only.

## Exit Codes

| Code | Meaning |
| --- | --- |
| `0` | Scan completed and no selected threshold was met. |
| `1` | CLI usage error from argument parsing. |
| `2` | Scan completed and `--fail-on` threshold was met. |

## Current Rules

| Rule | Severity | Area | Summary |
| --- | --- | --- | --- |
| `LNX-SSH-001` | high | SSH | `PermitRootLogin yes` is enabled. |
| `LNX-SSH-002` | medium | SSH | `PasswordAuthentication yes` is enabled. |
| `LNX-SSH-003` | high | SSH | `PermitEmptyPasswords yes` is enabled. |
| `LNX-SSH-004` | medium | SSH | `MaxAuthTries` is above `4`. |
| `LNX-SSH-005` | medium | SSH | `AllowTcpForwarding yes` or `all` is enabled. |
| `LNX-KRN-001` | high | Kernel | `kernel.randomize_va_space=0` disables ASLR. |
| `LNX-KRN-002` | high | Kernel | `vm.mmap_min_addr` is below `65536`. |
| `LNX-KRN-003` | medium | Kernel | `kernel.kptr_restrict=0` exposes kernel pointers. |
| `LNX-FS-001` | high | Filesystem | `fs.protected_hardlinks=0` disables hardlink protection. |
| `LNX-FS-002` | high | Filesystem | `fs.protected_symlinks=0` disables symlink protection. |
| `LNX-NET-001` | medium | Network | `net.ipv4.ip_forward=1` is enabled. |
| `LNX-NET-002` | low | Network | `net.ipv4.conf.all.accept_redirects=1` is enabled. |
| `LNX-NET-003` | medium | Network | `net.ipv6.conf.all.forwarding=1` is enabled. |
| `LNX-NET-004` | low | Network | `net.ipv6.conf.all.accept_redirects=1` is enabled. |
| `LNX-PKG-001` | medium | Packages | Package updates are available. |
| `LNX-PKG-002` | high | Packages | Security package updates are available. |
| `LNX-PKG-003` | medium | Packages | Package metadata is stale. |
| `LNX-FW-001` | medium | Firewall | A known host firewall is disabled. |
| `LNX-SVC-001` | medium | Services | An enabled systemd service appears externally bound. |

Rule details live in [docs/rules.md](docs/rules.md).

## Report Score

Linwarden starts each report at `100` and subtracts a fixed penalty per finding:

| Severity | Penalty |
| --- | --- |
| critical | 35 |
| high | 20 |
| medium | 10 |
| low | 3 |

The score is intentionally simple. It is a triage signal, not a compliance rating.

## Project Layout

```text
src/linwarden/
  cli.py          command line entry point
  config.py       profiles, disabled rules, and suppressions
  collectors.py   host snapshot collection
  parsers.py      small parsers for Linux files
  rules.py        built-in hardening checks
  reporters.py    JSON, Markdown, and SARIF rendering
  models.py       report data structures
tests/
  fixtures/       deterministic Linux fixture root
docs/
  architecture.md implementation overview
  configuration.md profile and suppression config
  comparison.md    positioning against adjacent Linux security tools
  contributor-ideas.md scoped contribution backlog
  github-actions.md CI and SARIF workflow examples
  launch.md      copy and checklist for public announcements
  positioning.md maintainer messaging guide
  release.md      release artifact and publishing workflow
  rules.md        rule catalog
  report-schema.md JSON report contract
```

## Development

```bash
make test
make compile
make lint
make typecheck
make smoke
make smoke-sarif
make check
```

Use `make check PYTHON=.venv/bin/python` when running through a project virtualenv.

No network services or privileged permissions are required for the test suite.

## Security Model

Linwarden is read-only by default. It does not modify host state, load kernel modules, call package managers, or send telemetry. Reports can contain host configuration details, so treat generated artifacts as operationally sensitive.

## Known Limits

- Static SSH mode reads `sshd_config` plus simple `Include` directives; `Match` behavior may differ from effective OpenSSH config.
- Effective SSH mode executes `sshd -T`; use it only when scanning the live host intentionally.
- Package metadata age relies on local cache marker mtimes and does not call package manager commands.
- Firewalld and nftables service state is inferred from systemd enablement markers when present; config-only detection leaves enabled state unknown.
- Enabled systemd service exposure detection is static and only flags common wildcard bind options in service unit `ExecStart` lines.
- Missing files are treated as absent data so scans can run in containers and fixture roots.
- Linwarden is a hardening triage tool, not a full CIS or DISA STIG compliance scanner.

Please report vulnerabilities using [SECURITY.md](SECURITY.md).

## Roadmap

- Additional bridge networking rules.
- Package vulnerability feed adapters beyond local package manager metadata.

Contributor-ready ideas live in [docs/contributor-ideas.md](docs/contributor-ideas.md).

## License

MIT. See [LICENSE](LICENSE).
