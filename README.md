# Linwarden

Linwarden is a rootless Linux host inventory and hardening audit CLI. It reads ordinary system files such as `/etc/os-release`, `/etc/ssh/sshd_config`, and selected `/proc/sys` values, then produces Markdown, JSON, or SARIF artifacts for CI, fleet jobs, and GitHub Actions.

The project goal is practical: give maintainers a small, auditable tool that explains risky Linux defaults without needing an agent, daemon, privileged service, external database, or network access.

## Features

- Rootless collection from `/etc`, `/proc`, and procfs sysctl paths.
- Deterministic JSON output for CI pipelines and scheduled host scans.
- Markdown output suitable for GitHub job summaries and issue attachments.
- SARIF output suitable for GitHub-native security ingestion.
- JSON config support for profiles, disabled rules, and justified suppressions.
- Optional effective OpenSSH config collection through `sshd -T`.
- Package update and host firewall posture signals where rootless files expose them.
- Severity scoring with `critical`, `high`, `medium`, and `low` buckets.
- CI-friendly exit thresholds through `--fail-on`.
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

## CLI

```text
linwarden scan [--root PATH] [--proc-root PATH] [--etc-root PATH]
               [--config PATH] [--format markdown|json|sarif]
               [--sshd-mode static|effective|auto] [--sshd-binary PATH]
               [--output PATH]
               [--fail-on off|low|medium|high|critical]
```

Common examples:

```bash
linwarden scan --format markdown --output linwarden-report.md
linwarden scan --format json --fail-on high
linwarden scan --config linwarden.json --format sarif --output linwarden.sarif
linwarden scan --sshd-mode effective --format json
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
| `LNX-FW-001` | medium | Firewall | A known host firewall is disabled. |

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
- Missing files are treated as absent data so scans can run in containers and fixture roots.
- Linwarden is a hardening triage tool, not a full CIS or DISA STIG compliance scanner.

Please report vulnerabilities using [SECURITY.md](SECURITY.md).

## Roadmap

- Optional systemd unit inventory.
- Additional bridge networking and firewall rules.
- Package manager freshness adapters beyond update-notifier status files.
- Signed release artifacts.

## License

MIT. See [LICENSE](LICENSE).
