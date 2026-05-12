# Linwarden

Linwarden is a rootless Linux host inventory and hardening audit CLI. It reads ordinary system files such as `/etc/os-release`, `/etc/ssh/sshd_config`, and selected `/proc/sys` values, then produces a human-readable Markdown report or a stable JSON artifact for CI, fleet jobs, and GitHub Actions.

The project goal is practical: give maintainers a small, auditable tool that explains risky Linux defaults without needing an agent, daemon, privileged service, external database, or network access.

## Features

- Rootless collection from `/etc`, `/proc`, and procfs sysctl paths.
- Deterministic JSON output for CI pipelines and scheduled host scans.
- Markdown output suitable for GitHub job summaries and issue attachments.
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
               [--format markdown|json] [--output PATH]
               [--fail-on off|low|medium|high|critical]
```

Common examples:

```bash
linwarden scan --format markdown --output linwarden-report.md
linwarden scan --format json --fail-on high
linwarden scan --root /mnt/server-image --format json
linwarden scan --proc-root /host/proc --etc-root /host/etc --format markdown
```

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
| `LNX-KRN-001` | high | Kernel | `kernel.randomize_va_space=0` disables ASLR. |
| `LNX-KRN-002` | high | Kernel | `vm.mmap_min_addr` is below `65536`. |
| `LNX-NET-001` | medium | Network | `net.ipv4.ip_forward=1` is enabled. |
| `LNX-NET-002` | low | Network | `net.ipv4.conf.all.accept_redirects=1` is enabled. |

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
  collectors.py   host snapshot collection
  parsers.py      small parsers for Linux files
  rules.py        built-in hardening checks
  reporters.py    JSON and Markdown rendering
  models.py       report data structures
tests/
  fixtures/       deterministic Linux fixture root
docs/
  architecture.md implementation overview
  rules.md        rule catalog
  report-schema.md JSON report contract
```

## Development

```bash
make test
make compile
make smoke
```

No network services or privileged permissions are required for the test suite.

## Security Model

Linwarden is read-only by default. It does not modify host state, load kernel modules, call package managers, or send telemetry. Reports can contain host configuration details, so treat generated artifacts as operationally sensitive.

## Known Limits

- SSH parsing reads the visible `sshd_config` file and does not execute `sshd -T`.
- `Include` and `Match` behavior may differ from the static SSH evidence shown in a report.
- Missing files are treated as absent data so scans can run in containers and fixture roots.
- Linwarden is a hardening triage tool, not a full CIS or DISA STIG compliance scanner.

Please report vulnerabilities using [SECURITY.md](SECURITY.md).

## Roadmap

- Optional systemd unit inventory.
- Additional sysctl rules for IPv6 and bridge networking.
- Package manager freshness adapters for Debian, Ubuntu, Fedora, and Arch.
- SARIF reporter for GitHub code scanning workflows.
- Rule suppression file with explicit justifications.

## License

MIT. See [LICENSE](LICENSE).
