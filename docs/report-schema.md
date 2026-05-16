# JSON Report Schema

Linwarden JSON reports are intended for CI and fleet ingestion. The current schema version is `1.7`.

## Top-Level Shape

```json
{
  "schema_version": "1.7",
  "host": {},
  "summary": {},
  "findings": [],
  "suppressed_findings": []
}
```

## Host

| Field | Type | Description |
| --- | --- | --- |
| `hostname` | string | Hostname from `/etc/hostname` or local fallback. |
| `os` | object | Parsed `/etc/os-release` key-value data. |
| `kernel_release` | string | Kernel release from procfs or platform fallback. |
| `uptime_seconds` | number | Uptime from `/proc/uptime`. |
| `load_average` | object | One, five, and fifteen minute load averages. |
| `memory` | object | Memory totals in MiB. |
| `mounts` | array | Parsed `/proc/mounts` entries. |
| `sysctls` | object | Selected sysctl values used by rules. |
| `sshd_source` | string | `static` or `effective`. |
| `sshd_match_context` | array | OpenSSH `-C` Match context entries used for effective SSH collection. |
| `package_status` | object | Package manager and update counts when known. |
| `firewall_status` | object | Host firewall provider and enabled state when known. |
| `bridge_interfaces` | array | Linux bridge interfaces detected from sysfs. |
| `systemd_service_exposures` | array | Enabled systemd services with static wildcard bind evidence. |
| `container_runtime_signals` | array | Static container runtime posture signals when visible from local files. |
| `package_vulnerabilities` | array | Package vulnerabilities loaded from an explicit local feed. |

## Package Status

| Field | Type | Description |
| --- | --- | --- |
| `manager` | string | Inferred package manager such as `apt`, `dnf`, `pacman`, `apk`, or `unknown`. |
| `updates_available` | integer or null | Pending package update count when a rootless status source exposes it. |
| `security_updates` | integer or null | Pending security update count when a rootless status source exposes it. |
| `source` | string | Source used for update counts, or `not found`. |
| `metadata_age_days` | integer or null | Age of the newest known local package metadata marker. |
| `metadata_source` | string | Source used for metadata age, or `not found`. |

## Bridge Interface

| Field | Type | Description |
| --- | --- | --- |
| `name` | string | Bridge interface name such as `docker0` or `br0`. |
| `members` | array | Member interface names from sysfs `brif` entries. |
| `ipv4_forwarding` | boolean or null | Per-interface IPv4 forwarding value when available. |
| `ipv6_forwarding` | boolean or null | Per-interface IPv6 forwarding value when available. |
| `source` | string | Sysfs bridge marker path used as evidence. |

## Systemd Service Exposure

| Field | Type | Description |
| --- | --- | --- |
| `name` | string | Service unit name. |
| `bind` | string | Wildcard bind address detected in the service `ExecStart`. |
| `source` | string | Unit file path used as evidence. |
| `enabled_source` | string | Enablement marker path used as evidence. |
| `exec_start` | string | `ExecStart` line that carried the bind evidence. |

## Container Runtime Signal

| Field | Type | Description |
| --- | --- | --- |
| `runtime` | string | Runtime name such as `docker` or `podman`. |
| `signal` | string | Signal type such as `tcp_api` or `docker_group_members`. |
| `evidence` | string | Static evidence read from the scanned root. |
| `source` | string | File path used as evidence. |

## Package Vulnerability

| Field | Type | Description |
| --- | --- | --- |
| `package` | string | Package name from the local vulnerability feed. |
| `installed_version` | string | Installed package version reported by the feed producer. |
| `fixed_version` | string | Version that fixes the vulnerability according to the feed. |
| `vulnerability_id` | string | Vulnerability identifier such as a CVE ID. |
| `severity` | string | `critical`, `high`, `medium`, or `low` from the feed. |
| `summary` | string | Short feed-provided vulnerability summary, or empty string. |
| `url` | string | Supporting URL from the feed, or empty string. |
| `source` | string | Local feed file path used as evidence. |

## Summary

| Field | Type | Description |
| --- | --- | --- |
| `total` | integer | Number of findings. |
| `by_severity` | object | Count by severity. |
| `score` | integer | Score from `0` to `100`. |

## Finding

| Field | Type | Description |
| --- | --- | --- |
| `rule_id` | string | Stable rule identifier. |
| `severity` | string | `critical`, `high`, `medium`, or `low`. |
| `title` | string | Short finding title. |
| `category` | string | Rule area such as `ssh`, `kernel`, or `network`. |
| `evidence` | string | Observed value that triggered the rule. |
| `impact` | string | Why the finding matters. |
| `remediation` | string | Suggested fix. |
| `references` | array | Supporting docs or manual pages. |

## Suppressed Finding

Suppressed findings are excluded from `summary`, `findings`, and threshold exit-code decisions, but remain visible for auditability.

| Field | Type | Description |
| --- | --- | --- |
| `rule_id` | string | Stable rule identifier. |
| `severity` | string | Original finding severity. |
| `title` | string | Original finding title. |
| `category` | string | Original finding category. |
| `evidence` | string | Evidence that would have triggered the rule. |
| `reason` | string | Profile or user-provided justification. |
| `source` | string | `profile`, `disabled_rule`, or `suppression`. |

## SARIF

SARIF output uses SARIF `2.1.0`. Active findings are emitted as SARIF results; suppressed findings are intentionally excluded from SARIF so CI/security ingestion reflects only actionable findings.
