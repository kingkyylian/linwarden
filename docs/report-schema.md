# JSON Report Schema

Linwarden JSON reports are intended for CI and fleet ingestion. The current schema version is `1.3`.

## Top-Level Shape

```json
{
  "schema_version": "1.3",
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
| `package_status` | object | Package manager and update counts when known. |
| `firewall_status` | object | Host firewall provider and enabled state when known. |

## Package Status

| Field | Type | Description |
| --- | --- | --- |
| `manager` | string | Inferred package manager such as `apt`, `dnf`, `pacman`, `apk`, or `unknown`. |
| `updates_available` | integer or null | Pending package update count when a rootless status source exposes it. |
| `security_updates` | integer or null | Pending security update count when a rootless status source exposes it. |
| `source` | string | Source used for update counts, or `not found`. |
| `metadata_age_days` | integer or null | Age of the newest known local package metadata marker. |
| `metadata_source` | string | Source used for metadata age, or `not found`. |

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
