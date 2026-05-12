# JSON Report Schema

Linwarden JSON reports are intended for CI and fleet ingestion. The current schema version is `1.0`.

## Top-Level Shape

```json
{
  "schema_version": "1.0",
  "host": {},
  "summary": {},
  "findings": []
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
