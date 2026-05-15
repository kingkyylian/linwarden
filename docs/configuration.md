# Configuration

Linwarden uses JSON config so it can stay dependency-free on Python 3.9+.

## Example

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

Use it with:

```bash
linwarden scan --config linwarden.json --format markdown
```

List the built-in profile catalog with:

```bash
linwarden profiles
linwarden profiles --format json
```

## Fields

| Field | Type | Required | Description |
| --- | --- | --- | --- |
| `profile` | string | no | One of `server`, `workstation`, `router`, or `container`. Defaults to `server`. |
| `disabled_rules` | array | no | Rule IDs to hide with source `disabled_rule`. |
| `suppressions` | array or object | no | Rule-specific suppressions with required justification text. |

## Profiles

| Profile | Intended use | Suppressed rules |
| --- | --- | --- |
| `server` | General Linux servers. | None. |
| `workstation` | Interactive desktops and laptops. SSH, firewall, package, and kernel findings remain visible. | None. |
| `router` | Hosts that intentionally route traffic between interfaces. | `LNX-NET-001`, `LNX-NET-003`. |
| `container` | Container or image-root scans where kernel and filesystem sysctl values may be inherited from the host. | `LNX-KRN-001`, `LNX-KRN-002`, `LNX-KRN-003`, `LNX-FS-001`, `LNX-FS-002`. |

Profile suppressions are still emitted as suppressed findings in JSON and Markdown reports. Use `disabled_rules` or `suppressions` only for local exceptions that are not part of the selected host role.

## Suppression Auditability

Suppressed findings are excluded from active score and `--fail-on` decisions. They are still emitted in JSON and Markdown reports with:

- rule ID
- severity
- evidence
- suppression source
- reason

SARIF output contains active findings only.
