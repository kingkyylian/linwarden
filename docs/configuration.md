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

## Fields

| Field | Type | Required | Description |
| --- | --- | --- | --- |
| `profile` | string | no | One of `server`, `workstation`, `router`, or `container`. Defaults to `server`. |
| `disabled_rules` | array | no | Rule IDs to hide with source `disabled_rule`. |
| `suppressions` | array or object | no | Rule-specific suppressions with required justification text. |

## Profiles

| Profile | Suppressed rules |
| --- | --- |
| `server` | None. |
| `workstation` | None. |
| `router` | `LNX-NET-001`, `LNX-NET-003`. |
| `container` | `LNX-KRN-001`, `LNX-KRN-003`. |

## Suppression Auditability

Suppressed findings are excluded from active score and `--fail-on` decisions. They are still emitted in JSON and Markdown reports with:

- rule ID
- severity
- evidence
- suppression source
- reason

SARIF output contains active findings only.
