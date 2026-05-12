# GitHub Actions

Linwarden can publish SARIF into GitHub code scanning or attach human-readable Markdown to a job summary.

## Code Scanning

Use this workflow when the repository contains a Linux fixture root, image extract, or mounted root prepared by earlier CI steps.

```yaml
name: Linwarden

on:
  push:
    branches: [main]
  pull_request:

permissions:
  contents: read
  security-events: write

jobs:
  scan:
    runs-on: ubuntu-latest
    steps:
      - name: Checkout
        uses: actions/checkout@v6

      - name: Set up Python
        uses: actions/setup-python@v6
        with:
          python-version: "3.13"

      - name: Install Linwarden from source
        run: python -m pip install .

      - name: Generate SARIF
        run: linwarden scan --root tests/fixtures/linux-root --format sarif --output linwarden.sarif --fail-on critical

      - name: Validate SARIF
        run: python -m json.tool linwarden.sarif > /dev/null

      - name: Upload SARIF
        uses: github/codeql-action/upload-sarif@v4
        with:
          sarif_file: linwarden.sarif
```

## Markdown Job Summary

Use this workflow for operators who want the report directly in the Actions run.

```yaml
- name: Generate Markdown report
  run: linwarden scan --root tests/fixtures/linux-root --format markdown --output linwarden-report.md --fail-on off

- name: Add report to job summary
  run: cat linwarden-report.md >> "$GITHUB_STEP_SUMMARY"
```

## Thresholds

`--fail-on` controls the job exit code:

| Value | Behavior |
| --- | --- |
| `off` | Never fail because of findings. |
| `low` | Fail on any finding. |
| `medium` | Fail on medium, high, or critical findings. |
| `high` | Fail on high or critical findings. |
| `critical` | Fail only on critical findings. |

Linwarden exits with code `2` when the threshold is met. Reserve exit code `1` for usage or collection errors.
