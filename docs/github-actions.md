# GitHub Actions

Linwarden can publish SARIF into GitHub code scanning or attach human-readable Markdown to a job summary.

## Code Scanning

Use the composite action when the repository contains a Linux fixture root, image extract, or mounted root prepared by earlier CI steps.

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

      - name: Run Linwarden
        uses: kingkyylian/linwarden@v0.13.0
        with:
          root: tests/fixtures/linux-root
          format: sarif
          fail-on: critical
          upload-sarif: "true"
```

## Unpacked Container Root

Use this pattern when CI builds or pulls a container image and you want Linwarden to inspect the unpacked filesystem without running inside the container.

```yaml
name: Linwarden container root

on:
  pull_request:

permissions:
  contents: read
  security-events: write

jobs:
  scan-container-root:
    runs-on: ubuntu-latest
    steps:
      - name: Checkout
        uses: actions/checkout@v6

      - name: Export image root
        run: |
          set -euo pipefail
          docker pull debian:bookworm-slim
          image_id="$(docker create debian:bookworm-slim)"
          mkdir -p container-root
          docker export "$image_id" | tar -xf - -C container-root
          docker rm "$image_id"

      - name: Run Linwarden
        uses: kingkyylian/linwarden@v0.13.0
        with:
          root: container-root
          format: sarif
          fail-on: high
          upload-sarif: "true"
```

## Mounted Host Paths

Use explicit procfs, sysfs, and `/etc` roots when a job mounts host paths separately.

```yaml
- name: Run Linwarden against mounted host paths
  uses: kingkyylian/linwarden@v0.13.0
  with:
    root: /host
    sys-root: /host/sys
    format: json
    fail-on: high
```

## Local Vulnerability Feed

Pass a generated local JSON feed when an earlier CI step has already matched package vulnerabilities.

```yaml
- name: Run Linwarden with local vulnerability feed
  uses: kingkyylian/linwarden@v0.13.0
  with:
    root: container-root
    vulnerability-feed: linwarden-vulnerabilities.json
    format: sarif
    fail-on: high
    upload-sarif: "true"
```

Use `vulnerability-feed-format: trivy` when the file is Trivy JSON output.

```yaml
- name: Run Linwarden with Trivy JSON
  uses: kingkyylian/linwarden@v0.13.0
  with:
    root: container-root
    vulnerability-feed: trivy-report.json
    vulnerability-feed-format: trivy
    format: sarif
    fail-on: high
    upload-sarif: "true"
```

Use `vulnerability-feed-format: grype` when the file is Grype JSON output.

```yaml
- name: Run Linwarden with Grype JSON
  uses: kingkyylian/linwarden@v0.13.0
  with:
    root: container-root
    vulnerability-feed: grype-report.json
    vulnerability-feed-format: grype
    format: sarif
    fail-on: high
    upload-sarif: "true"
```

Use `vulnerability-feed-format: osv` when the file is OSV Scanner JSON output.

```yaml
- name: Run Linwarden with OSV Scanner JSON
  uses: kingkyylian/linwarden@v0.13.0
  with:
    root: container-root
    vulnerability-feed: osv-scanner-report.json
    vulnerability-feed-format: osv
    format: sarif
    fail-on: high
    upload-sarif: "true"
```

## Markdown Job Summary

Use this workflow for operators who want the report directly in the Actions run.

```yaml
- name: Run Linwarden
  uses: kingkyylian/linwarden@v0.13.0
  with:
    root: tests/fixtures/linux-root
    format: markdown
    fail-on: off
    add-summary: "true"
```

## Effective SSH Context

Use multiline `sshd-match` input when OpenSSH `Match` blocks need a concrete connection context.

```yaml
- name: Run Linwarden with SSH Match context
  uses: kingkyylian/linwarden@v0.13.0
  with:
    root: /
    format: json
    sshd-mode: effective
    sshd-match: |
      user=deploy
      addr=203.0.113.10
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
