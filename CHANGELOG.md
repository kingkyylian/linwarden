# Changelog

All notable changes to Linwarden are documented here.

## 0.3.0 - 2026-05-12

- Added Ruff and mypy development checks.
- Added SARIF upload in GitHub Actions on pushes.
- Added static SSH `Include` parsing for fixture and offline config roots.
- Aligned static SSH parsing with OpenSSH first-value-wins behavior.
- Added `LNX-SSH-003` for `PermitEmptyPasswords yes`.
- Added config validation tests for unknown profiles and missing suppression reasons.

## 0.2.0 - 2026-05-12

- Added JSON config support through `--config`.
- Added rule suppression with mandatory justification text.
- Added built-in profiles for `server`, `workstation`, `router`, and `container`.
- Added SARIF output for GitHub-native security workflows.
- Added IPv6 forwarding and redirect rules.
- Added filesystem hardlink and symlink protection rules.
- Added kernel pointer exposure rule.
- Added suppressed finding visibility in JSON and Markdown reports.

## 0.1.0 - 2026-05-12

- Initial rootless Linux host scanner.
- Added `/etc/os-release`, hostname, load average, memory, mounts, SSH, and sysctl collection.
- Added six built-in SSH, kernel, and network hardening rules.
- Added JSON and Markdown reporters.
- Added CLI threshold exit behavior with `--fail-on`.
- Added fixture-based test suite and GitHub Actions CI.
