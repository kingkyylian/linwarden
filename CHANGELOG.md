# Changelog

All notable changes to Linwarden are documented here.

## 0.8.0 - 2026-05-13

- Added `LNX-SSH-004` for `MaxAuthTries` values above `4`.
- Added `LNX-SSH-005` for broadly enabled SSH TCP forwarding.
- Added CI coverage that runs the local composite GitHub Action through SARIF and Markdown-summary paths.

## 0.7.0 - 2026-05-12

- Added a composite GitHub Action wrapper for running Linwarden with `uses: kingkyylian/linwarden@v0.7.0`.
- Added action inputs for report format, output path, fail threshold, config, SSH mode, SSH Match context, SARIF upload, and Markdown job summaries.
- Updated GitHub Actions docs with copy-paste workflows for code scanning, job summaries, and effective SSH context.

## 0.6.0 - 2026-05-12

- Added OpenSSH `sshd -T -C` Match context support through repeatable `--sshd-match KEY=VALUE`.
- Added firewalld and nftables rootless firewall provider detection.
- Added release checksum manifest generation and optional GPG detached checksum signatures.
- Added opt-in PyPI trusted publishing in the tag release workflow.
- Expanded JSON SSH metadata and bumped report schema to `1.4`.

## 0.5.0 - 2026-05-12

- Added package metadata age collection for APT, DNF, Pacman, and APK cache markers.
- Added `LNX-PKG-003` for stale package metadata.
- Expanded JSON package status metadata and bumped report schema to `1.3`.

## 0.4.0 - 2026-05-12

- Added explicit `--sshd-mode effective` and `--sshd-mode auto` support using `sshd -T`.
- Added `--sshd-binary` for testable and non-standard OpenSSH installations.
- Added package update signal collection from `update-notifier` status files.
- Added host firewall signal collection for UFW.
- Added `LNX-PKG-001`, `LNX-PKG-002`, and `LNX-FW-001`.
- Added minimal distro fixture coverage for Debian, Fedora, Arch, and Alpine roots.
- Added tag-based GitHub Release artifact workflow.
- Expanded JSON host metadata with SSH source, package status, and firewall status.

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
