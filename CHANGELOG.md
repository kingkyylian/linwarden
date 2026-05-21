# Changelog

All notable changes to Linwarden are documented here.

## Unreleased

- Added a Docker daemon config rule for explicitly disabled `userns-remap` when visible from local files.
- Tightened DNF package metadata freshness collection to use explicit `repodata/repomd.xml` or `expired_repos.json` markers instead of cache directory mtimes.
- Refactored rule evaluation around a registry of small rule functions so new checks no longer require editing one large evaluator body.

## 0.13.1 - 2026-05-19

- Prepared the first PyPI trusted-publishing release with refreshed release artifacts and documentation examples.

## 0.13.0 - 2026-05-15

- Added `linwarden profiles` to list built-in scan profile behavior as Markdown or JSON.
- Expanded the container profile to suppress inherited kernel and filesystem sysctl findings for container and image-root scans.
- Added `--vulnerability-feed-format` with support for Linwarden, Trivy, and Grype JSON vulnerability feeds.
- Added Trivy and Grype feed examples to the composite GitHub Action and package vulnerability feed docs.
- Improved package vulnerability remediation when an imported feed entry does not provide a fixed version.

## 0.12.0 - 2026-05-13

- Added bridge interface and forwarding posture checks for container-host scenarios.
- Added `LNX-NET-005`, `LNX-NET-006`, and `LNX-NET-007` for bridge firewall hooks and bridge forwarding.
- Added optional local package vulnerability feed ingestion through `--vulnerability-feed`.
- Added `LNX-PKG-004` for feed-provided package vulnerabilities.
- Expanded JSON host metadata and bumped report schema to `1.6`.

## 0.11.0 - 2026-05-13

- Added rootless detection for enabled systemd services that appear externally bound.
- Added `LNX-SVC-001` for enabled systemd service wildcard binds.
- Expanded JSON host metadata and bumped report schema to `1.5`.

## 0.10.1 - 2026-05-13

- Fixed artifact attestation verification docs to verify release files one at a time.

## 0.10.0 - 2026-05-13

- Added GitHub artifact attestations for tag release assets.

## 0.9.0 - 2026-05-13

- Added a GitHub Actions example for scanning an unpacked container root.
- Added richer Fedora fixture coverage for firewalld and DNF metadata.
- Added richer Arch fixture coverage for Pacman metadata.

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
