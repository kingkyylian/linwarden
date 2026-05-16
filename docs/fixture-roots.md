# Fixture Roots

The distro fixture roots are synthetic, sanitized Linux filesystem extracts used only for tests. They are not copied from a live host and do not contain real hostnames, users, secrets, package databases, logs, tokens, SSH keys, or machine identifiers.

Each fixture keeps only small text markers that exercise Linwarden's rootless collectors:

- `/etc/os-release`
- `/etc/hostname`
- `/etc/ssh/sshd_config`
- selected `/proc` files and procfs sysctl values
- package manager metadata markers
- firewall configuration or enablement markers
- systemd service markers where the distribution commonly uses systemd

## Fixture Inventory

| Fixture | Origin model | Sanitization notes | Coverage |
| --- | --- | --- | --- |
| `tests/fixtures/debian-root` | Synthetic Debian 12-style server root. | Hostname, update counts, procfs values, and package metadata are fabricated. | APT metadata, update-notifier counts, disabled UFW, SSH password auth, procfs sysctls. |
| `tests/fixtures/fedora-root` | Synthetic Fedora-style server root. | Firewalld and systemd markers are small hand-written files, not copied unit databases. | DNF metadata, enabled firewalld, enabled wildcard-bound service, SSH MaxAuthTries finding. |
| `tests/fixtures/arch-root` | Synthetic Arch-style rolling root. | Pacman sync database files are marker files without package data. | Pacman metadata, enabled nftables marker, SSH TCP forwarding, IPv4 redirect sysctl, bridge forwarding. |
| `tests/fixtures/alpine-root` | Synthetic Alpine-style minimal root. | APK index is a marker file and procfs values are fabricated. | APK metadata, nftables config-only detection, low `vm.mmap_min_addr`, IPv6 redirect sysctl. |

## Rules

- Keep fixtures small and deterministic.
- Do not add files copied from a real machine unless they are fully reviewed and sanitized.
- Do not include `.env`, keys, tokens, logs, shell histories, real usernames, real hostnames, or machine IDs.
- Prefer explicit marker files over large package manager caches.
