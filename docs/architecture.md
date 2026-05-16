# Architecture

Linwarden is intentionally small. The scanner is a single-process CLI with no daemon, no network calls, and no privileged helper.

## Data Flow

```text
CLI args
  -> collectors.collect_host_snapshot()
  -> optional local package vulnerability feed parsing
  -> rules.evaluate_snapshot()
  -> config.apply_config()
  -> reporters.render_json() or reporters.render_markdown()
  -> stdout or output file
```

## Modules

| Module | Responsibility |
| --- | --- |
| `cli.py` | Argument parsing, output routing, threshold exit codes. |
| `config.py` | Profiles, disabled rules, and justified suppressions. |
| `collectors.py` | Builds a `HostSnapshot` from Linux filesystem inputs. |
| `parsers.py` | Parses small Linux text formats such as `os-release`, `meminfo`, and `mounts`. |
| `rules.py` | Converts a snapshot into actionable findings. |
| `reporters.py` | Converts snapshots and findings into JSON, Markdown, or SARIF artifacts. |
| `models.py` | Dataclasses shared across the scanner. |

## Rootless Collection

The collector reads files that are normally world-readable on Linux hosts:

- `/etc/os-release`
- `/etc/hostname`
- `/etc/ssh/sshd_config`
- `/proc/loadavg`
- `/proc/meminfo`
- `/proc/mounts`
- `/proc/uptime`
- selected `/proc/sys/...` sysctl values
- bridge interfaces from `/sys/class/net/*/bridge` and members from `/sys/class/net/*/brif`
- `/var/lib/update-notifier/updates-available` when present
- package manager metadata markers such as APT update stamps, DNF cache metadata, Pacman sync databases, and APK index caches
- `/etc/ufw/ufw.conf` when present
- `/etc/firewalld/firewalld.conf` and firewalld systemd enablement markers when present
- `/etc/nftables.conf` and nftables systemd enablement markers when present
- enabled systemd service markers under `/etc/systemd/system/*.wants/*.service` and matching unit files when present
- container runtime posture markers from `/etc/docker/daemon.json`, `/etc/group`, and enabled Docker or Podman systemd units when present
- an optional local package vulnerability JSON feed when `--vulnerability-feed` is provided

SSH collection defaults to static file parsing. When `--sshd-mode effective` is selected, Linwarden executes `sshd -T -f <config>` and records `sshd_source` as `effective`.

When `--sshd-match KEY=VALUE` entries are provided, Linwarden passes them to `sshd -T` through OpenSSH `-C` so `Match` blocks can be evaluated for a specific connection context.

Package manager labels are inferred from `/etc/os-release` `ID` and `ID_LIKE` values, then enriched with rootless update counts when a supported status file is present.

Bridge posture detection is static. It reads bridge interfaces from sysfs, bridge firewall hook sysctls from procfs, and per-bridge interface forwarding values from procfs. It does not call `ip`, `bridge`, `sysctl`, Docker, Podman, or Kubernetes tools.

Package vulnerability feed ingestion is explicit and local-only. The CLI reads the JSON file provided through `--vulnerability-feed`, validates the selected `--vulnerability-feed-format`, and converts each entry into normal package findings. Normal scans do not read vulnerability feeds unless the option is present.

Systemd service exposure detection is static. It follows enabled service markers inside the scanned root and flags common wildcard bind options such as `--bind 0.0.0.0` or `--listen [::]:PORT`; it does not call `systemctl` or inspect live sockets.

Container runtime posture detection is static and conservative. It flags explicit Docker or Podman non-loopback TCP API endpoints from configuration or enabled unit files, and explicit non-root Docker group members from `/etc/group`. It does not call Docker, Podman, `systemctl`, or inspect live sockets.

Missing files are treated as absent data, not fatal errors. This keeps the CLI usable in containers, rescue mounts, and partial forensic copies.

## Fixture Roots

Every collector accepts root overrides:

- `--root`
- `--proc-root`
- `--etc-root`
- `--sys-root`

This is the main testability mechanism. A fixture root can emulate Linux files on any development machine.

## Stability Guarantees

- JSON output includes `schema_version`.
- Rule IDs are stable once released.
- Suppressed findings remain visible in JSON and Markdown reports.
- Exit code `2` is reserved for threshold failures.
- Reports are read-only and should not alter host state.
