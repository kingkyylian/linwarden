# Architecture

Linwarden is intentionally small. The scanner is a single-process CLI with no daemon, no network calls, and no privileged helper.

## Data Flow

```text
CLI args
  -> collectors.collect_host_snapshot()
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

Missing files are treated as absent data, not fatal errors. This keeps the CLI usable in containers, rescue mounts, and partial forensic copies.

## Fixture Roots

Every collector accepts root overrides:

- `--root`
- `--proc-root`
- `--etc-root`

This is the main testability mechanism. A fixture root can emulate Linux files on any development machine.

## Stability Guarantees

- JSON output includes `schema_version`.
- Rule IDs are stable once released.
- Suppressed findings remain visible in JSON and Markdown reports.
- Exit code `2` is reserved for threshold failures.
- Reports are read-only and should not alter host state.
