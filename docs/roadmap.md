# Roadmap

## Near Term

- Keep release verification tight now that PyPI publishing is live, including post-release install smoke tests.
- Expand fixture-backed distro coverage for package metadata freshness and firewall posture.
- Add static container runtime signals only when the evidence is reliable from files, config, groups, or systemd units.

## Later

- Add more SARIF and JSON report contract tests around externally consumed fields.
- Improve contributor-ready issue scoping from proven fixture gaps.

## Non-Goals

- Linwarden will not become a privileged remediation agent.
- Linwarden will not send telemetry.
- Linwarden will not require a server component.
