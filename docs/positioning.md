# Positioning

## Category

Rootless Linux hardening scanner for CI and fleet triage.

## Audience

- DevOps and SRE teams that own Linux servers but do not want another daemon.
- Security engineers who need lightweight posture artifacts in pull requests and scheduled jobs.
- Self-hosted operators who want an understandable report without granting root.
- Image maintainers who scan mounted roots before publishing.

## Primary Message

Linwarden gives you explainable Linux hardening findings without an agent, daemon, privileged helper, database, network service, or runtime dependencies.

## Supporting Messages

- Read-only by default.
- Works on live hosts, mounted roots, containers, and fixture directories.
- Produces Markdown for humans, JSON for automation, and SARIF for GitHub code scanning.
- Keeps findings small enough to review and fix.
- Complements compliance platforms instead of pretending to replace them.

## Proof Points

- Python 3.9-3.13 CI matrix.
- Fixture-backed parser, collector, reporter, and rule tests.
- SARIF upload smoke test in CI.
- Release checksums and optional detached GPG checksum signatures.
- Zero runtime dependencies.

## Avoid

- Do not call Linwarden a full compliance scanner.
- Do not promise CVE coverage.
- Do not imply host firewall service state when only config files are visible.
- Do not describe it as an EDR, SIEM, CSPM, or vulnerability scanner.
