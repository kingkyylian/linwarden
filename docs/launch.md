# Launch Kit

Use this page when announcing Linwarden in GitHub, social posts, newsletters, or community forums.

## One-Line Description

Linwarden is a rootless Linux hardening scanner that emits Markdown, JSON, and SARIF without an agent, daemon, database, network service, or privileged helper.

## Short Post

Linwarden is a small Linux hardening scanner for CI and fleet triage.

It reads ordinary `/etc`, `/proc`, and `/sys` files, explains risky SSH/kernel/network/filesystem/package/firewall defaults, and emits Markdown, JSON, or SARIF. It is read-only, rootless by default, and works against live hosts, mounted roots, containers, and test fixtures.

Repository: https://github.com/kingkyylian/linwarden
PyPI: https://pypi.org/project/linwarden/

Install:

```bash
python3 -m pip install linwarden
```

## Show HN Draft

Title:

```text
Show HN: Linwarden, a rootless Linux hardening scanner for CI
```

Body:

```text
I built Linwarden as a small read-only Linux hardening scanner for teams that want a quick posture signal without installing an agent or running privileged CI.

It reads ordinary files under /etc, /proc, and /sys, evaluates explainable rules, and emits Markdown, JSON, or SARIF for GitHub code scanning. It can also scan mounted roots and fixture directories, which makes it useful for image checks and offline analysis.

It is not meant to replace CIS/STIG tooling. The goal is fast, auditable triage with stable artifacts.

Install: python3 -m pip install linwarden
```

## Reddit Draft

```text
I'm building Linwarden, a rootless Linux hardening scanner for CI and small fleet triage.

It does not install an agent or daemon. It reads normal /etc, /proc, and /sys files, checks common SSH/kernel/network/filesystem/package/firewall posture issues, and emits Markdown, JSON, or SARIF.

Use cases I'm targeting:
- GitHub Actions code scanning via SARIF
- golden image checks
- mounted-root/offline analysis
- quick self-hosted server posture reports

Feedback on useful Linux hardening rules and distro fixtures would be valuable.
```

## Maintainer Checklist

- Pin the current release tag.
- Attach `SHA256SUMS` and, if configured, `SHA256SUMS.asc`.
- Confirm PyPI install smoke for the current version.
- Add a terminal GIF or screenshot showing `linwarden scan --format markdown`.
- Link to [docs/github-actions.md](github-actions.md) from the release notes.
- Open contributor-friendly issues from [docs/contributor-ideas.md](contributor-ideas.md).
