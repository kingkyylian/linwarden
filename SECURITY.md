# Security Policy

## Supported Versions

Linwarden is pre-1.0. Security fixes are applied to the `main` branch until release branches exist.

## Reporting a Vulnerability

Please do not open a public issue for a vulnerability. Use GitHub private vulnerability reporting if available on the repository, or contact the maintainers through the security contact listed in the repository profile.

Include:

- Affected version or commit.
- Operating system and Python version.
- Minimal reproduction steps.
- Whether the issue exposes sensitive host data, writes host state, or affects CI exit behavior.

## Scope

In scope:

- Unexpected host writes.
- Path traversal in report output handling.
- Incorrect severity threshold exit behavior.
- Report content that leaks more data than documented.

Out of scope:

- Findings that are intentionally informational.
- Vulnerabilities in local Python installations.
- Reports generated from untrusted fixture roots supplied by the caller.
