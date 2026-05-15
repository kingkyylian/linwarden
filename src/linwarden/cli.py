from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path
from typing import Optional, Sequence, TextIO

from . import __version__
from .collectors import collect_host_snapshot
from .config import apply_config, default_config, load_config, profile_catalog
from .reporters import render_json, render_markdown, render_sarif
from .rules import evaluate_snapshot, threshold_is_met


def main(
    argv: Optional[Sequence[str]] = None,
    stdout: Optional[TextIO] = None,
    stderr: Optional[TextIO] = None,
) -> int:
    out = stdout if stdout is not None else sys.stdout
    err = stderr if stderr is not None else sys.stderr
    parser = _build_parser()
    args = parser.parse_args(argv)

    if args.command == "scan":
        return _scan(args, out, err)
    if args.command == "profiles":
        return _profiles(args, out)

    parser.print_help(err)
    return 1


def _build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="linwarden",
        description="Rootless Linux host inventory and hardening audit CLI.",
    )
    parser.add_argument("--version", action="version", version=f"linwarden {__version__}")
    subparsers = parser.add_subparsers(dest="command")

    scan = subparsers.add_parser("scan", help="collect a host snapshot and evaluate built-in checks")
    scan.add_argument("--root", type=Path, default=Path("/"), help="filesystem root to inspect")
    scan.add_argument("--proc-root", type=Path, help="override procfs root")
    scan.add_argument("--etc-root", type=Path, help="override /etc root")
    scan.add_argument("--sys-root", type=Path, help="override sysfs root")
    scan.add_argument("--config", type=Path, help="JSON config file with profile and suppressions")
    scan.add_argument("--vulnerability-feed", type=Path, help="local package vulnerability feed JSON file")
    scan.add_argument(
        "--vulnerability-feed-format",
        choices=("linwarden", "trivy", "grype"),
        default="linwarden",
        help="format of --vulnerability-feed",
    )
    scan.add_argument("--sshd-mode", choices=("static", "effective", "auto"), default="static")
    scan.add_argument("--sshd-binary", default="sshd", help="sshd binary to use with effective or auto mode")
    scan.add_argument(
        "--sshd-match",
        action="append",
        default=[],
        metavar="KEY=VALUE",
        help="OpenSSH -C Match context entry for effective or auto SSH collection",
    )
    scan.add_argument("--format", choices=("json", "markdown", "sarif"), default="markdown")
    scan.add_argument("--output", type=Path, help="write the report to a file instead of stdout")
    scan.add_argument(
        "--fail-on",
        choices=("off", "low", "medium", "high", "critical"),
        default="off",
        help="return exit code 2 when a finding at or above this severity exists",
    )

    profiles = subparsers.add_parser("profiles", help="list built-in scan profiles")
    profiles.add_argument("--format", choices=("json", "markdown"), default="markdown")
    return parser


def _profiles(args: argparse.Namespace, stdout: TextIO) -> int:
    profiles = profile_catalog()
    if args.format == "json":
        payload = {
            "profiles": [
                {
                    "name": profile.name,
                    "description": profile.description,
                    "suppressed_rules": [
                        {"rule_id": rule_id, "reason": reason}
                        for rule_id, reason in sorted(profile.suppressions.items())
                    ],
                }
                for profile in profiles
            ]
        }
        stdout.write(json.dumps(payload, indent=2, sort_keys=True) + "\n")
        return 0

    lines = [
        "# Linwarden Profiles",
        "",
        "| Profile | Description | Suppressed Rules |",
        "| --- | --- | --- |",
    ]
    for profile in profiles:
        suppressed = ", ".join(sorted(profile.suppressions)) or "None"
        lines.append(f"| {profile.name} | {_markdown_cell(profile.description)} | {suppressed} |")
    stdout.write("\n".join(lines) + "\n")
    return 0


def _markdown_cell(value: str) -> str:
    return value.replace("|", "\\|").replace("\n", " ")


def _scan(args: argparse.Namespace, stdout: TextIO, stderr: TextIO) -> int:
    try:
        config = load_config(args.config) if args.config else default_config()
    except (OSError, ValueError) as exc:
        stderr.write(f"linwarden: {exc}\n")
        return 1

    try:
        snapshot = collect_host_snapshot(
            root=args.root,
            proc_root=args.proc_root or args.root / "proc",
            etc_root=args.etc_root or args.root / "etc",
            sys_root=args.sys_root or args.root / "sys",
            sshd_mode=args.sshd_mode,
            sshd_binary=args.sshd_binary,
            sshd_match_context=tuple(args.sshd_match),
            vulnerability_feed=args.vulnerability_feed,
            vulnerability_feed_format=args.vulnerability_feed_format,
        )
    except (OSError, RuntimeError, ValueError) as exc:
        stderr.write(f"linwarden: {exc}\n")
        return 1
    result = apply_config(evaluate_snapshot(snapshot), config)

    if args.format == "json":
        report = render_json(
            snapshot,
            result.active_findings,
            suppressed_findings=result.suppressed_findings,
        )
    elif args.format == "sarif":
        report = render_sarif(snapshot, result.active_findings)
    else:
        report = render_markdown(
            snapshot,
            result.active_findings,
            suppressed_findings=result.suppressed_findings,
        )

    if args.output:
        args.output.parent.mkdir(parents=True, exist_ok=True)
        args.output.write_text(report, encoding="utf-8")
    else:
        stdout.write(report)

    return 2 if threshold_is_met(list(result.active_findings), args.fail_on) else 0
