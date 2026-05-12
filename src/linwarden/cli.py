from __future__ import annotations

import argparse
import sys
from pathlib import Path
from typing import Optional, Sequence, TextIO

from . import __version__
from .collectors import collect_host_snapshot
from .config import apply_config, default_config, load_config
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
    scan.add_argument("--config", type=Path, help="JSON config file with profile and suppressions")
    scan.add_argument("--format", choices=("json", "markdown", "sarif"), default="markdown")
    scan.add_argument("--output", type=Path, help="write the report to a file instead of stdout")
    scan.add_argument(
        "--fail-on",
        choices=("off", "low", "medium", "high", "critical"),
        default="off",
        help="return exit code 2 when a finding at or above this severity exists",
    )
    return parser


def _scan(args: argparse.Namespace, stdout: TextIO, stderr: TextIO) -> int:
    try:
        config = load_config(args.config) if args.config else default_config()
    except (OSError, ValueError) as exc:
        stderr.write(f"linwarden: {exc}\n")
        return 1

    snapshot = collect_host_snapshot(
        root=args.root,
        proc_root=args.proc_root or args.root / "proc",
        etc_root=args.etc_root or args.root / "etc",
    )
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
