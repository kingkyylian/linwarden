from __future__ import annotations

from dataclasses import asdict
import json

from .models import Finding, HostSnapshot
from .rules import summarize_findings


def render_json(snapshot: HostSnapshot, findings: list[Finding]) -> str:
    payload = {
        "schema_version": "1.0",
        "host": _host_payload(snapshot),
        "summary": asdict(summarize_findings(findings)),
        "findings": [asdict(finding) for finding in findings],
    }
    return json.dumps(payload, indent=2, sort_keys=True) + "\n"


def render_markdown(snapshot: HostSnapshot, findings: list[Finding]) -> str:
    summary = summarize_findings(findings)
    lines = [
        "# Linwarden Report",
        "",
        f"- Host: `{snapshot.hostname}`",
        f"- OS: `{snapshot.os_release.get('PRETTY_NAME', 'unknown')}`",
        f"- Kernel: `{snapshot.kernel_release}`",
        f"- Score: `{summary.score}/100`",
        f"- Findings: `{summary.total}`",
        "",
        "## Findings",
        "",
        "| Severity | Rule | Title | Evidence |",
        "| --- | --- | --- | --- |",
    ]

    if findings:
        for finding in findings:
            lines.append(
                "| "
                + " | ".join(
                    [
                        _cell(finding.severity.upper()),
                        _cell(finding.rule_id),
                        _cell(finding.title),
                        _cell(finding.evidence),
                    ]
                )
                + " |"
            )
    else:
        lines.append("| OK | - | No findings | - |")

    lines.extend(["", "## Remediation", ""])
    for finding in findings:
        lines.extend(
            [
                f"### {finding.rule_id}: {finding.title}",
                "",
                f"Impact: {finding.impact}",
                "",
                f"Fix: {finding.remediation}",
                "",
            ]
        )

    return "\n".join(lines).rstrip() + "\n"


def _host_payload(snapshot: HostSnapshot) -> dict[str, object]:
    return {
        "hostname": snapshot.hostname,
        "os": snapshot.os_release,
        "kernel_release": snapshot.kernel_release,
        "uptime_seconds": snapshot.uptime_seconds,
        "load_average": asdict(snapshot.load_average),
        "memory": asdict(snapshot.memory),
        "mounts": [asdict(mount) for mount in snapshot.mounts],
        "sysctls": snapshot.sysctls,
    }


def _cell(value: str) -> str:
    return value.replace("|", "\\|").replace("\n", " ")
