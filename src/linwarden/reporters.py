from __future__ import annotations

import json
from dataclasses import asdict
from typing import List, Tuple, Union

from .models import Finding, HostSnapshot, SuppressedFinding
from .rules import summarize_findings

FindingCollection = Union[List[Finding], Tuple[Finding, ...]]


def render_json(
    snapshot: HostSnapshot,
    findings: FindingCollection,
    suppressed_findings: tuple[SuppressedFinding, ...] = (),
) -> str:
    payload = {
        "schema_version": "1.4",
        "host": _host_payload(snapshot),
        "summary": asdict(summarize_findings(list(findings))),
        "findings": [asdict(finding) for finding in findings],
        "suppressed_findings": [asdict(finding) for finding in suppressed_findings],
    }
    return json.dumps(payload, indent=2, sort_keys=True) + "\n"


def render_markdown(
    snapshot: HostSnapshot,
    findings: FindingCollection,
    suppressed_findings: tuple[SuppressedFinding, ...] = (),
) -> str:
    summary = summarize_findings(list(findings))
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

    if suppressed_findings:
        lines.extend(
            [
                "",
                "## Suppressed Findings",
                "",
                "| Source | Rule | Title | Reason |",
                "| --- | --- | --- | --- |",
            ]
        )
        for suppressed in suppressed_findings:
            lines.append(
                "| "
                + " | ".join(
                    [
                        _cell(suppressed.source),
                        _cell(suppressed.rule_id),
                        _cell(suppressed.title),
                        _cell(suppressed.reason),
                    ]
                )
                + " |"
            )

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


def render_sarif(snapshot: HostSnapshot, findings: FindingCollection) -> str:
    rules = []
    results = []
    for finding in findings:
        rules.append(
            {
                "id": finding.rule_id,
                "name": finding.title,
                "shortDescription": {"text": finding.title},
                "fullDescription": {"text": finding.impact},
                "help": {"text": finding.remediation},
                "properties": {
                    "category": finding.category,
                    "severity": finding.severity,
                    "references": list(finding.references),
                },
            }
        )
        results.append(
            {
                "ruleId": finding.rule_id,
                "level": _sarif_level(finding.severity),
                "message": {"text": f"{finding.title}: {finding.evidence}"},
                "locations": [
                    {
                        "physicalLocation": {
                            "artifactLocation": {
                                "uri": "docs/rules.md"
                            }
                        }
                    }
                ],
                "properties": {
                    "category": finding.category,
                    "severity": finding.severity,
                    "host": snapshot.hostname,
                    "remediation": finding.remediation,
                },
            }
        )

    payload = {
        "version": "2.1.0",
        "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
        "runs": [
            {
                "tool": {
                    "driver": {
                        "name": "Linwarden",
                        "informationUri": "https://github.com/kingkyylian/linwarden",
                        "rules": rules,
                    }
                },
                "results": results,
            }
        ],
    }
    return json.dumps(payload, indent=2, sort_keys=True) + "\n"


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
        "sshd_source": snapshot.sshd_source,
        "sshd_match_context": list(snapshot.sshd_match_context),
        "package_status": asdict(snapshot.package_status),
        "firewall_status": asdict(snapshot.firewall_status),
    }


def _cell(value: str) -> str:
    return value.replace("|", "\\|").replace("\n", " ")


def _sarif_level(severity: str) -> str:
    if severity in {"critical", "high"}:
        return "error"
    if severity == "medium":
        return "warning"
    return "note"
