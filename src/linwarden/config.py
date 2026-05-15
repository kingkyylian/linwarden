from __future__ import annotations

import json
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Mapping, Union

from .models import EvaluationResult, Finding, SuppressedFinding


@dataclass(frozen=True)
class ProfileDefinition:
    name: str
    description: str
    suppressions: Mapping[str, str]


PROFILE_CATALOG = {
    "server": ProfileDefinition(
        name="server",
        description="Default profile for general Linux servers; no profile suppressions are applied.",
        suppressions={},
    ),
    "workstation": ProfileDefinition(
        name="workstation",
        description=(
            "Profile for interactive desktops and laptops; no profile suppressions are applied so "
            "SSH, firewall, package, and kernel findings stay visible."
        ),
        suppressions={},
    ),
    "router": ProfileDefinition(
        name="router",
        description="Profile for hosts whose role intentionally routes traffic between interfaces.",
        suppressions={
            "LNX-NET-001": "router profile expects IPv4 forwarding",
            "LNX-NET-003": "router profile expects IPv6 forwarding",
        },
    ),
    "container": ProfileDefinition(
        name="container",
        description=(
            "Profile for container or image-root scans where kernel and filesystem sysctl values "
            "may be inherited from the container host."
        ),
        suppressions={
            "LNX-KRN-001": "container profile may inherit kernel ASLR from the host",
            "LNX-KRN-002": "container profile may inherit low memory mapping policy from the host",
            "LNX-KRN-003": "container profile may inherit kernel pointer visibility from the host",
            "LNX-FS-001": "container profile may inherit hardlink protection from the host",
            "LNX-FS-002": "container profile may inherit symlink protection from the host",
        },
    ),
}


@dataclass(frozen=True)
class ScanConfig:
    profile: str = "server"
    disabled_rules: tuple[str, ...] = ()
    suppressions: dict[str, str] = field(default_factory=dict)


def default_config() -> ScanConfig:
    return ScanConfig()


def profile_catalog() -> tuple[ProfileDefinition, ...]:
    return tuple(PROFILE_CATALOG.values())


def load_config(path: Union[Path, str]) -> ScanConfig:
    payload = json.loads(Path(path).read_text(encoding="utf-8"))
    if not isinstance(payload, dict):
        raise ValueError("config must be a JSON object")

    profile = _string_value(payload.get("profile", "server"), "profile")
    if profile not in PROFILE_CATALOG:
        allowed = ", ".join(sorted(PROFILE_CATALOG))
        raise ValueError(f"unknown profile {profile!r}; expected one of: {allowed}")

    disabled_rules = tuple(
        _string_value(rule_id, "disabled_rules item")
        for rule_id in _list_value(payload.get("disabled_rules", []), "disabled_rules")
    )

    return ScanConfig(
        profile=profile,
        disabled_rules=disabled_rules,
        suppressions=_parse_suppressions(payload.get("suppressions", [])),
    )


def apply_config(findings: list[Finding], config: ScanConfig) -> EvaluationResult:
    active: list[Finding] = []
    suppressed: list[SuppressedFinding] = []
    profile_suppressions = PROFILE_CATALOG[config.profile].suppressions
    disabled_rules = set(config.disabled_rules)

    for finding in findings:
        if finding.rule_id in profile_suppressions:
            suppressed.append(
                _suppressed_finding(
                    finding,
                    source="profile",
                    reason=profile_suppressions[finding.rule_id],
                )
            )
        elif finding.rule_id in disabled_rules:
            suppressed.append(
                _suppressed_finding(
                    finding,
                    source="disabled_rule",
                    reason="rule disabled by config",
                )
            )
        elif finding.rule_id in config.suppressions:
            suppressed.append(
                _suppressed_finding(
                    finding,
                    source="suppression",
                    reason=config.suppressions[finding.rule_id],
                )
            )
        else:
            active.append(finding)

    return EvaluationResult(tuple(active), tuple(suppressed))


def _parse_suppressions(value: Any) -> dict[str, str]:
    if isinstance(value, dict):
        return {
            _string_value(rule_id, "suppression rule_id"): _reason(reason)
            for rule_id, reason in value.items()
        }

    suppressions: dict[str, str] = {}
    for item in _list_value(value, "suppressions"):
        if not isinstance(item, dict):
            raise ValueError("suppressions entries must be objects")
        rule_id = _string_value(item.get("rule_id"), "suppression rule_id")
        reason = _reason(item.get("reason"))
        suppressions[rule_id] = reason
    return suppressions


def _suppressed_finding(finding: Finding, source: str, reason: str) -> SuppressedFinding:
    return SuppressedFinding(
        rule_id=finding.rule_id,
        severity=finding.severity,
        title=finding.title,
        category=finding.category,
        evidence=finding.evidence,
        reason=reason,
        source=source,
    )


def _string_value(value: Any, field_name: str) -> str:
    if not isinstance(value, str) or not value.strip():
        raise ValueError(f"{field_name} must be a non-empty string")
    return value.strip()


def _reason(value: Any) -> str:
    return _string_value(value, "suppression reason")


def _list_value(value: Any, field_name: str) -> list[Any]:
    if not isinstance(value, list):
        raise ValueError(f"{field_name} must be a list")
    return value
