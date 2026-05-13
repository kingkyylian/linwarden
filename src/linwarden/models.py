from __future__ import annotations

from dataclasses import dataclass, field
from typing import Optional


@dataclass(frozen=True)
class LoadAverage:
    one_minute: float
    five_minutes: float
    fifteen_minutes: float


@dataclass(frozen=True)
class MemoryInfo:
    total_mib: int
    available_mib: int
    swap_total_mib: int
    swap_free_mib: int


@dataclass(frozen=True)
class Mount:
    source: str
    mount_point: str
    filesystem: str
    options: tuple[str, ...]


@dataclass(frozen=True)
class PackageStatus:
    manager: str
    updates_available: Optional[int]
    security_updates: Optional[int]
    source: str
    metadata_age_days: Optional[int] = None
    metadata_source: str = "not found"


@dataclass(frozen=True)
class FirewallStatus:
    provider: str
    enabled: Optional[bool]
    source: str


@dataclass(frozen=True)
class BridgeInterface:
    name: str
    members: tuple[str, ...]
    ipv4_forwarding: Optional[bool]
    ipv6_forwarding: Optional[bool]
    source: str


@dataclass(frozen=True)
class SystemdServiceExposure:
    name: str
    bind: str
    source: str
    enabled_source: str
    exec_start: str


@dataclass(frozen=True)
class PackageVulnerability:
    package: str
    installed_version: str
    fixed_version: str
    vulnerability_id: str
    severity: str
    summary: str
    url: str
    source: str


@dataclass(frozen=True)
class HostSnapshot:
    hostname: str
    os_release: dict[str, str]
    kernel_release: str
    uptime_seconds: float
    load_average: LoadAverage
    memory: MemoryInfo
    mounts: tuple[Mount, ...]
    sysctls: dict[str, str]
    sshd_options: dict[str, str]
    sshd_source: str
    sshd_match_context: tuple[str, ...]
    package_status: PackageStatus
    firewall_status: FirewallStatus
    bridge_interfaces: tuple[BridgeInterface, ...]
    systemd_service_exposures: tuple[SystemdServiceExposure, ...]
    package_vulnerabilities: tuple[PackageVulnerability, ...]


@dataclass(frozen=True)
class Finding:
    rule_id: str
    severity: str
    title: str
    category: str
    evidence: str
    impact: str
    remediation: str
    references: tuple[str, ...] = field(default_factory=tuple)


@dataclass(frozen=True)
class SuppressedFinding:
    rule_id: str
    severity: str
    title: str
    category: str
    evidence: str
    reason: str
    source: str


@dataclass(frozen=True)
class EvaluationResult:
    active_findings: tuple[Finding, ...]
    suppressed_findings: tuple[SuppressedFinding, ...]


@dataclass(frozen=True)
class FindingSummary:
    total: int
    by_severity: dict[str, int]
    score: int
