from __future__ import annotations

from dataclasses import dataclass, field


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
class FindingSummary:
    total: int
    by_severity: dict[str, int]
    score: int
