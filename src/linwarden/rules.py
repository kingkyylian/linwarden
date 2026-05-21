from __future__ import annotations

from collections.abc import Callable, Iterable
from dataclasses import dataclass
from typing import Optional

from .models import Finding, FindingSummary, HostSnapshot

SEVERITY_ORDER = {"low": 1, "medium": 2, "high": 3, "critical": 4}
SCORE_WEIGHTS = {"low": 3, "medium": 10, "high": 20, "critical": 35}
MAX_AUTH_TRIES_LIMIT = 4

RuleEvaluator = Callable[[HostSnapshot], Iterable[Finding]]


@dataclass(frozen=True)
class RuleDefinition:
    rule_id: str
    category: str
    evaluate: RuleEvaluator


def evaluate_snapshot(snapshot: HostSnapshot) -> list[Finding]:
    findings: list[Finding] = []
    for rule in RULES:
        findings.extend(rule.evaluate(snapshot))
    return findings


def _ssh_root_login(snapshot: HostSnapshot) -> tuple[Finding, ...]:
    permit_root_login = snapshot.sshd_options.get("permitrootlogin", "not set").lower()
    if permit_root_login != "yes":
        return ()
    return (
        Finding(
            rule_id="LNX-SSH-001",
            severity="high",
            title="SSH root login is permitted",
            category="ssh",
            evidence=f"PermitRootLogin {permit_root_login}",
            impact="Remote attackers can attempt direct privileged logins instead of going through named accounts.",
            remediation="Set PermitRootLogin no in sshd_config and reload sshd.",
            references=("man:sshd_config(5)",),
        ),
    )


def _ssh_password_authentication(snapshot: HostSnapshot) -> tuple[Finding, ...]:
    password_auth = snapshot.sshd_options.get("passwordauthentication", "not set").lower()
    if password_auth != "yes":
        return ()
    return (
        Finding(
            rule_id="LNX-SSH-002",
            severity="medium",
            title="SSH password authentication is enabled",
            category="ssh",
            evidence=f"PasswordAuthentication {password_auth}",
            impact="Password-based SSH increases exposure to credential stuffing and weak password attacks.",
            remediation="Prefer key-based SSH and set PasswordAuthentication no after confirming access.",
            references=("man:sshd_config(5)",),
        ),
    )


def _ssh_empty_passwords(snapshot: HostSnapshot) -> tuple[Finding, ...]:
    permit_empty_passwords = snapshot.sshd_options.get("permitemptypasswords", "not set").lower()
    if permit_empty_passwords != "yes":
        return ()
    return (
        Finding(
            rule_id="LNX-SSH-003",
            severity="high",
            title="SSH permits empty passwords",
            category="ssh",
            evidence=f"PermitEmptyPasswords {permit_empty_passwords}",
            impact="Accounts with empty passwords can authenticate over SSH without a credential secret.",
            remediation="Set PermitEmptyPasswords no in sshd_config and reload sshd.",
            references=("man:sshd_config(5)",),
        ),
    )


def _ssh_max_auth_tries(snapshot: HostSnapshot) -> tuple[Finding, ...]:
    max_auth_tries = _int_or_none(snapshot.sshd_options.get("maxauthtries"))
    if max_auth_tries is None or max_auth_tries <= MAX_AUTH_TRIES_LIMIT:
        return ()
    return (
        Finding(
            rule_id="LNX-SSH-004",
            severity="medium",
            title="SSH allows too many authentication attempts",
            category="ssh",
            evidence=f"MaxAuthTries {max_auth_tries}",
            impact=(
                "Allowing many authentication attempts per connection increases exposure "
                "to password guessing and noisy credential attacks."
            ),
            remediation=f"Set MaxAuthTries {MAX_AUTH_TRIES_LIMIT} or lower in sshd_config and reload sshd.",
            references=("man:sshd_config(5)",),
        ),
    )


def _ssh_tcp_forwarding(snapshot: HostSnapshot) -> tuple[Finding, ...]:
    allow_tcp_forwarding = snapshot.sshd_options.get("allowtcpforwarding", "not set").lower()
    if allow_tcp_forwarding not in {"yes", "all"}:
        return ()
    return (
        Finding(
            rule_id="LNX-SSH-005",
            severity="medium",
            title="SSH TCP forwarding is broadly enabled",
            category="ssh",
            evidence=f"AllowTcpForwarding {allow_tcp_forwarding}",
            impact=(
                "SSH users can tunnel arbitrary TCP connections through the host, "
                "which may bypass network controls or expose internal services."
            ),
            remediation="Set AllowTcpForwarding no unless SSH tunneling is explicitly required for this host.",
            references=("man:sshd_config(5)",),
        ),
    )


def _kernel_aslr(snapshot: HostSnapshot) -> tuple[Finding, ...]:
    randomize_va_space = snapshot.sysctls.get("kernel.randomize_va_space")
    if randomize_va_space != "0":
        return ()
    return (
        Finding(
            rule_id="LNX-KRN-001",
            severity="high",
            title="Address space layout randomization is disabled",
            category="kernel",
            evidence="kernel.randomize_va_space=0",
            impact="Memory corruption exploits become easier when process address layouts are predictable.",
            remediation="Set kernel.randomize_va_space=2 with sysctl and persist it under /etc/sysctl.d/.",
            references=("https://docs.kernel.org/admin-guide/sysctl/kernel.html",),
        ),
    )


def _network_ipv4_forwarding(snapshot: HostSnapshot) -> tuple[Finding, ...]:
    ip_forward = snapshot.sysctls.get("net.ipv4.ip_forward")
    if ip_forward != "1":
        return ()
    return (
        Finding(
            rule_id="LNX-NET-001",
            severity="medium",
            title="IPv4 forwarding is enabled",
            category="network",
            evidence="net.ipv4.ip_forward=1",
            impact="The host can route traffic between interfaces, which broadens blast radius if unintended.",
            remediation="Set net.ipv4.ip_forward=0 unless this system is intentionally acting as a router.",
            references=("https://docs.kernel.org/networking/ip-sysctl.html",),
        ),
    )


def _network_ipv4_redirects(snapshot: HostSnapshot) -> tuple[Finding, ...]:
    accept_redirects = snapshot.sysctls.get("net.ipv4.conf.all.accept_redirects")
    if accept_redirects != "1":
        return ()
    return (
        Finding(
            rule_id="LNX-NET-002",
            severity="low",
            title="IPv4 ICMP redirects are accepted",
            category="network",
            evidence="net.ipv4.conf.all.accept_redirects=1",
            impact="Malicious redirects can influence host routing decisions on hostile networks.",
            remediation="Set net.ipv4.conf.all.accept_redirects=0 unless redirects are explicitly required.",
            references=("https://docs.kernel.org/networking/ip-sysctl.html",),
        ),
    )


def _network_ipv6_forwarding(snapshot: HostSnapshot) -> tuple[Finding, ...]:
    ipv6_forwarding = snapshot.sysctls.get("net.ipv6.conf.all.forwarding")
    if ipv6_forwarding != "1":
        return ()
    return (
        Finding(
            rule_id="LNX-NET-003",
            severity="medium",
            title="IPv6 forwarding is enabled",
            category="network",
            evidence="net.ipv6.conf.all.forwarding=1",
            impact="The host can route IPv6 traffic between interfaces, which may be unintended on non-router systems.",
            remediation=(
                "Set net.ipv6.conf.all.forwarding=0 unless this system is intentionally "
                "acting as an IPv6 router."
            ),
            references=("https://docs.kernel.org/networking/ip-sysctl.html",),
        ),
    )


def _network_ipv6_redirects(snapshot: HostSnapshot) -> tuple[Finding, ...]:
    ipv6_accept_redirects = snapshot.sysctls.get("net.ipv6.conf.all.accept_redirects")
    if ipv6_accept_redirects != "1":
        return ()
    return (
        Finding(
            rule_id="LNX-NET-004",
            severity="low",
            title="IPv6 ICMP redirects are accepted",
            category="network",
            evidence="net.ipv6.conf.all.accept_redirects=1",
            impact="Malicious redirects can influence IPv6 routing decisions on hostile networks.",
            remediation="Set net.ipv6.conf.all.accept_redirects=0 unless redirects are explicitly required.",
            references=("https://docs.kernel.org/networking/ip-sysctl.html",),
        ),
    )


def _network_bridge_ipv4_hooks(snapshot: HostSnapshot) -> tuple[Finding, ...]:
    if not snapshot.bridge_interfaces:
        return ()
    bridge_nf_ipv4 = snapshot.sysctls.get("net.bridge.bridge-nf-call-iptables")
    if bridge_nf_ipv4 != "0":
        return ()
    return (
        Finding(
            rule_id="LNX-NET-005",
            severity="medium",
            title="Bridge IPv4 firewall hooks are disabled",
            category="network",
            evidence="net.bridge.bridge-nf-call-iptables=0 with bridge interfaces present",
            impact=(
                "IPv4 traffic crossing Linux bridges may bypass iptables-based host policy, "
                "which is common on container hosts."
            ),
            remediation=(
                "Set net.bridge.bridge-nf-call-iptables=1 when bridged container traffic "
                "must pass through iptables policy."
            ),
            references=("https://docs.kernel.org/networking/bridge.html",),
        ),
    )


def _network_bridge_ipv6_hooks(snapshot: HostSnapshot) -> tuple[Finding, ...]:
    if not snapshot.bridge_interfaces:
        return ()
    bridge_nf_ipv6 = snapshot.sysctls.get("net.bridge.bridge-nf-call-ip6tables")
    if bridge_nf_ipv6 != "0":
        return ()
    return (
        Finding(
            rule_id="LNX-NET-006",
            severity="medium",
            title="Bridge IPv6 firewall hooks are disabled",
            category="network",
            evidence="net.bridge.bridge-nf-call-ip6tables=0 with bridge interfaces present",
            impact=(
                "IPv6 traffic crossing Linux bridges may bypass ip6tables-based host policy, "
                "which is common on container hosts."
            ),
            remediation=(
                "Set net.bridge.bridge-nf-call-ip6tables=1 when bridged container traffic "
                "must pass through ip6tables policy."
            ),
            references=("https://docs.kernel.org/networking/bridge.html",),
        ),
    )


def _network_bridge_forwarding(snapshot: HostSnapshot) -> list[Finding]:
    findings: list[Finding] = []
    for bridge in snapshot.bridge_interfaces:
        enabled_protocols = []
        if bridge.ipv4_forwarding is True:
            enabled_protocols.append("IPv4")
        if bridge.ipv6_forwarding is True:
            enabled_protocols.append("IPv6")
        if not enabled_protocols:
            continue
        findings.append(
            Finding(
                rule_id="LNX-NET-007",
                severity="medium",
                title="Bridge interface forwarding is enabled",
                category="network",
                evidence=f"{bridge.name} bridge forwarding enabled for {', '.join(enabled_protocols)}",
                impact=(
                    "A bridge interface with forwarding enabled can route traffic for attached "
                    "container or VM interfaces when host policy allows it."
                ),
                remediation=(
                    "Disable forwarding on the bridge interface unless this host is intentionally "
                    "routing bridged workloads."
                ),
                references=("https://docs.kernel.org/networking/ip-sysctl.html",),
            )
        )
    return findings


def _kernel_mmap_min_addr(snapshot: HostSnapshot) -> tuple[Finding, ...]:
    mmap_min_addr = _int_or_none(snapshot.sysctls.get("vm.mmap_min_addr"))
    if mmap_min_addr is None or mmap_min_addr >= 65536:
        return ()
    return (
        Finding(
            rule_id="LNX-KRN-002",
            severity="high",
            title="Low memory mappings are not protected",
            category="kernel",
            evidence=f"vm.mmap_min_addr={mmap_min_addr}",
            impact="Low-address memory mappings can make kernel null-pointer bugs easier to exploit.",
            remediation="Set vm.mmap_min_addr to at least 65536 unless a legacy workload requires otherwise.",
            references=("https://docs.kernel.org/admin-guide/sysctl/vm.html",),
        ),
    )


def _filesystem_hardlink_protection(snapshot: HostSnapshot) -> tuple[Finding, ...]:
    protected_hardlinks = snapshot.sysctls.get("fs.protected_hardlinks")
    if protected_hardlinks != "0":
        return ()
    return (
        Finding(
            rule_id="LNX-FS-001",
            severity="high",
            title="Hardlink protection is disabled",
            category="filesystem",
            evidence="fs.protected_hardlinks=0",
            impact=(
                "Users may be able to create hardlinks to files they do not own, "
                "weakening common privilege escalation protections."
            ),
            remediation="Set fs.protected_hardlinks=1 and persist it under /etc/sysctl.d/.",
            references=("https://docs.kernel.org/admin-guide/sysctl/fs.html",),
        ),
    )


def _filesystem_symlink_protection(snapshot: HostSnapshot) -> tuple[Finding, ...]:
    protected_symlinks = snapshot.sysctls.get("fs.protected_symlinks")
    if protected_symlinks != "0":
        return ()
    return (
        Finding(
            rule_id="LNX-FS-002",
            severity="high",
            title="Symlink protection is disabled",
            category="filesystem",
            evidence="fs.protected_symlinks=0",
            impact="Users may be exposed to symlink race attacks in sticky world-writable directories.",
            remediation="Set fs.protected_symlinks=1 and persist it under /etc/sysctl.d/.",
            references=("https://docs.kernel.org/admin-guide/sysctl/fs.html",),
        ),
    )


def _kernel_pointer_restrict(snapshot: HostSnapshot) -> tuple[Finding, ...]:
    kptr_restrict = snapshot.sysctls.get("kernel.kptr_restrict")
    if kptr_restrict != "0":
        return ()
    return (
        Finding(
            rule_id="LNX-KRN-003",
            severity="medium",
            title="Kernel pointer exposure is unrestricted",
            category="kernel",
            evidence="kernel.kptr_restrict=0",
            impact="Kernel pointer addresses can help attackers bypass kernel exploitation mitigations.",
            remediation="Set kernel.kptr_restrict=1 or 2 and persist it under /etc/sysctl.d/.",
            references=("https://docs.kernel.org/admin-guide/sysctl/kernel.html",),
        ),
    )


def _package_updates(snapshot: HostSnapshot) -> tuple[Finding, ...]:
    updates_available = snapshot.package_status.updates_available
    if updates_available is None or updates_available <= 0:
        return ()
    return (
        Finding(
            rule_id="LNX-PKG-001",
            severity="medium",
            title="Package updates are available",
            category="packages",
            evidence=f"{updates_available} package updates available via {snapshot.package_status.manager}",
            impact="Unapplied package updates can leave the host exposed to known defects and vulnerabilities.",
            remediation="Review and apply pending package updates through the system package manager.",
            references=("man:apt(8)", "man:dnf(8)", "man:pacman(8)", "man:apk(8)"),
        ),
    )


def _package_security_updates(snapshot: HostSnapshot) -> tuple[Finding, ...]:
    security_updates = snapshot.package_status.security_updates
    if security_updates is None or security_updates <= 0:
        return ()
    return (
        Finding(
            rule_id="LNX-PKG-002",
            severity="high",
            title="Security package updates are available",
            category="packages",
            evidence=f"{security_updates} security updates available via {snapshot.package_status.manager}",
            impact="Known security fixes have not been applied to this host.",
            remediation="Prioritize applying pending security updates and restart affected services if required.",
            references=("man:apt(8)", "man:dnf(8)", "man:pacman(8)", "man:apk(8)"),
        ),
    )


def _package_metadata_stale(snapshot: HostSnapshot) -> tuple[Finding, ...]:
    metadata_age_days = snapshot.package_status.metadata_age_days
    if metadata_age_days is None or metadata_age_days <= 14:
        return ()
    return (
        Finding(
            rule_id="LNX-PKG-003",
            severity="medium",
            title="Package metadata is stale",
            category="packages",
            evidence=f"{snapshot.package_status.manager} package metadata is {metadata_age_days} days old",
            impact="Stale package metadata can hide available fixes from update checks and audit jobs.",
            remediation="Refresh package metadata with the system package manager before trusting update counts.",
            references=("man:apt(8)", "man:dnf(8)", "man:pacman(8)", "man:apk(8)"),
        ),
    )


def _package_vulnerabilities(snapshot: HostSnapshot) -> list[Finding]:
    findings: list[Finding] = []
    for vulnerability in snapshot.package_vulnerabilities:
        if vulnerability.fixed_version:
            vulnerability_remediation = (
                f"Upgrade {vulnerability.package} to {vulnerability.fixed_version} or later, "
                "or document why the local feed entry does not apply."
            )
        else:
            vulnerability_remediation = (
                f"Review the vendor advisory for {vulnerability.package}; the local feed did not provide "
                "a fixed version."
            )
        findings.append(
            Finding(
                rule_id="LNX-PKG-004",
                severity=vulnerability.severity,
                title="Known package vulnerability is present",
                category="packages",
                evidence=(
                    f"{vulnerability.package} {vulnerability.installed_version} is affected by "
                    f"{vulnerability.vulnerability_id}"
                ),
                impact=(
                    vulnerability.summary
                    or "A local vulnerability feed reports that the installed package version is affected."
                ),
                remediation=vulnerability_remediation,
                references=(vulnerability.url,) if vulnerability.url else (),
            )
        )
    return findings


def _firewall_disabled(snapshot: HostSnapshot) -> tuple[Finding, ...]:
    if snapshot.firewall_status.provider == "unknown" or snapshot.firewall_status.enabled is not False:
        return ()
    return (
        Finding(
            rule_id="LNX-FW-001",
            severity="medium",
            title="Host firewall is disabled",
            category="firewall",
            evidence=f"{snapshot.firewall_status.provider} firewall disabled",
            impact="The host may expose services directly without local packet filtering.",
            remediation="Enable the host firewall or document why perimeter controls are sufficient.",
            references=("man:ufw(8)", "man:firewalld(1)", "man:nft(8)"),
        ),
    )


def _systemd_service_exposures(snapshot: HostSnapshot) -> list[Finding]:
    findings: list[Finding] = []
    for exposure in snapshot.systemd_service_exposures:
        findings.append(
            Finding(
                rule_id="LNX-SVC-001",
                severity="medium",
                title="Enabled service appears externally bound",
                category="services",
                evidence=f"{exposure.name} enabled and bound to {exposure.bind}",
                impact=(
                    "An enabled service with a wildcard bind can accept connections "
                    "from non-local interfaces when network policy allows it."
                ),
                remediation=(
                    "Review whether the service must listen externally; bind it to "
                    "127.0.0.1 or ::1 when only local access is needed."
                ),
                references=("man:systemd.service(5)", "man:systemd.unit(5)"),
            )
        )
    return findings


def _container_runtime_tcp_api(snapshot: HostSnapshot) -> list[Finding]:
    findings: list[Finding] = []
    for signal in snapshot.container_runtime_signals:
        if signal.signal != "tcp_api":
            continue
        findings.append(
            Finding(
                rule_id="LNX-CTR-001",
                severity="high",
                title="Container runtime API is bound to non-loopback TCP",
                category="containers",
                evidence=f"{signal.runtime} API endpoint {signal.evidence} from {signal.source}",
                impact=(
                    "An exposed container runtime API can let remote clients control containers, "
                    "mount host paths, or alter workload state."
                ),
                remediation=(
                    "Bind the runtime API to a Unix socket or loopback-only endpoint, and use SSH or "
                    "mutual TLS if remote access is required."
                ),
                references=(
                    "https://docs.docker.com/engine/security/https/",
                    "https://docs.podman.io/en/latest/markdown/podman-system-service.1.html",
                ),
            )
        )
    return findings


def _container_runtime_docker_group_members(snapshot: HostSnapshot) -> list[Finding]:
    findings: list[Finding] = []
    for signal in snapshot.container_runtime_signals:
        if signal.signal != "docker_group_members":
            continue
        findings.append(
            Finding(
                rule_id="LNX-CTR-002",
                severity="high",
                title="Docker group grants daemon-level access to users",
                category="containers",
                evidence=f"{signal.evidence} from {signal.source}",
                impact=(
                    "Members of the docker group can control the Docker daemon and can often reach "
                    "host-root equivalent privileges."
                ),
                remediation=(
                    "Remove unnecessary users from the docker group; prefer sudo auditing or rootless "
                    "Docker where non-root operation is required."
                ),
                references=("https://docs.docker.com/engine/install/linux-postinstall/",),
            )
        )
    return findings


def _container_runtime_userns_remap_disabled(snapshot: HostSnapshot) -> list[Finding]:
    findings: list[Finding] = []
    for signal in snapshot.container_runtime_signals:
        if signal.signal != "userns_remap_disabled":
            continue
        findings.append(
            Finding(
                rule_id="LNX-CTR-003",
                severity="medium",
                title="Docker user namespace remapping is explicitly disabled",
                category="containers",
                evidence=f"{signal.evidence} from {signal.source}",
                impact=(
                    "Containers that run as root are not remapped to an unprivileged host UID range, "
                    "which weakens isolation when a workload escapes its container boundary."
                ),
                remediation=(
                    'Configure Docker daemon `"userns-remap": "default"` or a dedicated remap user '
                    "after validating subordinate UID/GID ranges and workload compatibility."
                ),
                references=("https://docs.docker.com/engine/security/userns-remap/",),
            )
        )
    return findings


RULES: tuple[RuleDefinition, ...] = (
    RuleDefinition("LNX-SSH-001", "ssh", _ssh_root_login),
    RuleDefinition("LNX-SSH-002", "ssh", _ssh_password_authentication),
    RuleDefinition("LNX-SSH-003", "ssh", _ssh_empty_passwords),
    RuleDefinition("LNX-SSH-004", "ssh", _ssh_max_auth_tries),
    RuleDefinition("LNX-SSH-005", "ssh", _ssh_tcp_forwarding),
    RuleDefinition("LNX-KRN-001", "kernel", _kernel_aslr),
    RuleDefinition("LNX-NET-001", "network", _network_ipv4_forwarding),
    RuleDefinition("LNX-NET-002", "network", _network_ipv4_redirects),
    RuleDefinition("LNX-NET-003", "network", _network_ipv6_forwarding),
    RuleDefinition("LNX-NET-004", "network", _network_ipv6_redirects),
    RuleDefinition("LNX-NET-005", "network", _network_bridge_ipv4_hooks),
    RuleDefinition("LNX-NET-006", "network", _network_bridge_ipv6_hooks),
    RuleDefinition("LNX-NET-007", "network", _network_bridge_forwarding),
    RuleDefinition("LNX-KRN-002", "kernel", _kernel_mmap_min_addr),
    RuleDefinition("LNX-FS-001", "filesystem", _filesystem_hardlink_protection),
    RuleDefinition("LNX-FS-002", "filesystem", _filesystem_symlink_protection),
    RuleDefinition("LNX-KRN-003", "kernel", _kernel_pointer_restrict),
    RuleDefinition("LNX-PKG-001", "packages", _package_updates),
    RuleDefinition("LNX-PKG-002", "packages", _package_security_updates),
    RuleDefinition("LNX-PKG-003", "packages", _package_metadata_stale),
    RuleDefinition("LNX-PKG-004", "packages", _package_vulnerabilities),
    RuleDefinition("LNX-FW-001", "firewall", _firewall_disabled),
    RuleDefinition("LNX-SVC-001", "services", _systemd_service_exposures),
    RuleDefinition("LNX-CTR-001", "containers", _container_runtime_tcp_api),
    RuleDefinition("LNX-CTR-002", "containers", _container_runtime_docker_group_members),
    RuleDefinition("LNX-CTR-003", "containers", _container_runtime_userns_remap_disabled),
)


def summarize_findings(findings: list[Finding]) -> FindingSummary:
    counts = {"critical": 0, "high": 0, "medium": 0, "low": 0}
    penalty = 0
    for finding in findings:
        counts[finding.severity] = counts.get(finding.severity, 0) + 1
        penalty += SCORE_WEIGHTS.get(finding.severity, 0)

    return FindingSummary(
        total=len(findings),
        by_severity=counts,
        score=max(0, 100 - penalty),
    )


def threshold_is_met(findings: list[Finding], threshold: str) -> bool:
    if threshold == "off":
        return False
    target = SEVERITY_ORDER[threshold]
    return any(SEVERITY_ORDER[finding.severity] >= target for finding in findings)


def _int_or_none(value: Optional[str]) -> Optional[int]:
    if value is None:
        return None
    try:
        return int(value)
    except ValueError:
        return None
