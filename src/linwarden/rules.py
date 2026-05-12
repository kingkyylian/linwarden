from __future__ import annotations

from typing import Optional

from .models import Finding, FindingSummary, HostSnapshot


SEVERITY_ORDER = {"low": 1, "medium": 2, "high": 3, "critical": 4}
SCORE_WEIGHTS = {"low": 3, "medium": 10, "high": 20, "critical": 35}


def evaluate_snapshot(snapshot: HostSnapshot) -> list[Finding]:
    findings: list[Finding] = []

    permit_root_login = snapshot.sshd_options.get("permitrootlogin", "not set").lower()
    if permit_root_login == "yes":
        findings.append(
            Finding(
                rule_id="LNX-SSH-001",
                severity="high",
                title="SSH root login is permitted",
                category="ssh",
                evidence=f"PermitRootLogin {permit_root_login}",
                impact="Remote attackers can attempt direct privileged logins instead of going through named accounts.",
                remediation="Set PermitRootLogin no in sshd_config and reload sshd.",
                references=("man:sshd_config(5)",),
            )
        )

    password_auth = snapshot.sshd_options.get("passwordauthentication", "not set").lower()
    if password_auth == "yes":
        findings.append(
            Finding(
                rule_id="LNX-SSH-002",
                severity="medium",
                title="SSH password authentication is enabled",
                category="ssh",
                evidence=f"PasswordAuthentication {password_auth}",
                impact="Password-based SSH increases exposure to credential stuffing and weak password attacks.",
                remediation="Prefer key-based SSH and set PasswordAuthentication no after confirming access.",
                references=("man:sshd_config(5)",),
            )
        )

    randomize_va_space = snapshot.sysctls.get("kernel.randomize_va_space")
    if randomize_va_space == "0":
        findings.append(
            Finding(
                rule_id="LNX-KRN-001",
                severity="high",
                title="Address space layout randomization is disabled",
                category="kernel",
                evidence="kernel.randomize_va_space=0",
                impact="Memory corruption exploits become easier when process address layouts are predictable.",
                remediation="Set kernel.randomize_va_space=2 with sysctl and persist it under /etc/sysctl.d/.",
                references=("https://docs.kernel.org/admin-guide/sysctl/kernel.html",),
            )
        )

    ip_forward = snapshot.sysctls.get("net.ipv4.ip_forward")
    if ip_forward == "1":
        findings.append(
            Finding(
                rule_id="LNX-NET-001",
                severity="medium",
                title="IPv4 forwarding is enabled",
                category="network",
                evidence="net.ipv4.ip_forward=1",
                impact="The host can route traffic between interfaces, which broadens blast radius if unintended.",
                remediation="Set net.ipv4.ip_forward=0 unless this system is intentionally acting as a router.",
                references=("https://docs.kernel.org/networking/ip-sysctl.html",),
            )
        )

    accept_redirects = snapshot.sysctls.get("net.ipv4.conf.all.accept_redirects")
    if accept_redirects == "1":
        findings.append(
            Finding(
                rule_id="LNX-NET-002",
                severity="low",
                title="IPv4 ICMP redirects are accepted",
                category="network",
                evidence="net.ipv4.conf.all.accept_redirects=1",
                impact="Malicious redirects can influence host routing decisions on hostile networks.",
                remediation="Set net.ipv4.conf.all.accept_redirects=0 unless redirects are explicitly required.",
                references=("https://docs.kernel.org/networking/ip-sysctl.html",),
            )
        )

    ipv6_forwarding = snapshot.sysctls.get("net.ipv6.conf.all.forwarding")
    if ipv6_forwarding == "1":
        findings.append(
            Finding(
                rule_id="LNX-NET-003",
                severity="medium",
                title="IPv6 forwarding is enabled",
                category="network",
                evidence="net.ipv6.conf.all.forwarding=1",
                impact="The host can route IPv6 traffic between interfaces, which may be unintended on non-router systems.",
                remediation="Set net.ipv6.conf.all.forwarding=0 unless this system is intentionally acting as an IPv6 router.",
                references=("https://docs.kernel.org/networking/ip-sysctl.html",),
            )
        )

    ipv6_accept_redirects = snapshot.sysctls.get("net.ipv6.conf.all.accept_redirects")
    if ipv6_accept_redirects == "1":
        findings.append(
            Finding(
                rule_id="LNX-NET-004",
                severity="low",
                title="IPv6 ICMP redirects are accepted",
                category="network",
                evidence="net.ipv6.conf.all.accept_redirects=1",
                impact="Malicious redirects can influence IPv6 routing decisions on hostile networks.",
                remediation="Set net.ipv6.conf.all.accept_redirects=0 unless redirects are explicitly required.",
                references=("https://docs.kernel.org/networking/ip-sysctl.html",),
            )
        )

    mmap_min_addr = _int_or_none(snapshot.sysctls.get("vm.mmap_min_addr"))
    if mmap_min_addr is not None and mmap_min_addr < 65536:
        findings.append(
            Finding(
                rule_id="LNX-KRN-002",
                severity="high",
                title="Low memory mappings are not protected",
                category="kernel",
                evidence=f"vm.mmap_min_addr={mmap_min_addr}",
                impact="Low-address memory mappings can make kernel null-pointer bugs easier to exploit.",
                remediation="Set vm.mmap_min_addr to at least 65536 unless a legacy workload requires otherwise.",
                references=("https://docs.kernel.org/admin-guide/sysctl/vm.html",),
            )
        )

    protected_hardlinks = snapshot.sysctls.get("fs.protected_hardlinks")
    if protected_hardlinks == "0":
        findings.append(
            Finding(
                rule_id="LNX-FS-001",
                severity="high",
                title="Hardlink protection is disabled",
                category="filesystem",
                evidence="fs.protected_hardlinks=0",
                impact="Users may be able to create hardlinks to files they do not own, weakening common privilege escalation protections.",
                remediation="Set fs.protected_hardlinks=1 and persist it under /etc/sysctl.d/.",
                references=("https://docs.kernel.org/admin-guide/sysctl/fs.html",),
            )
        )

    protected_symlinks = snapshot.sysctls.get("fs.protected_symlinks")
    if protected_symlinks == "0":
        findings.append(
            Finding(
                rule_id="LNX-FS-002",
                severity="high",
                title="Symlink protection is disabled",
                category="filesystem",
                evidence="fs.protected_symlinks=0",
                impact="Users may be exposed to symlink race attacks in sticky world-writable directories.",
                remediation="Set fs.protected_symlinks=1 and persist it under /etc/sysctl.d/.",
                references=("https://docs.kernel.org/admin-guide/sysctl/fs.html",),
            )
        )

    kptr_restrict = snapshot.sysctls.get("kernel.kptr_restrict")
    if kptr_restrict == "0":
        findings.append(
            Finding(
                rule_id="LNX-KRN-003",
                severity="medium",
                title="Kernel pointer exposure is unrestricted",
                category="kernel",
                evidence="kernel.kptr_restrict=0",
                impact="Kernel pointer addresses can help attackers bypass kernel exploitation mitigations.",
                remediation="Set kernel.kptr_restrict=1 or 2 and persist it under /etc/sysctl.d/.",
                references=("https://docs.kernel.org/admin-guide/sysctl/kernel.html",),
            )
        )

    return findings


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
