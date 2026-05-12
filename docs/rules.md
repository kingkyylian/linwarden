# Rule Catalog

Rules are designed to be explainable. Each finding includes evidence, impact, remediation, and references.

Linwarden uses static, rootless evidence. For SSH, this means the parser reads `sshd_config` directly and does not execute `sshd -T`; distribution-specific includes and `Match` blocks may require manual confirmation.

## Severity Guide

| Severity | Meaning |
| --- | --- |
| critical | Direct, likely compromise or severe exposure. |
| high | Security control disabled or privileged attack path exposed. |
| medium | Risky configuration that may be valid in some roles. |
| low | Defense-in-depth issue or environment-dependent risk. |

## SSH Rules

### LNX-SSH-001: SSH root login is permitted

- Severity: high
- Evidence: `PermitRootLogin yes`
- Impact: Attackers can attempt direct privileged logins.
- Remediation: Set `PermitRootLogin no` and reload `sshd`.

### LNX-SSH-002: SSH password authentication is enabled

- Severity: medium
- Evidence: `PasswordAuthentication yes`
- Impact: Password-based SSH increases exposure to weak passwords and credential stuffing.
- Remediation: Prefer key-based SSH and set `PasswordAuthentication no` after validating access.

## Kernel Rules

### LNX-KRN-001: Address space layout randomization is disabled

- Severity: high
- Evidence: `kernel.randomize_va_space=0`
- Impact: Predictable process memory layout can make exploitation easier.
- Remediation: Set `kernel.randomize_va_space=2` and persist it under `/etc/sysctl.d/`.

### LNX-KRN-002: Low memory mappings are not protected

- Severity: high
- Evidence: `vm.mmap_min_addr` below `65536`
- Impact: Kernel null-pointer bugs can become easier to exploit.
- Remediation: Set `vm.mmap_min_addr=65536` unless a legacy workload requires otherwise.

### LNX-KRN-003: Kernel pointer exposure is unrestricted

- Severity: medium
- Evidence: `kernel.kptr_restrict=0`
- Impact: Kernel pointer addresses can help attackers bypass kernel exploitation mitigations.
- Remediation: Set `kernel.kptr_restrict=1` or `2` and persist it under `/etc/sysctl.d/`.

## Filesystem Rules

### LNX-FS-001: Hardlink protection is disabled

- Severity: high
- Evidence: `fs.protected_hardlinks=0`
- Impact: Users may be able to create hardlinks to files they do not own.
- Remediation: Set `fs.protected_hardlinks=1` and persist it under `/etc/sysctl.d/`.

### LNX-FS-002: Symlink protection is disabled

- Severity: high
- Evidence: `fs.protected_symlinks=0`
- Impact: Users may be exposed to symlink race attacks in sticky world-writable directories.
- Remediation: Set `fs.protected_symlinks=1` and persist it under `/etc/sysctl.d/`.

## Network Rules

### LNX-NET-001: IPv4 forwarding is enabled

- Severity: medium
- Evidence: `net.ipv4.ip_forward=1`
- Impact: The host can route traffic between interfaces.
- Remediation: Set `net.ipv4.ip_forward=0` unless the host is intentionally a router.

### LNX-NET-002: IPv4 ICMP redirects are accepted

- Severity: low
- Evidence: `net.ipv4.conf.all.accept_redirects=1`
- Impact: Malicious redirects can influence routing decisions on hostile networks.
- Remediation: Set `net.ipv4.conf.all.accept_redirects=0` unless redirects are required.

### LNX-NET-003: IPv6 forwarding is enabled

- Severity: medium
- Evidence: `net.ipv6.conf.all.forwarding=1`
- Impact: The host can route IPv6 traffic between interfaces.
- Remediation: Set `net.ipv6.conf.all.forwarding=0` unless the host is intentionally an IPv6 router.

### LNX-NET-004: IPv6 ICMP redirects are accepted

- Severity: low
- Evidence: `net.ipv6.conf.all.accept_redirects=1`
- Impact: Malicious redirects can influence IPv6 routing decisions on hostile networks.
- Remediation: Set `net.ipv6.conf.all.accept_redirects=0` unless redirects are required.
