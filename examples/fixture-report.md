# Linwarden Report

- Host: `fixture-box`
- OS: `Debian GNU/Linux 12 (bookworm)`
- Kernel: `6.8.7-fixture`
- Score: `17/100`
- Findings: `6`

## Findings

| Severity | Rule | Title | Evidence |
| --- | --- | --- | --- |
| HIGH | LNX-SSH-001 | SSH root login is permitted | PermitRootLogin yes |
| MEDIUM | LNX-SSH-002 | SSH password authentication is enabled | PasswordAuthentication yes |
| HIGH | LNX-KRN-001 | Address space layout randomization is disabled | kernel.randomize_va_space=0 |
| MEDIUM | LNX-NET-001 | IPv4 forwarding is enabled | net.ipv4.ip_forward=1 |
| LOW | LNX-NET-002 | IPv4 ICMP redirects are accepted | net.ipv4.conf.all.accept_redirects=1 |
| HIGH | LNX-KRN-002 | Low memory mappings are not protected | vm.mmap_min_addr=0 |

## Remediation

### LNX-SSH-001: SSH root login is permitted

Impact: Remote attackers can attempt direct privileged logins instead of going through named accounts.

Fix: Set PermitRootLogin no in sshd_config and reload sshd.

### LNX-SSH-002: SSH password authentication is enabled

Impact: Password-based SSH increases exposure to credential stuffing and weak password attacks.

Fix: Prefer key-based SSH and set PasswordAuthentication no after confirming access.

### LNX-KRN-001: Address space layout randomization is disabled

Impact: Memory corruption exploits become easier when process address layouts are predictable.

Fix: Set kernel.randomize_va_space=2 with sysctl and persist it under /etc/sysctl.d/.

### LNX-NET-001: IPv4 forwarding is enabled

Impact: The host can route traffic between interfaces, which broadens blast radius if unintended.

Fix: Set net.ipv4.ip_forward=0 unless this system is intentionally acting as a router.

### LNX-NET-002: IPv4 ICMP redirects are accepted

Impact: Malicious redirects can influence host routing decisions on hostile networks.

Fix: Set net.ipv4.conf.all.accept_redirects=0 unless redirects are explicitly required.

### LNX-KRN-002: Low memory mappings are not protected

Impact: Low-address memory mappings can make kernel null-pointer bugs easier to exploit.

Fix: Set vm.mmap_min_addr to at least 65536 unless a legacy workload requires otherwise.
