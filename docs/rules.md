# Rule Catalog

Rules are designed to be explainable. Each finding includes evidence, impact, remediation, and references.

Linwarden uses static, rootless evidence by default. For SSH, static mode reads `sshd_config` and simple `Include` directives directly. Effective mode can execute `sshd -T` when the operator explicitly requests it.

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

### LNX-SSH-003: SSH permits empty passwords

- Severity: high
- Evidence: `PermitEmptyPasswords yes`
- Impact: Accounts with empty passwords can authenticate over SSH without a credential secret.
- Remediation: Set `PermitEmptyPasswords no` and reload `sshd`.

### LNX-SSH-004: SSH allows too many authentication attempts

- Severity: medium
- Evidence: `MaxAuthTries` above `4`
- Impact: High retry counts increase exposure to password guessing and noisy credential attacks.
- Remediation: Set `MaxAuthTries 4` or lower and reload `sshd`.

### LNX-SSH-005: SSH TCP forwarding is broadly enabled

- Severity: medium
- Evidence: `AllowTcpForwarding yes` or `all`
- Impact: SSH users can tunnel TCP connections through the host and potentially bypass network controls.
- Remediation: Set `AllowTcpForwarding no` unless SSH tunneling is explicitly required.

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

## Package Rules

### LNX-PKG-001: Package updates are available

- Severity: medium
- Evidence: update count from the local package update status source.
- Impact: Unapplied package updates can leave the host exposed to known defects and vulnerabilities.
- Remediation: Review and apply pending package updates through the system package manager.

### LNX-PKG-002: Security package updates are available

- Severity: high
- Evidence: security update count from the local package update status source.
- Impact: Known security fixes have not been applied to this host.
- Remediation: Prioritize applying pending security updates and restart affected services if required.

### LNX-PKG-003: Package metadata is stale

- Severity: medium
- Evidence: age of the newest known local package metadata marker.
- Impact: Stale package metadata can hide available fixes from update checks and audit jobs.
- Remediation: Refresh package metadata with the system package manager before trusting update counts.

## Firewall Rules

### LNX-FW-001: Host firewall is disabled

- Severity: medium
- Evidence: known host firewall provider reports disabled state.
- Impact: The host may expose services directly without local packet filtering.
- Remediation: Enable the host firewall or document why perimeter controls are sufficient.

Linwarden currently reads UFW config state directly and infers firewalld or nftables enablement from systemd enablement markers when present. A provider config file without a service marker is reported as unknown enabled state, not as disabled.
