from __future__ import annotations

import platform
import socket
import subprocess
from pathlib import Path
from typing import Optional, Union

from .models import FirewallStatus, HostSnapshot, PackageStatus
from .parsers import (
    parse_loadavg,
    parse_meminfo,
    parse_mounts,
    parse_os_release,
    parse_sshd_config,
    read_text,
)

SYSCTL_PATHS = {
    "fs.protected_hardlinks": ("sys", "fs", "protected_hardlinks"),
    "fs.protected_symlinks": ("sys", "fs", "protected_symlinks"),
    "kernel.kptr_restrict": ("sys", "kernel", "kptr_restrict"),
    "kernel.randomize_va_space": ("sys", "kernel", "randomize_va_space"),
    "net.ipv4.ip_forward": ("sys", "net", "ipv4", "ip_forward"),
    "net.ipv4.conf.all.accept_redirects": (
        "sys",
        "net",
        "ipv4",
        "conf",
        "all",
        "accept_redirects",
    ),
    "net.ipv6.conf.all.forwarding": (
        "sys",
        "net",
        "ipv6",
        "conf",
        "all",
        "forwarding",
    ),
    "net.ipv6.conf.all.accept_redirects": (
        "sys",
        "net",
        "ipv6",
        "conf",
        "all",
        "accept_redirects",
    ),
    "vm.mmap_min_addr": ("sys", "vm", "mmap_min_addr"),
}


def collect_host_snapshot(
    root: Union[Path, str] = Path("/"),
    proc_root: Optional[Union[Path, str]] = None,
    etc_root: Optional[Union[Path, str]] = None,
    sshd_mode: str = "static",
    sshd_binary: Union[Path, str] = "sshd",
) -> HostSnapshot:
    root_path = Path(root)
    proc_path = Path(proc_root) if proc_root is not None else root_path / "proc"
    etc_path = Path(etc_root) if etc_root is not None else root_path / "etc"

    hostname = read_text(etc_path / "hostname", socket.gethostname()) or socket.gethostname()
    os_release = parse_os_release(etc_path / "os-release")
    kernel_release = read_text(proc_path / "sys" / "kernel" / "osrelease", platform.release())
    uptime = _read_float(proc_path / "uptime")
    sshd_options, sshd_source = _read_sshd_options(etc_path, sshd_mode, sshd_binary)

    return HostSnapshot(
        hostname=hostname,
        os_release=os_release,
        kernel_release=kernel_release,
        uptime_seconds=uptime,
        load_average=parse_loadavg(proc_path / "loadavg"),
        memory=parse_meminfo(proc_path / "meminfo"),
        mounts=parse_mounts(proc_path / "mounts"),
        sysctls=_read_sysctls(proc_path),
        sshd_options=sshd_options,
        sshd_source=sshd_source,
        package_status=_read_package_status(root_path, os_release),
        firewall_status=_read_firewall_status(etc_path),
    )


def _read_float(path: Path) -> float:
    value = read_text(path, "0").split()
    try:
        return float(value[0])
    except (IndexError, ValueError):
        return 0.0


def _read_sysctls(proc_root: Path) -> dict[str, str]:
    values: dict[str, str] = {}
    for key, path_parts in SYSCTL_PATHS.items():
        value = read_text(proc_root.joinpath(*path_parts))
        if value:
            values[key] = value
    return values


def _read_sshd_options(
    etc_root: Path,
    sshd_mode: str,
    sshd_binary: Union[Path, str],
) -> tuple[dict[str, str], str]:
    sshd_config = etc_root / "ssh" / "sshd_config"
    if sshd_mode == "static":
        return parse_sshd_config(sshd_config), "static"
    if sshd_mode == "effective":
        return _read_effective_sshd_config(sshd_config, sshd_binary), "effective"
    if sshd_mode == "auto":
        try:
            return _read_effective_sshd_config(sshd_config, sshd_binary), "effective"
        except RuntimeError:
            return parse_sshd_config(sshd_config), "static"
    raise ValueError(f"unsupported sshd_mode: {sshd_mode}")


def _read_effective_sshd_config(
    sshd_config: Path,
    sshd_binary: Union[Path, str],
) -> dict[str, str]:
    try:
        completed = subprocess.run(
            [str(sshd_binary), "-T", "-f", str(sshd_config)],
            check=True,
            capture_output=True,
            text=True,
            timeout=5,
        )
    except (OSError, subprocess.SubprocessError) as exc:
        raise RuntimeError(f"failed to read effective sshd config: {exc}") from exc
    return _parse_key_value_lines(completed.stdout)


def _parse_key_value_lines(text: str) -> dict[str, str]:
    values: dict[str, str] = {}
    for raw_line in text.splitlines():
        parts = raw_line.strip().split(None, 1)
        if len(parts) == 2:
            values[parts[0].lower()] = parts[1].strip()
    return values


def _read_package_status(root: Path, os_release: dict[str, str]) -> PackageStatus:
    manager = _package_manager(os_release)
    update_notifier = root / "var" / "lib" / "update-notifier" / "updates-available"
    update_text = read_text(update_notifier)
    if update_text:
        return PackageStatus(
            manager=manager,
            updates_available=_first_int(update_text, "packages can be updated"),
            security_updates=_first_int(update_text, "updates are security updates"),
            source=str(update_notifier),
        )
    return PackageStatus(manager=manager, updates_available=None, security_updates=None, source="not found")


def _package_manager(os_release: dict[str, str]) -> str:
    distro_ids = {os_release.get("ID", "")}
    distro_ids.update(os_release.get("ID_LIKE", "").split())

    if distro_ids & {"debian", "ubuntu"}:
        return "apt"
    if distro_ids & {"fedora", "rhel", "centos"}:
        return "dnf"
    if "arch" in distro_ids:
        return "pacman"
    if "alpine" in distro_ids:
        return "apk"
    return "unknown"


def _first_int(text: str, marker: str) -> Optional[int]:
    for line in text.splitlines():
        if marker not in line:
            continue
        for part in line.split():
            if part.isdigit():
                return int(part)
    return None


def _read_firewall_status(etc_root: Path) -> FirewallStatus:
    ufw_config = etc_root / "ufw" / "ufw.conf"
    ufw_text = read_text(ufw_config)
    if ufw_text:
        enabled = None
        for raw_line in ufw_text.splitlines():
            line = raw_line.strip()
            if line.startswith("ENABLED="):
                enabled = line.split("=", 1)[1].strip().lower() == "yes"
        return FirewallStatus(provider="ufw", enabled=enabled, source=str(ufw_config))
    return FirewallStatus(provider="unknown", enabled=None, source="not found")
