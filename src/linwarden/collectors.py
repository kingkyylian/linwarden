from __future__ import annotations

import json
import platform
import shlex
import socket
import subprocess
import time
from pathlib import Path
from typing import Optional, Sequence, Union

from .models import (
    BridgeInterface,
    FirewallStatus,
    HostSnapshot,
    PackageStatus,
    PackageVulnerability,
    SystemdServiceExposure,
)
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
    "net.bridge.bridge-nf-call-iptables": (
        "sys",
        "net",
        "bridge",
        "bridge-nf-call-iptables",
    ),
    "net.bridge.bridge-nf-call-ip6tables": (
        "sys",
        "net",
        "bridge",
        "bridge-nf-call-ip6tables",
    ),
    "vm.mmap_min_addr": ("sys", "vm", "mmap_min_addr"),
}


def collect_host_snapshot(
    root: Union[Path, str] = Path("/"),
    proc_root: Optional[Union[Path, str]] = None,
    etc_root: Optional[Union[Path, str]] = None,
    sshd_mode: str = "static",
    sshd_binary: Union[Path, str] = "sshd",
    sshd_match_context: Sequence[str] = (),
    sys_root: Optional[Union[Path, str]] = None,
    vulnerability_feed: Optional[Union[Path, str]] = None,
) -> HostSnapshot:
    root_path = Path(root)
    proc_path = Path(proc_root) if proc_root is not None else root_path / "proc"
    etc_path = Path(etc_root) if etc_root is not None else root_path / "etc"
    sys_path = Path(sys_root) if sys_root is not None else root_path / "sys"

    hostname = read_text(etc_path / "hostname", socket.gethostname()) or socket.gethostname()
    os_release = parse_os_release(etc_path / "os-release")
    kernel_release = read_text(proc_path / "sys" / "kernel" / "osrelease", platform.release())
    uptime = _read_float(proc_path / "uptime")
    sshd_context = _normalize_sshd_match_context(sshd_match_context)
    sshd_options, sshd_source = _read_sshd_options(etc_path, sshd_mode, sshd_binary, sshd_context)

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
        sshd_match_context=sshd_context,
        package_status=_read_package_status(root_path, os_release),
        firewall_status=_read_firewall_status(etc_path),
        bridge_interfaces=_read_bridge_interfaces(sys_path, proc_path),
        systemd_service_exposures=_read_systemd_service_exposures(root_path, etc_path),
        package_vulnerabilities=_read_package_vulnerabilities(vulnerability_feed),
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
    sshd_match_context: tuple[str, ...],
) -> tuple[dict[str, str], str]:
    sshd_config = etc_root / "ssh" / "sshd_config"
    if sshd_mode == "static":
        return parse_sshd_config(sshd_config), "static"
    if sshd_mode == "effective":
        return _read_effective_sshd_config(sshd_config, sshd_binary, sshd_match_context), "effective"
    if sshd_mode == "auto":
        try:
            return _read_effective_sshd_config(sshd_config, sshd_binary, sshd_match_context), "effective"
        except RuntimeError:
            return parse_sshd_config(sshd_config), "static"
    raise ValueError(f"unsupported sshd_mode: {sshd_mode}")


def _read_effective_sshd_config(
    sshd_config: Path,
    sshd_binary: Union[Path, str],
    sshd_match_context: tuple[str, ...],
) -> dict[str, str]:
    command = [str(sshd_binary), "-T", "-f", str(sshd_config)]
    if sshd_match_context:
        command.extend(["-C", ",".join(sshd_match_context)])
    try:
        completed = subprocess.run(
            command,
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


def _normalize_sshd_match_context(sshd_match_context: Sequence[str]) -> tuple[str, ...]:
    values: list[str] = []
    for raw_value in sshd_match_context:
        key, separator, value = raw_value.partition("=")
        if not separator or not key or not value or "," in key or "," in value:
            raise ValueError("sshd match context entries must use key=value without commas")
        values.append(f"{key.strip()}={value.strip()}")
    return tuple(values)


def _read_package_status(root: Path, os_release: dict[str, str]) -> PackageStatus:
    manager = _package_manager(os_release)
    metadata_age_days, metadata_source = _read_package_metadata_age(root, manager)
    update_notifier = root / "var" / "lib" / "update-notifier" / "updates-available"
    update_text = read_text(update_notifier)
    if update_text:
        return PackageStatus(
            manager=manager,
            updates_available=_first_int(update_text, "packages can be updated"),
            security_updates=_first_int(update_text, "updates are security updates"),
            source=str(update_notifier),
            metadata_age_days=metadata_age_days,
            metadata_source=metadata_source,
        )
    return PackageStatus(
        manager=manager,
        updates_available=None,
        security_updates=None,
        source="not found",
        metadata_age_days=metadata_age_days,
        metadata_source=metadata_source,
    )


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


def _read_package_metadata_age(root: Path, manager: str) -> tuple[Optional[int], str]:
    newest_mtime: Optional[float] = None
    newest_source: Optional[Path] = None
    for path in _package_metadata_candidates(root, manager):
        try:
            mtime = path.stat().st_mtime
        except OSError:
            continue
        if newest_mtime is None or mtime > newest_mtime:
            newest_mtime = mtime
            newest_source = path

    if newest_mtime is None or newest_source is None:
        return None, "not found"

    age_days = max(0, int((time.time() - newest_mtime) // 86400))
    return age_days, str(newest_source)


def _package_metadata_candidates(root: Path, manager: str) -> tuple[Path, ...]:
    if manager == "apt":
        return (
            root / "var" / "lib" / "apt" / "periodic" / "update-success-stamp",
            root / "var" / "cache" / "apt" / "pkgcache.bin",
        )
    if manager == "dnf":
        return (
            root / "var" / "cache" / "dnf" / "expired_repos.json",
            root / "var" / "cache" / "dnf",
        )
    if manager == "pacman":
        return tuple(sorted((root / "var" / "lib" / "pacman" / "sync").glob("*.db")))
    if manager == "apk":
        return tuple(sorted((root / "var" / "cache" / "apk").glob("APKINDEX*.tar.gz")))
    return ()


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

    firewalld_marker = _systemd_wants_marker(etc_root, "firewalld.service")
    firewalld_config = etc_root / "firewalld" / "firewalld.conf"
    if _path_exists_or_symlink(firewalld_marker):
        return FirewallStatus(provider="firewalld", enabled=True, source=str(firewalld_marker))
    if firewalld_config.exists():
        return FirewallStatus(provider="firewalld", enabled=None, source=str(firewalld_config))

    nftables_marker = _systemd_wants_marker(etc_root, "nftables.service")
    nftables_config = etc_root / "nftables.conf"
    if _path_exists_or_symlink(nftables_marker):
        return FirewallStatus(provider="nftables", enabled=True, source=str(nftables_marker))
    if nftables_config.exists():
        return FirewallStatus(provider="nftables", enabled=None, source=str(nftables_config))

    return FirewallStatus(provider="unknown", enabled=None, source="not found")


def _read_bridge_interfaces(sys_root: Path, proc_root: Path) -> tuple[BridgeInterface, ...]:
    net_root = sys_root / "class" / "net"
    try:
        candidates = sorted(net_root.iterdir(), key=lambda path: path.name)
    except OSError:
        return ()

    bridges: list[BridgeInterface] = []
    for interface in candidates:
        bridge_source = interface / "bridge"
        if not bridge_source.exists():
            continue
        bridges.append(
            BridgeInterface(
                name=interface.name,
                members=_read_bridge_members(interface),
                ipv4_forwarding=_read_sysctl_bool(
                    proc_root / "sys" / "net" / "ipv4" / "conf" / interface.name / "forwarding"
                ),
                ipv6_forwarding=_read_sysctl_bool(
                    proc_root / "sys" / "net" / "ipv6" / "conf" / interface.name / "forwarding"
                ),
                source=str(bridge_source),
            )
        )
    return tuple(bridges)


def _read_bridge_members(interface: Path) -> tuple[str, ...]:
    brif = interface / "brif"
    try:
        return tuple(sorted(path.name for path in brif.iterdir() if _path_exists_or_symlink(path)))
    except OSError:
        return ()


def _read_sysctl_bool(path: Path) -> Optional[bool]:
    value = read_text(path)
    if value == "1":
        return True
    if value == "0":
        return False
    return None


def _systemd_wants_marker(etc_root: Path, service_name: str) -> Path:
    return etc_root / "systemd" / "system" / "multi-user.target.wants" / service_name


def _path_exists_or_symlink(path: Path) -> bool:
    return path.exists() or path.is_symlink()


def _read_systemd_service_exposures(root: Path, etc_root: Path) -> tuple[SystemdServiceExposure, ...]:
    exposures: list[SystemdServiceExposure] = []
    seen_services: set[str] = set()
    for marker in _enabled_systemd_service_markers(etc_root):
        service_name = marker.name
        if service_name in seen_services:
            continue
        seen_services.add(service_name)
        unit_text, unit_source = _read_systemd_unit_text(root, etc_root, service_name, marker)
        if not unit_text:
            continue
        bind = _external_service_bind(unit_text)
        if bind is None:
            continue
        exec_start = _first_service_value(unit_text, "ExecStart")
        exposures.append(
            SystemdServiceExposure(
                name=service_name,
                bind=bind,
                source=unit_source,
                enabled_source=str(marker),
                exec_start=exec_start,
            )
        )
    return tuple(exposures)


def _enabled_systemd_service_markers(etc_root: Path) -> tuple[Path, ...]:
    system_root = etc_root / "systemd" / "system"
    try:
        return tuple(
            sorted(
                path
                for path in system_root.glob("*.wants/*.service")
                if _path_exists_or_symlink(path)
            )
        )
    except OSError:
        return ()


def _read_systemd_unit_text(
    root: Path,
    etc_root: Path,
    service_name: str,
    marker: Path,
) -> tuple[str, str]:
    candidates: list[Path] = []
    if marker.is_symlink():
        try:
            target = marker.readlink()
        except OSError:
            target = None
        if target is not None:
            if target.is_absolute():
                candidates.append(root / target.relative_to("/"))
            else:
                candidates.append(marker.parent / target)
    elif marker.is_file():
        candidates.append(marker)

    candidates.extend(
        [
            etc_root / "systemd" / "system" / service_name,
            root / "usr" / "lib" / "systemd" / "system" / service_name,
            root / "lib" / "systemd" / "system" / service_name,
        ]
    )

    seen: set[Path] = set()
    for candidate in candidates:
        if candidate in seen:
            continue
        seen.add(candidate)
        text = read_text(candidate)
        if text:
            return text, str(candidate)
    return "", "not found"


def _external_service_bind(unit_text: str) -> Optional[str]:
    if _first_service_value(unit_text, "Type").lower() == "oneshot":
        return None
    for exec_start in _service_values(unit_text, "ExecStart"):
        bind = _external_bind_from_exec_start(exec_start)
        if bind is not None:
            return bind
    return None


_BIND_OPTION_NAMES = {
    "--addr",
    "--address",
    "--bind",
    "--host",
    "--listen",
    "--listen-address",
    "-b",
}

_BIND_OPTION_PARTS = ("addr", "address", "bind", "host", "listen")
_EXTERNAL_BINDS = ("0.0.0.0", "::", "[::]", "*")
_LOCAL_BINDS = ("127.", "localhost", "::1", "[::1]")


def _external_bind_from_exec_start(exec_start: str) -> Optional[str]:
    try:
        tokens = shlex.split(exec_start, comments=False, posix=True)
    except ValueError:
        tokens = exec_start.split()

    for index, token in enumerate(tokens):
        option, separator, value = token.partition("=")
        if separator and _is_bind_option(option):
            bind = _external_bind_value(value)
            if bind is not None:
                return bind
        if token in _BIND_OPTION_NAMES and index + 1 < len(tokens):
            bind = _external_bind_value(tokens[index + 1])
            if bind is not None:
                return bind
    return None


def _is_bind_option(option: str) -> bool:
    normalized = option.lower().replace("_", "-")
    return any(part in normalized for part in _BIND_OPTION_PARTS)


def _external_bind_value(value: str) -> Optional[str]:
    normalized = value.strip().lower()
    if normalized.startswith(_LOCAL_BINDS):
        return None
    for bind in _EXTERNAL_BINDS:
        if normalized == bind or normalized.startswith(f"{bind}:") or normalized.startswith(f"{bind}/"):
            return bind
    if (
        normalized.startswith("[::]:")
        or normalized.startswith("http://0.0.0.0")
        or normalized.startswith("https://0.0.0.0")
    ):
        return "0.0.0.0" if "0.0.0.0" in normalized else "[::]"
    return None


def _service_values(unit_text: str, key: str) -> tuple[str, ...]:
    values: list[str] = []
    in_service = False
    for raw_line in unit_text.splitlines():
        line = raw_line.strip()
        if not line or line.startswith("#"):
            continue
        if line.startswith("[") and line.endswith("]"):
            in_service = line.lower() == "[service]"
            continue
        if not in_service or "=" not in line:
            continue
        raw_key, value = line.split("=", 1)
        if raw_key.strip().lower() == key.lower() and value.strip():
            values.append(value.strip())
    return tuple(values)


def _first_service_value(unit_text: str, key: str) -> str:
    values = _service_values(unit_text, key)
    return values[0] if values else ""


def _read_package_vulnerabilities(
    vulnerability_feed: Optional[Union[Path, str]],
) -> tuple[PackageVulnerability, ...]:
    if vulnerability_feed is None:
        return ()

    feed_path = Path(vulnerability_feed)
    try:
        payload = json.loads(feed_path.read_text(encoding="utf-8"))
    except OSError as exc:
        raise ValueError(f"vulnerability feed {feed_path}: {exc}") from exc
    except json.JSONDecodeError as exc:
        raise ValueError(f"vulnerability feed {feed_path}: invalid JSON at line {exc.lineno}") from exc

    if not isinstance(payload, dict):
        raise ValueError(f"vulnerability feed {feed_path}: root must be an object")
    if payload.get("version") != 1:
        raise ValueError(f"vulnerability feed {feed_path}: version must be 1")

    entries = payload.get("vulnerabilities")
    if not isinstance(entries, list):
        raise ValueError(f"vulnerability feed {feed_path}: vulnerabilities must be an array")

    vulnerabilities: list[PackageVulnerability] = []
    for index, entry in enumerate(entries):
        if not isinstance(entry, dict):
            raise ValueError(f"vulnerability feed {feed_path}: vulnerabilities[{index}] must be an object")
        vulnerabilities.append(_package_vulnerability_from_entry(feed_path, index, entry))
    return tuple(vulnerabilities)


_VULNERABILITY_SEVERITIES = {"critical", "high", "medium", "low"}


def _package_vulnerability_from_entry(
    feed_path: Path,
    index: int,
    entry: dict[str, object],
) -> PackageVulnerability:
    severity = _required_feed_string(feed_path, index, entry, "severity").lower()
    if severity not in _VULNERABILITY_SEVERITIES:
        raise ValueError(
            f"vulnerability feed {feed_path}: vulnerabilities[{index}].severity must be critical, high, medium, or low"
        )

    return PackageVulnerability(
        package=_required_feed_string(feed_path, index, entry, "package"),
        installed_version=_required_feed_string(feed_path, index, entry, "installed_version"),
        fixed_version=_required_feed_string(feed_path, index, entry, "fixed_version"),
        vulnerability_id=_required_feed_string(feed_path, index, entry, "id"),
        severity=severity,
        summary=_optional_feed_string(feed_path, index, entry, "summary"),
        url=_optional_feed_string(feed_path, index, entry, "url"),
        source=str(feed_path),
    )


def _required_feed_string(feed_path: Path, index: int, entry: dict[str, object], key: str) -> str:
    value = entry.get(key)
    if not isinstance(value, str) or not value.strip():
        raise ValueError(f"vulnerability feed {feed_path}: vulnerabilities[{index}].{key} must be a non-empty string")
    return value.strip()


def _optional_feed_string(feed_path: Path, index: int, entry: dict[str, object], key: str) -> str:
    value = entry.get(key, "")
    if value is None:
        return ""
    if not isinstance(value, str):
        raise ValueError(f"vulnerability feed {feed_path}: vulnerabilities[{index}].{key} must be a string")
    return value.strip()
