from __future__ import annotations

import json
import math
import platform
import shlex
import socket
import subprocess
import time
from pathlib import Path
from typing import Optional, Sequence, Union
from urllib.parse import urlparse

from .models import (
    BridgeInterface,
    ContainerRuntimeSignal,
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
    vulnerability_feed_format: str = "linwarden",
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
        package_vulnerabilities=_read_package_vulnerabilities(vulnerability_feed, vulnerability_feed_format),
        container_runtime_signals=_read_container_runtime_signals(root_path, etc_path),
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
        apt_lists = root / "var" / "lib" / "apt" / "lists"
        return (
            root / "var" / "lib" / "apt" / "periodic" / "update-success-stamp",
            root / "var" / "cache" / "apt" / "pkgcache.bin",
            *tuple(sorted(apt_lists.glob("*Release"))),
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
    ufw_status: Optional[FirewallStatus] = None
    if ufw_text:
        enabled = None
        for raw_line in ufw_text.splitlines():
            line = raw_line.strip()
            if line.startswith("ENABLED="):
                enabled = line.split("=", 1)[1].strip().lower() == "yes"
        ufw_status = FirewallStatus(provider="ufw", enabled=enabled, source=str(ufw_config))
        if enabled is True:
            return ufw_status

    firewalld_marker = _enabled_systemd_unit_marker(etc_root, "firewalld.service")
    firewalld_config = etc_root / "firewalld" / "firewalld.conf"
    if firewalld_marker is not None:
        return FirewallStatus(provider="firewalld", enabled=True, source=str(firewalld_marker))

    nftables_marker = _enabled_systemd_unit_marker(etc_root, "nftables.service")
    nftables_config = etc_root / "nftables.conf"
    if nftables_marker is not None:
        return FirewallStatus(provider="nftables", enabled=True, source=str(nftables_marker))

    if ufw_status is not None:
        return ufw_status
    if firewalld_config.exists():
        return FirewallStatus(provider="firewalld", enabled=None, source=str(firewalld_config))
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


def _enabled_systemd_unit_marker(etc_root: Path, unit_name: str) -> Optional[Path]:
    for marker in _enabled_systemd_unit_markers(etc_root):
        if marker.name == unit_name:
            return marker
    return None


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


def _read_container_runtime_signals(root: Path, etc_root: Path) -> tuple[ContainerRuntimeSignal, ...]:
    signals: list[ContainerRuntimeSignal] = []
    signals.extend(_read_docker_daemon_json_signals(etc_root / "docker" / "daemon.json"))
    signals.extend(_read_docker_group_signals(etc_root / "group"))
    signals.extend(_read_container_runtime_systemd_signals(root, etc_root))
    return tuple(signals)


def _read_docker_daemon_json_signals(path: Path) -> tuple[ContainerRuntimeSignal, ...]:
    text = read_text(path)
    if not text:
        return ()
    try:
        payload = json.loads(text)
    except json.JSONDecodeError:
        return ()
    if not isinstance(payload, dict):
        return ()
    hosts = payload.get("hosts")
    if not isinstance(hosts, list):
        return ()
    signals: list[ContainerRuntimeSignal] = []
    for host in hosts:
        if isinstance(host, str) and _is_external_tcp_endpoint(host):
            signals.append(
                ContainerRuntimeSignal(
                    runtime="docker",
                    signal="tcp_api",
                    evidence=host.strip(),
                    source=str(path),
                )
            )
    return tuple(signals)


def _read_docker_group_signals(path: Path) -> tuple[ContainerRuntimeSignal, ...]:
    for raw_line in read_text(path).splitlines():
        parts = raw_line.split(":")
        if len(parts) < 4 or parts[0] != "docker":
            continue
        members = tuple(
            member.strip()
            for member in parts[3].split(",")
            if member.strip() and member.strip() != "root"
        )
        if not members:
            return ()
        return (
            ContainerRuntimeSignal(
                runtime="docker",
                signal="docker_group_members",
                evidence=f"docker group members: {', '.join(members)}",
                source=str(path),
            ),
        )
    return ()


def _read_container_runtime_systemd_signals(root: Path, etc_root: Path) -> tuple[ContainerRuntimeSignal, ...]:
    signals: list[ContainerRuntimeSignal] = []
    runtime_units = {
        "docker.service": "docker",
        "podman.service": "podman",
        "podman.socket": "podman",
    }
    for marker in _enabled_systemd_unit_markers(etc_root):
        runtime = runtime_units.get(marker.name)
        if runtime is None:
            continue
        unit_text, unit_source = _read_systemd_unit_text(root, etc_root, marker.name, marker)
        if not unit_text:
            continue
        for endpoint in _container_runtime_tcp_endpoints(unit_text):
            if _is_external_tcp_endpoint(endpoint):
                signals.append(
                    ContainerRuntimeSignal(
                        runtime=runtime,
                        signal="tcp_api",
                        evidence=endpoint,
                        source=unit_source,
                    )
                )
    return tuple(signals)


def _container_runtime_tcp_endpoints(unit_text: str) -> tuple[str, ...]:
    endpoints: list[str] = []
    for exec_start in _unit_values(unit_text, "ExecStart", ("service",)):
        parts = _shlex_split(exec_start)
        for index, part in enumerate(parts):
            if part in {"-H", "--host"} and index + 1 < len(parts):
                endpoints.append(parts[index + 1])
            elif part.startswith("-Htcp://"):
                endpoints.append(part[2:])
            elif part.startswith("--host=tcp://"):
                endpoints.append(part.split("=", 1)[1])
            elif part.startswith("tcp://"):
                endpoints.append(part)
    for listen_stream in _unit_values(unit_text, "ListenStream", ("socket",)):
        value = listen_stream.strip()
        if value.startswith("tcp://"):
            endpoints.append(value)
        elif ":" in value and not value.startswith("/"):
            endpoints.append(f"tcp://{value}")
    return tuple(dict.fromkeys(endpoints))


def _shlex_split(value: str) -> list[str]:
    try:
        return shlex.split(value)
    except ValueError:
        return value.split()


def _is_external_tcp_endpoint(endpoint: str) -> bool:
    value = endpoint.strip()
    if not value.startswith("tcp://"):
        return False
    parsed = urlparse(value)
    host = parsed.hostname
    if host is None:
        return False
    return host not in {"localhost", "127.0.0.1", "::1"}


def _enabled_systemd_service_markers(etc_root: Path) -> tuple[Path, ...]:
    return tuple(path for path in _enabled_systemd_unit_markers(etc_root) if path.name.endswith(".service"))


def _enabled_systemd_unit_markers(etc_root: Path) -> tuple[Path, ...]:
    system_root = etc_root / "systemd" / "system"
    try:
        return tuple(sorted(path for path in system_root.glob("*.wants/*") if _path_exists_or_symlink(path)))
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
            unit_texts = [text]
            sources = [str(candidate)]
            for drop_in in _systemd_drop_in_candidates(etc_root, service_name):
                drop_in_text = read_text(drop_in)
                if drop_in_text:
                    unit_texts.append(drop_in_text)
                    sources.append(str(drop_in))
            return "\n".join(unit_texts), ", ".join(sources)
    return "", "not found"


def _systemd_drop_in_candidates(etc_root: Path, service_name: str) -> tuple[Path, ...]:
    drop_in_root = etc_root / "systemd" / "system" / f"{service_name}.d"
    try:
        return tuple(sorted(drop_in_root.glob("*.conf")))
    except OSError:
        return ()


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
    return _unit_values(unit_text, key, ("service",))


def _unit_values(unit_text: str, key: str, sections: tuple[str, ...]) -> tuple[str, ...]:
    values: list[str] = []
    in_target_section = False
    for raw_line in unit_text.splitlines():
        line = raw_line.strip()
        if not line or line.startswith("#"):
            continue
        if line.startswith("[") and line.endswith("]"):
            in_target_section = line[1:-1].strip().lower() in sections
            continue
        if not in_target_section or "=" not in line:
            continue
        raw_key, value = line.split("=", 1)
        if raw_key.strip().lower() == key.lower():
            stripped_value = value.strip()
            if stripped_value:
                values.append(stripped_value)
            else:
                values.clear()
    return tuple(values)


def _first_service_value(unit_text: str, key: str) -> str:
    values = _service_values(unit_text, key)
    return values[0] if values else ""


def _read_package_vulnerabilities(
    vulnerability_feed: Optional[Union[Path, str]],
    vulnerability_feed_format: str,
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

    if vulnerability_feed_format == "linwarden":
        return _read_linwarden_vulnerability_feed(feed_path, payload)
    if vulnerability_feed_format == "trivy":
        return _read_trivy_vulnerability_feed(feed_path, payload)
    if vulnerability_feed_format == "grype":
        return _read_grype_vulnerability_feed(feed_path, payload)
    if vulnerability_feed_format == "osv":
        return _read_osv_vulnerability_feed(feed_path, payload)
    raise ValueError(
        f"vulnerability feed format must be linwarden, trivy, grype, or osv: {vulnerability_feed_format}"
    )


def _read_linwarden_vulnerability_feed(feed_path: Path, payload: object) -> tuple[PackageVulnerability, ...]:
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


def _read_trivy_vulnerability_feed(feed_path: Path, payload: object) -> tuple[PackageVulnerability, ...]:
    if isinstance(payload, dict):
        results = payload.get("Results")
    elif isinstance(payload, list):
        results = payload
    else:
        raise ValueError(f"vulnerability feed {feed_path}: trivy root must be an object or array")

    if not isinstance(results, list):
        raise ValueError(f"vulnerability feed {feed_path}: trivy Results must be an array")

    vulnerabilities: list[PackageVulnerability] = []
    for result_index, result in enumerate(results):
        if not isinstance(result, dict):
            raise ValueError(f"vulnerability feed {feed_path}: trivy Results[{result_index}] must be an object")
        target = _optional_trivy_string(result, "Target")
        entries = result.get("Vulnerabilities")
        if entries is None:
            continue
        if not isinstance(entries, list):
            raise ValueError(
                f"vulnerability feed {feed_path}: trivy Results[{result_index}].Vulnerabilities must be an array"
            )
        for vulnerability_index, entry in enumerate(entries):
            if not isinstance(entry, dict):
                raise ValueError(
                    f"vulnerability feed {feed_path}: trivy Results[{result_index}]."
                    f"Vulnerabilities[{vulnerability_index}] must be an object"
                )
            vulnerabilities.append(
                _package_vulnerability_from_trivy_entry(
                    feed_path,
                    target,
                    result_index,
                    vulnerability_index,
                    entry,
                )
            )
    return tuple(vulnerabilities)


def _read_grype_vulnerability_feed(feed_path: Path, payload: object) -> tuple[PackageVulnerability, ...]:
    if not isinstance(payload, dict):
        raise ValueError(f"vulnerability feed {feed_path}: grype root must be an object")

    matches = payload.get("matches")
    if not isinstance(matches, list):
        raise ValueError(f"vulnerability feed {feed_path}: grype matches must be an array")

    source = _grype_source(payload)
    vulnerabilities: list[PackageVulnerability] = []
    for index, match in enumerate(matches):
        if not isinstance(match, dict):
            raise ValueError(f"vulnerability feed {feed_path}: grype matches[{index}] must be an object")
        vulnerabilities.append(_package_vulnerability_from_grype_match(feed_path, source, index, match))
    return tuple(vulnerabilities)


def _read_osv_vulnerability_feed(feed_path: Path, payload: object) -> tuple[PackageVulnerability, ...]:
    if not isinstance(payload, dict):
        raise ValueError(f"vulnerability feed {feed_path}: osv root must be an object")

    results = payload.get("results")
    if not isinstance(results, list):
        raise ValueError(f"vulnerability feed {feed_path}: osv results must be an array")

    vulnerabilities: list[PackageVulnerability] = []
    for result_index, result in enumerate(results):
        if not isinstance(result, dict):
            raise ValueError(f"vulnerability feed {feed_path}: osv results[{result_index}] must be an object")
        source_path = _osv_source_path(result)
        packages = result.get("packages")
        if packages is None:
            continue
        if not isinstance(packages, list):
            raise ValueError(f"vulnerability feed {feed_path}: osv results[{result_index}].packages must be an array")
        for package_index, package_entry in enumerate(packages):
            if not isinstance(package_entry, dict):
                raise ValueError(
                    f"vulnerability feed {feed_path}: osv results[{result_index}]."
                    f"packages[{package_index}] must be an object"
            )
            vulnerabilities.extend(
                _package_vulnerabilities_from_osv_package(
                    feed_path,
                    source_path,
                    result_index,
                    package_index,
                    package_entry,
                )
            )
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


def _package_vulnerability_from_trivy_entry(
    feed_path: Path,
    target: str,
    result_index: int,
    vulnerability_index: int,
    entry: dict[str, object],
) -> PackageVulnerability:
    severity = _required_trivy_string(feed_path, result_index, vulnerability_index, entry, "Severity").lower()
    if severity == "unknown":
        severity = "low"
    if severity not in _VULNERABILITY_SEVERITIES:
        raise ValueError(
            f"vulnerability feed {feed_path}: trivy Results[{result_index}]."
            f"Vulnerabilities[{vulnerability_index}].Severity must be critical, high, medium, low, or unknown"
        )

    return PackageVulnerability(
        package=_required_trivy_string(feed_path, result_index, vulnerability_index, entry, "PkgName"),
        installed_version=_required_trivy_string(
            feed_path, result_index, vulnerability_index, entry, "InstalledVersion"
        ),
        fixed_version=_optional_trivy_string(entry, "FixedVersion"),
        vulnerability_id=_required_trivy_string(
            feed_path, result_index, vulnerability_index, entry, "VulnerabilityID"
        ),
        severity=severity,
        summary=_optional_trivy_string(entry, "Title") or _optional_trivy_string(entry, "Description"),
        url=_trivy_reference_url(entry),
        source=f"{feed_path}#{target}" if target else str(feed_path),
    )


def _package_vulnerability_from_grype_match(
    feed_path: Path,
    source: str,
    index: int,
    match: dict[str, object],
) -> PackageVulnerability:
    vulnerability = _required_grype_object(feed_path, index, match, "vulnerability")
    artifact = _required_grype_object(feed_path, index, match, "artifact")
    severity = _required_grype_string(feed_path, index, vulnerability, "severity").lower()
    if severity == "negligible" or severity == "unknown":
        severity = "low"
    if severity not in _VULNERABILITY_SEVERITIES:
        raise ValueError(
            f"vulnerability feed {feed_path}: grype matches[{index}].vulnerability.severity must be "
            "critical, high, medium, low, negligible, or unknown"
        )

    return PackageVulnerability(
        package=_required_grype_string(feed_path, index, artifact, "name"),
        installed_version=_required_grype_string(feed_path, index, artifact, "version"),
        fixed_version=_grype_fixed_version(vulnerability),
        vulnerability_id=_required_grype_string(feed_path, index, vulnerability, "id"),
        severity=severity,
        summary=_optional_grype_string(vulnerability, "description"),
        url=_grype_reference_url(vulnerability),
        source=f"{feed_path}#{source}" if source else str(feed_path),
    )


def _package_vulnerabilities_from_osv_package(
    feed_path: Path,
    source_path: str,
    result_index: int,
    package_index: int,
    package_entry: dict[str, object],
) -> list[PackageVulnerability]:
    package = _required_osv_package(feed_path, result_index, package_index, package_entry)
    entries = package_entry.get("vulnerabilities")
    if entries is None:
        return []
    if not isinstance(entries, list):
        raise ValueError(
            f"vulnerability feed {feed_path}: osv results[{result_index}].packages[{package_index}]."
            "vulnerabilities must be an array"
        )

    vulnerability_by_id: dict[str, dict[str, object]] = {}
    ordered_vulnerabilities: list[tuple[str, dict[str, object]]] = []
    for vulnerability_index, entry in enumerate(entries):
        if not isinstance(entry, dict):
            raise ValueError(
                f"vulnerability feed {feed_path}: osv results[{result_index}].packages[{package_index}]."
                f"vulnerabilities[{vulnerability_index}] must be an object"
            )
        vulnerability_id = _required_osv_string(
            feed_path,
            result_index,
            package_index,
            vulnerability_index,
            entry,
            "id",
        )
        vulnerability_by_id[vulnerability_id] = entry
        ordered_vulnerabilities.append((vulnerability_id, entry))

    selected: list[tuple[str, dict[str, object]]] = []
    handled_ids: set[str] = set()
    groups = package_entry.get("groups")
    if isinstance(groups, list):
        for group in groups:
            if not isinstance(group, dict):
                continue
            ids = group.get("ids")
            if not isinstance(ids, list):
                continue
            group_ids = [vulnerability_id for vulnerability_id in ids if isinstance(vulnerability_id, str)]
            if not group_ids:
                continue
            for vulnerability_id in group_ids:
                vulnerability = vulnerability_by_id.get(vulnerability_id)
                if vulnerability is not None:
                    selected.append((group_ids[0], vulnerability))
                    handled_ids.update(group_ids)
                    break

    for vulnerability_id, vulnerability in ordered_vulnerabilities:
        if vulnerability_id not in handled_ids:
            selected.append((vulnerability_id, vulnerability))

    return [
        _package_vulnerability_from_osv_entry(feed_path, source_path, package, vulnerability_id, vulnerability)
        for vulnerability_id, vulnerability in selected
    ]


def _package_vulnerability_from_osv_entry(
    feed_path: Path,
    source_path: str,
    package: dict[str, str],
    vulnerability_id: str,
    vulnerability: dict[str, object],
) -> PackageVulnerability:
    return PackageVulnerability(
        package=package["name"],
        installed_version=package["version"],
        fixed_version=_osv_fixed_version(package["name"], vulnerability),
        vulnerability_id=vulnerability_id,
        severity=_osv_severity(package["name"], vulnerability),
        summary=_optional_osv_string(vulnerability, "summary") or _optional_osv_string(vulnerability, "details"),
        url=_osv_reference_url(vulnerability) or f"https://osv.dev/vulnerability/{vulnerability_id}",
        source=f"{feed_path}#{source_path}" if source_path else str(feed_path),
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


def _required_trivy_string(
    feed_path: Path,
    result_index: int,
    vulnerability_index: int,
    entry: dict[str, object],
    key: str,
) -> str:
    value = entry.get(key)
    if not isinstance(value, str) or not value.strip():
        raise ValueError(
            f"vulnerability feed {feed_path}: trivy Results[{result_index}]."
            f"Vulnerabilities[{vulnerability_index}].{key} must be a non-empty string"
        )
    return value.strip()


def _optional_trivy_string(entry: dict[str, object], key: str) -> str:
    value = entry.get(key, "")
    return value.strip() if isinstance(value, str) else ""


def _trivy_reference_url(entry: dict[str, object]) -> str:
    primary_url = _optional_trivy_string(entry, "PrimaryURL")
    if primary_url:
        return primary_url
    references = entry.get("References")
    if isinstance(references, list):
        for reference in references:
            if isinstance(reference, str) and reference.strip():
                return reference.strip()
    return ""


def _required_grype_object(
    feed_path: Path,
    index: int,
    match: dict[str, object],
    key: str,
) -> dict[str, object]:
    value = match.get(key)
    if not isinstance(value, dict):
        raise ValueError(f"vulnerability feed {feed_path}: grype matches[{index}].{key} must be an object")
    return value


def _required_grype_string(
    feed_path: Path,
    index: int,
    entry: dict[str, object],
    key: str,
) -> str:
    value = entry.get(key)
    if not isinstance(value, str) or not value.strip():
        raise ValueError(f"vulnerability feed {feed_path}: grype matches[{index}].{key} must be a non-empty string")
    return value.strip()


def _optional_grype_string(entry: dict[str, object], key: str) -> str:
    value = entry.get(key, "")
    return value.strip() if isinstance(value, str) else ""


def _grype_fixed_version(vulnerability: dict[str, object]) -> str:
    fix = vulnerability.get("fix")
    if not isinstance(fix, dict):
        return ""
    versions = fix.get("versions")
    if not isinstance(versions, list):
        return ""
    return ", ".join(version.strip() for version in versions if isinstance(version, str) and version.strip())


def _grype_reference_url(vulnerability: dict[str, object]) -> str:
    data_source = _optional_grype_string(vulnerability, "dataSource")
    if data_source:
        return data_source
    urls = vulnerability.get("urls")
    if isinstance(urls, list):
        for url in urls:
            if isinstance(url, str) and url.strip():
                return url.strip()
    return ""


def _grype_source(payload: dict[str, object]) -> str:
    source = payload.get("source")
    if not isinstance(source, dict):
        return ""
    target = source.get("target")
    if isinstance(target, dict):
        user_input = _optional_grype_string(target, "userInput")
        if user_input:
            return user_input
    return _optional_grype_string(source, "type")


def _osv_source_path(result: dict[str, object]) -> str:
    source = result.get("source")
    if not isinstance(source, dict):
        return ""
    path = source.get("path")
    return path.strip() if isinstance(path, str) else ""


def _required_osv_package(
    feed_path: Path,
    result_index: int,
    package_index: int,
    package_entry: dict[str, object],
) -> dict[str, str]:
    package = package_entry.get("package")
    if not isinstance(package, dict):
        raise ValueError(
            f"vulnerability feed {feed_path}: osv results[{result_index}].packages[{package_index}]."
            "package must be an object"
        )
    name = _required_osv_package_string(feed_path, result_index, package_index, package, "name")
    version = _required_osv_package_string(feed_path, result_index, package_index, package, "version")
    return {"name": name, "version": version}


def _required_osv_package_string(
    feed_path: Path,
    result_index: int,
    package_index: int,
    package: dict[object, object],
    key: str,
) -> str:
    value = package.get(key)
    if not isinstance(value, str) or not value.strip():
        raise ValueError(
            f"vulnerability feed {feed_path}: osv results[{result_index}].packages[{package_index}]."
            f"package.{key} must be a non-empty string"
        )
    return value.strip()


def _required_osv_string(
    feed_path: Path,
    result_index: int,
    package_index: int,
    vulnerability_index: int,
    entry: dict[str, object],
    key: str,
) -> str:
    value = entry.get(key)
    if not isinstance(value, str) or not value.strip():
        raise ValueError(
            f"vulnerability feed {feed_path}: osv results[{result_index}].packages[{package_index}]."
            f"vulnerabilities[{vulnerability_index}].{key} must be a non-empty string"
        )
    return value.strip()


def _optional_osv_string(entry: dict[str, object], key: str) -> str:
    value = entry.get(key, "")
    return value.strip() if isinstance(value, str) else ""


def _osv_fixed_version(package_name: str, vulnerability: dict[str, object]) -> str:
    affected = vulnerability.get("affected")
    if not isinstance(affected, list):
        return ""

    fixed_versions: list[str] = []
    for affected_entry in affected:
        if not isinstance(affected_entry, dict):
            continue
        affected_package = affected_entry.get("package")
        if isinstance(affected_package, dict):
            affected_name = affected_package.get("name")
            if isinstance(affected_name, str) and affected_name.strip() and affected_name.strip() != package_name:
                continue
        ranges = affected_entry.get("ranges")
        if not isinstance(ranges, list):
            continue
        for range_entry in ranges:
            if not isinstance(range_entry, dict):
                continue
            events = range_entry.get("events")
            if not isinstance(events, list):
                continue
            for event in events:
                if not isinstance(event, dict):
                    continue
                fixed = event.get("fixed")
                if isinstance(fixed, str) and fixed.strip() and fixed.strip() not in fixed_versions:
                    fixed_versions.append(fixed.strip())
    return ", ".join(fixed_versions)


def _osv_reference_url(vulnerability: dict[str, object]) -> str:
    references = vulnerability.get("references")
    if isinstance(references, list):
        for reference in references:
            if not isinstance(reference, dict):
                continue
            url = reference.get("url")
            if isinstance(url, str) and url.strip():
                return url.strip()
    return ""


def _osv_severity(package_name: str, vulnerability: dict[str, object]) -> str:
    severity = vulnerability.get("severity")
    if isinstance(severity, list):
        parsed = _osv_severity_from_list(severity)
        if parsed:
            return parsed

    affected = vulnerability.get("affected")
    if isinstance(affected, list):
        for affected_entry in affected:
            if not isinstance(affected_entry, dict):
                continue
            affected_package = affected_entry.get("package")
            if isinstance(affected_package, dict):
                affected_name = affected_package.get("name")
                if isinstance(affected_name, str) and affected_name.strip() and affected_name.strip() != package_name:
                    continue
            affected_severity = affected_entry.get("severity")
            if isinstance(affected_severity, list):
                parsed = _osv_severity_from_list(affected_severity)
                if parsed:
                    return parsed
    return "low"


def _osv_severity_from_list(severity: list[object]) -> str:
    for entry in severity:
        if not isinstance(entry, dict):
            continue
        score = entry.get("score")
        if not isinstance(score, str) or not score.strip():
            continue
        normalized = score.strip().lower()
        if normalized in _VULNERABILITY_SEVERITIES:
            return normalized
        numeric_score = _cvss_base_score(score.strip())
        if numeric_score is not None:
            return _cvss_severity(numeric_score)
    return ""


def _cvss_severity(score: float) -> str:
    if score >= 9.0:
        return "critical"
    if score >= 7.0:
        return "high"
    if score >= 4.0:
        return "medium"
    return "low"


def _cvss_base_score(score: str) -> Optional[float]:
    try:
        return float(score)
    except ValueError:
        pass
    if score.startswith("CVSS:3."):
        return _cvss_v3_base_score(score)
    return None


def _cvss_v3_base_score(vector: str) -> Optional[float]:
    metrics = {}
    for raw_metric in vector.split("/"):
        key, separator, value = raw_metric.partition(":")
        if not separator or not key or not value:
            continue
        metrics[key] = value

    scope = metrics.get("S")
    if scope not in {"U", "C"}:
        return None
    try:
        av = {"N": 0.85, "A": 0.62, "L": 0.55, "P": 0.2}[metrics["AV"]]
        ac = {"L": 0.77, "H": 0.44}[metrics["AC"]]
        if scope == "U":
            pr = {"N": 0.85, "L": 0.62, "H": 0.27}[metrics["PR"]]
        else:
            pr = {"N": 0.85, "L": 0.68, "H": 0.5}[metrics["PR"]]
        ui = {"N": 0.85, "R": 0.62}[metrics["UI"]]
        confidentiality = {"H": 0.56, "L": 0.22, "N": 0.0}[metrics["C"]]
        integrity = {"H": 0.56, "L": 0.22, "N": 0.0}[metrics["I"]]
        availability = {"H": 0.56, "L": 0.22, "N": 0.0}[metrics["A"]]
    except KeyError:
        return None

    impact_subscore = 1 - ((1 - confidentiality) * (1 - integrity) * (1 - availability))
    if scope == "U":
        impact = 6.42 * impact_subscore
    else:
        impact = 7.52 * (impact_subscore - 0.029) - (3.25 * ((impact_subscore - 0.02) ** 15))
    if impact <= 0:
        return 0.0

    exploitability = 8.22 * av * ac * pr * ui
    if scope == "U":
        return _round_up_1_decimal(min(impact + exploitability, 10))
    return _round_up_1_decimal(min(1.08 * (impact + exploitability), 10))


def _round_up_1_decimal(value: float) -> float:
    return math.ceil(value * 10) / 10
