from __future__ import annotations

import platform
import socket
from pathlib import Path
from typing import Optional, Union

from .models import HostSnapshot
from .parsers import (
    parse_loadavg,
    parse_meminfo,
    parse_mounts,
    parse_os_release,
    parse_sshd_config,
    read_text,
)


SYSCTL_PATHS = {
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
    "vm.mmap_min_addr": ("sys", "vm", "mmap_min_addr"),
}


def collect_host_snapshot(
    root: Union[Path, str] = Path("/"),
    proc_root: Optional[Union[Path, str]] = None,
    etc_root: Optional[Union[Path, str]] = None,
) -> HostSnapshot:
    root_path = Path(root)
    proc_path = Path(proc_root) if proc_root is not None else root_path / "proc"
    etc_path = Path(etc_root) if etc_root is not None else root_path / "etc"

    hostname = read_text(etc_path / "hostname", socket.gethostname()) or socket.gethostname()
    os_release = parse_os_release(etc_path / "os-release")
    kernel_release = read_text(proc_path / "sys" / "kernel" / "osrelease", platform.release())
    uptime = _read_float(proc_path / "uptime")

    return HostSnapshot(
        hostname=hostname,
        os_release=os_release,
        kernel_release=kernel_release,
        uptime_seconds=uptime,
        load_average=parse_loadavg(proc_path / "loadavg"),
        memory=parse_meminfo(proc_path / "meminfo"),
        mounts=parse_mounts(proc_path / "mounts"),
        sysctls=_read_sysctls(proc_path),
        sshd_options=parse_sshd_config(etc_path / "ssh" / "sshd_config"),
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
