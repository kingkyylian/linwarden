from __future__ import annotations

import shlex
from pathlib import Path

from .models import LoadAverage, MemoryInfo, Mount


def read_text(path: Path, default: str = "") -> str:
    try:
        return path.read_text(encoding="utf-8").strip()
    except OSError:
        return default


def parse_os_release(path: Path) -> dict[str, str]:
    values: dict[str, str] = {}
    for raw_line in read_text(path).splitlines():
        line = raw_line.strip()
        if not line or line.startswith("#") or "=" not in line:
            continue
        key, raw_value = line.split("=", 1)
        try:
            parsed = shlex.split(raw_value, comments=False, posix=True)
            value = parsed[0] if parsed else ""
        except ValueError:
            value = raw_value.strip().strip('"').strip("'")
        values[key] = value
    return values


def parse_sshd_config(path: Path) -> dict[str, str]:
    values: dict[str, str] = {}
    for raw_line in read_text(path).splitlines():
        line = raw_line.strip()
        if not line or line.startswith("#"):
            continue
        if "#" in line:
            line = line.split("#", 1)[0].strip()
        parts = line.split(None, 1)
        if len(parts) == 2:
            values[parts[0].lower()] = parts[1].strip()
    return values


def parse_loadavg(path: Path) -> LoadAverage:
    parts = read_text(path, "0 0 0").split()
    values = [float(part) for part in parts[:3]]
    while len(values) < 3:
        values.append(0.0)
    return LoadAverage(values[0], values[1], values[2])


def parse_meminfo(path: Path) -> MemoryInfo:
    values: dict[str, int] = {}
    for raw_line in read_text(path).splitlines():
        if ":" not in raw_line:
            continue
        key, raw_value = raw_line.split(":", 1)
        parts = raw_value.strip().split()
        if parts and parts[0].isdigit():
            values[key] = int(parts[0])

    return MemoryInfo(
        total_mib=values.get("MemTotal", 0) // 1024,
        available_mib=values.get("MemAvailable", values.get("MemFree", 0)) // 1024,
        swap_total_mib=values.get("SwapTotal", 0) // 1024,
        swap_free_mib=values.get("SwapFree", 0) // 1024,
    )


def parse_mounts(path: Path) -> tuple[Mount, ...]:
    mounts: list[Mount] = []
    for raw_line in read_text(path).splitlines():
        parts = raw_line.split()
        if len(parts) < 4:
            continue
        mounts.append(
            Mount(
                source=_unescape_mount(parts[0]),
                mount_point=_unescape_mount(parts[1]),
                filesystem=parts[2],
                options=tuple(parts[3].split(",")),
            )
        )
    return tuple(mounts)


def _unescape_mount(value: str) -> str:
    return (
        value.replace("\\040", " ")
        .replace("\\011", "\t")
        .replace("\\012", "\n")
        .replace("\\134", "\\")
    )
