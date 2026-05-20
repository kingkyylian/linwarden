from __future__ import annotations

import argparse
import os
import subprocess
import sys
from pathlib import Path
from tempfile import TemporaryDirectory
from typing import Callable, Optional, Protocol


class CompletedProcessLike(Protocol):
    stdout: str


Runner = Callable[..., CompletedProcessLike]


def smoke_pypi_release(
    version: str,
    fixture_root: Path = Path("tests/fixtures/linux-root"),
    venv_path: Optional[Path] = None,
    python: str = sys.executable,
    runner: Runner = subprocess.run,
) -> None:
    normalized_version = _normalize_version(version)
    if not fixture_root.exists():
        raise FileNotFoundError(f"fixture root not found: {fixture_root}")

    if venv_path is None:
        with TemporaryDirectory(prefix=f"linwarden-pypi-smoke-{normalized_version}-") as temp_dir:
            _run_smoke(normalized_version, fixture_root, Path(temp_dir) / "venv", python, runner)
        return

    _run_smoke(normalized_version, fixture_root, venv_path, python, runner)


def _run_smoke(
    version: str,
    fixture_root: Path,
    venv_path: Path,
    python: str,
    runner: Runner,
) -> None:
    scripts_dir = "Scripts" if os.name == "nt" else "bin"
    venv_python = venv_path / scripts_dir / ("python.exe" if os.name == "nt" else "python")
    linwarden = venv_path / scripts_dir / ("linwarden.exe" if os.name == "nt" else "linwarden")

    runner([python, "-m", "venv", str(venv_path)], check=True)
    runner(
        [
            str(venv_python),
            "-m",
            "pip",
            "install",
            "--no-cache-dir",
            "--upgrade",
            f"linwarden=={version}",
        ],
        check=True,
    )
    completed = runner([str(linwarden), "--version"], check=True, capture_output=True, text=True)
    expected_version = f"linwarden {version}"
    if completed.stdout.strip() != expected_version:
        raise RuntimeError(
            f"installed linwarden version did not match {version}: {completed.stdout.strip()!r}"
        )
    runner([str(linwarden), "--help"], check=True)
    runner(
        [
            str(linwarden),
            "scan",
            "--root",
            str(fixture_root),
            "--format",
            "json",
            "--fail-on",
            "off",
        ],
        check=True,
    )


def _normalize_version(version: str) -> str:
    value = version.strip()
    if value.startswith("v"):
        value = value[1:]
    if not value:
        raise ValueError("version must not be empty")
    return value


def main() -> int:
    parser = argparse.ArgumentParser(description="Install a Linwarden release from PyPI and run CLI smoke checks.")
    parser.add_argument("version", help="release version to install, with or without a leading v")
    parser.add_argument(
        "--fixture-root",
        type=Path,
        default=Path("tests/fixtures/linux-root"),
        help="fixture root used for the smoke scan",
    )
    parser.add_argument("--venv", type=Path, help="optional virtual environment path to create and reuse")
    parser.add_argument("--python", default=sys.executable, help="Python executable used to create the smoke venv")
    args = parser.parse_args()

    smoke_pypi_release(args.version, fixture_root=args.fixture_root, venv_path=args.venv, python=args.python)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
