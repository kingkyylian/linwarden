from __future__ import annotations

import argparse
import re
from pathlib import Path
from typing import Optional, Sequence

PROJECT_VERSION_RE = re.compile(r'^version\s*=\s*"([^"]+)"\s*(?:#.*)?$')
RUNTIME_VERSION_RE = re.compile(r'^__version__\s*=\s*"([^"]+)"\s*(?:#.*)?$')


def verify_release_version(
    pyproject: Path,
    package_init: Path,
    ref_name: str,
    dist_dir: Optional[Path] = None,
    changelog: Optional[Path] = None,
) -> None:
    version = read_project_version(pyproject)
    runtime_version = read_runtime_version(package_init)
    if runtime_version != version:
        raise ValueError(f"runtime version {runtime_version} does not match pyproject version {version}")
    tag_version = version_from_ref(ref_name)
    if tag_version != version:
        raise ValueError(f"tag {ref_name} does not match pyproject version {version}")
    if changelog is not None:
        verify_changelog_section(changelog, version)
    if dist_dir is not None:
        verify_dist_files(dist_dir, version)


def read_project_version(pyproject: Path) -> str:
    in_project = False
    try:
        lines = pyproject.read_text(encoding="utf-8").splitlines()
    except OSError as exc:
        raise ValueError(f"failed to read {pyproject}: {exc}") from exc

    for raw_line in lines:
        line = raw_line.strip()
        if not line or line.startswith("#"):
            continue
        if line.startswith("[") and line.endswith("]"):
            in_project = line == "[project]"
            continue
        if not in_project:
            continue
        match = PROJECT_VERSION_RE.match(line)
        if match is not None:
            return match.group(1)
    raise ValueError(f"pyproject version not found in {pyproject}")


def read_runtime_version(package_init: Path) -> str:
    try:
        lines = package_init.read_text(encoding="utf-8").splitlines()
    except OSError as exc:
        raise ValueError(f"failed to read {package_init}: {exc}") from exc

    for raw_line in lines:
        match = RUNTIME_VERSION_RE.match(raw_line.strip())
        if match is not None:
            return match.group(1)
    raise ValueError(f"runtime version not found in {package_init}")


def version_from_ref(ref_name: str) -> str:
    if not ref_name.startswith("v") or len(ref_name) == 1:
        raise ValueError(f"release ref must be a v-prefixed tag: {ref_name}")
    return ref_name[1:]


def verify_dist_files(dist_dir: Path, version: str) -> None:
    try:
        files = sorted(path for path in dist_dir.iterdir() if path.is_file())
    except OSError as exc:
        raise ValueError(f"failed to read {dist_dir}: {exc}") from exc

    release_files = [
        path
        for path in files
        if path.name.endswith((".whl", ".tar.gz")) and path.name.startswith("linwarden-")
    ]
    if not release_files:
        raise ValueError(f"no Linwarden distribution files found in {dist_dir}")

    expected_prefix = f"linwarden-{version}"
    for path in release_files:
        if path.name == f"{expected_prefix}.tar.gz":
            continue
        if path.name.startswith(f"{expected_prefix}-") and path.name.endswith(".whl"):
            continue
        raise ValueError(f"dist file {path.name} does not match version {version}")


def verify_changelog_section(changelog: Path, version: str) -> None:
    try:
        lines = changelog.read_text(encoding="utf-8").splitlines()
    except OSError as exc:
        raise ValueError(f"failed to read {changelog}: {exc}") from exc

    in_section = False
    saw_entry = False
    for raw_line in lines:
        line = raw_line.strip()
        if line.startswith("## "):
            if in_section:
                break
            in_section = _is_changelog_version_heading(line, version)
            continue
        if in_section and line.startswith("- "):
            saw_entry = True

    if not in_section:
        raise ValueError(f"changelog section for version {version} not found in {changelog}")
    if not saw_entry:
        raise ValueError(f"changelog section for version {version} has no entries")


def _is_changelog_version_heading(line: str, version: str) -> bool:
    return re.fullmatch(rf"##\s+{re.escape(version)}\s+-\s+\d{{4}}-\d{{2}}-\d{{2}}", line) is not None


def main(argv: Optional[Sequence[str]] = None) -> int:
    parser = argparse.ArgumentParser(description="Verify Linwarden release tag, version, and distribution files.")
    parser.add_argument("--pyproject", type=Path, default=Path("pyproject.toml"))
    parser.add_argument("--package-init", type=Path, default=Path("src/linwarden/__init__.py"))
    parser.add_argument("--ref-name", required=True)
    parser.add_argument("--dist-dir", type=Path)
    parser.add_argument("--changelog", type=Path, default=Path("CHANGELOG.md"))
    args = parser.parse_args(argv)
    try:
        verify_release_version(args.pyproject, args.package_init, args.ref_name, args.dist_dir, args.changelog)
    except ValueError as exc:
        parser.error(str(exc))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
