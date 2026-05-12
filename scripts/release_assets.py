from __future__ import annotations

import argparse
import hashlib
from pathlib import Path
from typing import Optional, Sequence

EXCLUDED_MANIFEST_NAMES = {"SHA256SUMS", "SHA256SUMS.asc"}


def write_sha256sums(dist_dir: Path) -> Path:
    files = [
        path
        for path in sorted(dist_dir.iterdir())
        if path.is_file() and path.name not in EXCLUDED_MANIFEST_NAMES and not path.name.endswith(".asc")
    ]
    if not files:
        raise ValueError(f"no release files found in {dist_dir}")

    manifest = dist_dir / "SHA256SUMS"
    lines = [f"{_sha256(path)}  {path.name}" for path in files]
    manifest.write_text("\n".join(lines) + "\n", encoding="utf-8")
    return manifest


def main(argv: Optional[Sequence[str]] = None) -> int:
    parser = argparse.ArgumentParser(description="Generate Linwarden release asset metadata.")
    parser.add_argument("dist_dir", type=Path)
    args = parser.parse_args(argv)
    write_sha256sums(args.dist_dir)
    return 0


def _sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


if __name__ == "__main__":
    raise SystemExit(main())
