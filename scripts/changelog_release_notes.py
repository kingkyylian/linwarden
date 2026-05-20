from __future__ import annotations

import argparse
import sys
from pathlib import Path
from typing import Optional, Sequence

if not __package__:
    sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from scripts.verify_release_version import changelog_release_notes, version_from_ref


def write_changelog_release_notes(changelog: Path, ref_name: str, output: Path) -> None:
    version = version_from_ref(ref_name)
    output.write_text(changelog_release_notes(changelog, version), encoding="utf-8")


def main(argv: Optional[Sequence[str]] = None) -> int:
    parser = argparse.ArgumentParser(description="Write GitHub release notes from the matching CHANGELOG.md section.")
    parser.add_argument("--ref-name", required=True)
    parser.add_argument("--changelog", type=Path, default=Path("CHANGELOG.md"))
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args(argv)
    try:
        write_changelog_release_notes(args.changelog, args.ref_name, args.output)
    except ValueError as exc:
        parser.error(str(exc))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
