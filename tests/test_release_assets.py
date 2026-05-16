import hashlib
import unittest
from pathlib import Path
from tempfile import TemporaryDirectory

from scripts.release_assets import write_sha256sums
from scripts.verify_release_version import verify_release_version

ROOT = Path(__file__).resolve().parents[1]


class ReleaseAssetTests(unittest.TestCase):
    def test_writes_stable_sha256_manifest_for_dist_files(self) -> None:
        with TemporaryDirectory() as temp_dir:
            dist = Path(temp_dir)
            wheel = dist / "linwarden-0.13.0-py3-none-any.whl"
            sdist = dist / "linwarden-0.13.0.tar.gz"
            wheel.write_bytes(b"wheel")
            sdist.write_bytes(b"sdist")

            manifest = write_sha256sums(dist)

            self.assertEqual(manifest, dist / "SHA256SUMS")
            self.assertEqual(
                manifest.read_text(encoding="utf-8"),
                "\n".join(
                    [
                        f"{hashlib.sha256(wheel.read_bytes()).hexdigest()}  {wheel.name}",
                        f"{hashlib.sha256(sdist.read_bytes()).hexdigest()}  {sdist.name}",
                        "",
                    ]
                ),
            )

    def test_source_distribution_excludes_local_checkpoints(self) -> None:
        manifest = (ROOT / "MANIFEST.in").read_text(encoding="utf-8")

        self.assertIn("recursive-exclude docs/checkpoints *", manifest)

    def test_verify_release_version_accepts_matching_tag_and_dist_files(self) -> None:
        with TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            dist = root / "dist"
            dist.mkdir()
            (root / "pyproject.toml").write_text(
                '[project]\nname = "linwarden"\nversion = "1.2.3"\n',
                encoding="utf-8",
            )
            (dist / "linwarden-1.2.3.tar.gz").write_bytes(b"sdist")
            (dist / "linwarden-1.2.3-py3-none-any.whl").write_bytes(b"wheel")

            verify_release_version(
                pyproject=root / "pyproject.toml",
                ref_name="v1.2.3",
                dist_dir=dist,
            )

    def test_verify_release_version_rejects_mismatched_tag(self) -> None:
        with TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            (root / "pyproject.toml").write_text(
                '[project]\nname = "linwarden"\nversion = "1.2.3"\n',
                encoding="utf-8",
            )

            with self.assertRaisesRegex(ValueError, "tag v1.2.4 does not match pyproject version 1.2.3"):
                verify_release_version(
                    pyproject=root / "pyproject.toml",
                    ref_name="v1.2.4",
                )

    def test_verify_release_version_rejects_mismatched_dist_files(self) -> None:
        with TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            dist = root / "dist"
            dist.mkdir()
            (root / "pyproject.toml").write_text(
                '[project]\nname = "linwarden"\nversion = "1.2.3"\n',
                encoding="utf-8",
            )
            (dist / "linwarden-1.2.4.tar.gz").write_bytes(b"sdist")

            with self.assertRaisesRegex(ValueError, "dist file linwarden-1.2.4.tar.gz does not match version 1.2.3"):
                verify_release_version(
                    pyproject=root / "pyproject.toml",
                    ref_name="v1.2.3",
                    dist_dir=dist,
                )


if __name__ == "__main__":
    unittest.main()
