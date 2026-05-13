import hashlib
import unittest
from pathlib import Path
from tempfile import TemporaryDirectory

from scripts.release_assets import write_sha256sums

ROOT = Path(__file__).resolve().parents[1]


class ReleaseAssetTests(unittest.TestCase):
    def test_writes_stable_sha256_manifest_for_dist_files(self) -> None:
        with TemporaryDirectory() as temp_dir:
            dist = Path(temp_dir)
            wheel = dist / "linwarden-0.11.0-py3-none-any.whl"
            sdist = dist / "linwarden-0.11.0.tar.gz"
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


if __name__ == "__main__":
    unittest.main()
