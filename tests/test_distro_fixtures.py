import unittest
from pathlib import Path
from tempfile import TemporaryDirectory

from linwarden.collectors import collect_host_snapshot

FIXTURE_DIR = Path(__file__).parent / "fixtures"


class DistroFixtureTests(unittest.TestCase):
    def test_collects_minimal_supported_distro_roots_without_crashing(self) -> None:
        fixture_ids = {
            "debian-root": "debian",
            "fedora-root": "fedora",
            "arch-root": "arch",
            "alpine-root": "alpine",
        }

        for fixture_name, distro_id in fixture_ids.items():
            with self.subTest(fixture_name=fixture_name):
                root = FIXTURE_DIR / fixture_name
                snapshot = collect_host_snapshot(root=root, proc_root=root / "proc", etc_root=root / "etc")

                self.assertEqual(snapshot.os_release["ID"], distro_id)
                self.assertGreaterEqual(snapshot.memory.total_mib, 0)
                self.assertIn(snapshot.package_status.manager, {"apk", "apt", "dnf", "pacman", "unknown"})

    def test_package_manager_detection_uses_id_like(self) -> None:
        with TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            etc = root / "etc"
            etc.mkdir()
            (etc / "os-release").write_text(
                'ID="linuxmint"\nID_LIKE="ubuntu debian"\n',
                encoding="utf-8",
            )

            snapshot = collect_host_snapshot(root=root, proc_root=root / "proc", etc_root=etc)

        self.assertEqual(snapshot.package_status.manager, "apt")


if __name__ == "__main__":
    unittest.main()
