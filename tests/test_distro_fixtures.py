import os
import time
import unittest
from pathlib import Path
from tempfile import TemporaryDirectory

from linwarden.collectors import collect_host_snapshot
from linwarden.rules import evaluate_snapshot

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

    def test_flags_stale_package_metadata(self) -> None:
        with TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            etc = root / "etc"
            stamp = root / "var" / "lib" / "apt" / "periodic" / "update-success-stamp"
            etc.mkdir()
            stamp.parent.mkdir(parents=True)
            (etc / "os-release").write_text('ID="debian"\n', encoding="utf-8")
            stamp.write_text("", encoding="utf-8")
            old_timestamp = time.time() - (30 * 86400)
            os.utime(stamp, (old_timestamp, old_timestamp))

            snapshot = collect_host_snapshot(root=root, proc_root=root / "proc", etc_root=etc)
            findings = {finding.rule_id: finding for finding in evaluate_snapshot(snapshot)}

        self.assertGreaterEqual(snapshot.package_status.metadata_age_days or 0, 29)
        self.assertEqual(snapshot.package_status.metadata_source, str(stamp))
        self.assertEqual(findings["LNX-PKG-003"].severity, "medium")

    def test_fedora_fixture_covers_firewalld_and_dnf_metadata(self) -> None:
        root = FIXTURE_DIR / "fedora-root"
        snapshot = collect_host_snapshot(root=root, proc_root=root / "proc", etc_root=root / "etc")

        self.assertEqual(snapshot.package_status.manager, "dnf")
        self.assertIsNotNone(snapshot.package_status.metadata_age_days)
        self.assertIn("var/cache/dnf", snapshot.package_status.metadata_source)
        self.assertEqual(snapshot.firewall_status.provider, "firewalld")
        self.assertEqual(snapshot.firewall_status.enabled, True)
        self.assertIn("firewalld.service", snapshot.firewall_status.source)

    def test_arch_fixture_covers_pacman_metadata(self) -> None:
        root = FIXTURE_DIR / "arch-root"
        snapshot = collect_host_snapshot(root=root, proc_root=root / "proc", etc_root=root / "etc")

        self.assertEqual(snapshot.package_status.manager, "pacman")
        self.assertIsNotNone(snapshot.package_status.metadata_age_days)
        self.assertTrue(snapshot.package_status.metadata_source.endswith(".db"))


if __name__ == "__main__":
    unittest.main()
