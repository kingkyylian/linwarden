import os
import time
import unittest
from pathlib import Path
from tempfile import TemporaryDirectory

from linwarden.collectors import collect_host_snapshot
from linwarden.rules import evaluate_snapshot

FIXTURE_DIR = Path(__file__).parent / "fixtures"


class DistroFixtureTests(unittest.TestCase):
    def test_collects_realistic_supported_distro_roots(self) -> None:
        fixture_expectations = {
            "debian-root": {
                "distro_id": "debian",
                "hostname": "debian-fixture",
                "manager": "apt",
                "metadata_source": "var/lib/apt/periodic/update-success-stamp",
                "firewall": ("ufw", False),
                "systemd_marker": "etc/systemd/system/multi-user.target.wants/fixture-local.service",
                "service_exposures": 0,
                "rules": {"LNX-SSH-002", "LNX-PKG-001", "LNX-PKG-002", "LNX-FW-001"},
            },
            "fedora-root": {
                "distro_id": "fedora",
                "hostname": "fedora-fixture",
                "manager": "dnf",
                "metadata_source": "var/cache/dnf",
                "firewall": ("firewalld", True),
                "systemd_marker": "etc/systemd/system/multi-user.target.wants/fixture-api.service",
                "service_exposures": 1,
                "rules": {"LNX-SSH-004", "LNX-SVC-001"},
            },
            "arch-root": {
                "distro_id": "arch",
                "hostname": "arch-fixture",
                "manager": "pacman",
                "metadata_source": "var/lib/pacman/sync",
                "firewall": ("nftables", True),
                "systemd_marker": "etc/systemd/system/multi-user.target.wants/nftables.service",
                "service_exposures": 0,
                "rules": {"LNX-SSH-005", "LNX-NET-002"},
            },
            "alpine-root": {
                "distro_id": "alpine",
                "hostname": "alpine-fixture",
                "manager": "apk",
                "metadata_source": "var/cache/apk/APKINDEX",
                "firewall": ("nftables", None),
                "systemd_marker": "",
                "service_exposures": 0,
                "rules": {"LNX-KRN-002", "LNX-NET-004"},
            },
        }

        for fixture_name, expected in fixture_expectations.items():
            with self.subTest(fixture_name=fixture_name):
                root = FIXTURE_DIR / fixture_name
                snapshot = collect_host_snapshot(root=root, proc_root=root / "proc", etc_root=root / "etc")
                findings = {finding.rule_id for finding in evaluate_snapshot(snapshot)}

                self.assertEqual(snapshot.os_release["ID"], expected["distro_id"])
                self.assertEqual(snapshot.hostname, expected["hostname"])
                self.assertIn("fixture", snapshot.kernel_release)
                self.assertGreater(snapshot.memory.total_mib, 0)
                self.assertGreater(snapshot.load_average.one_minute, 0)
                self.assertGreater(len(snapshot.mounts), 0)
                self.assertIn("kernel.randomize_va_space", snapshot.sysctls)
                self.assertIn("maxauthtries", snapshot.sshd_options)
                self.assertEqual(snapshot.package_status.manager, expected["manager"])
                self.assertIsNotNone(snapshot.package_status.metadata_age_days)
                self.assertIn(expected["metadata_source"], snapshot.package_status.metadata_source)
                self.assertEqual(
                    (snapshot.firewall_status.provider, snapshot.firewall_status.enabled),
                    expected["firewall"],
                )
                if expected["systemd_marker"]:
                    self.assertTrue((root / expected["systemd_marker"]).exists())
                self.assertEqual(len(snapshot.systemd_service_exposures), expected["service_exposures"])
                self.assertTrue(expected["rules"].issubset(findings))

    def test_fixture_origin_and_sanitization_are_documented(self) -> None:
        text = (Path(__file__).resolve().parents[1] / "docs" / "fixture-roots.md").read_text(encoding="utf-8")

        for fixture_name in ("debian-root", "fedora-root", "arch-root", "alpine-root"):
            with self.subTest(fixture_name=fixture_name):
                self.assertIn(f"`tests/fixtures/{fixture_name}`", text)
                self.assertIn("sanitized", text.lower())
                self.assertIn("synthetic", text.lower())

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
