import unittest
from pathlib import Path
from tempfile import TemporaryDirectory

from linwarden.collectors import collect_host_snapshot

FIXTURE_ROOT = Path(__file__).parent / "fixtures" / "linux-root"


class CollectorTests(unittest.TestCase):
    def test_collects_linux_snapshot_from_fixture_root(self) -> None:
        snapshot = collect_host_snapshot(
            root=FIXTURE_ROOT,
            proc_root=FIXTURE_ROOT / "proc",
            etc_root=FIXTURE_ROOT / "etc",
        )

        self.assertEqual(snapshot.hostname, "fixture-box")
        self.assertEqual(snapshot.os_release["ID"], "debian")
        self.assertEqual(snapshot.kernel_release, "6.8.7-fixture")
        self.assertEqual(snapshot.load_average.one_minute, 0.42)
        self.assertEqual(snapshot.memory.total_mib, 16000)
        self.assertEqual(snapshot.memory.available_mib, 8000)
        self.assertEqual(snapshot.sysctls["net.ipv4.ip_forward"], "1")
        self.assertEqual(snapshot.sysctls["net.ipv6.conf.all.forwarding"], "1")
        self.assertEqual(snapshot.sysctls["fs.protected_hardlinks"], "0")
        self.assertEqual(snapshot.sshd_options["permitrootlogin"], "yes")
        self.assertEqual(snapshot.sshd_options["x11forwarding"], "yes")
        self.assertEqual(snapshot.sshd_options["permitemptypasswords"], "yes")
        self.assertEqual(snapshot.sshd_source, "static")
        self.assertEqual(snapshot.package_status.manager, "apt")
        self.assertEqual(snapshot.package_status.updates_available, 12)
        self.assertEqual(snapshot.package_status.security_updates, 5)
        self.assertIsNone(snapshot.package_status.metadata_age_days)
        self.assertEqual(snapshot.package_status.metadata_source, "not found")
        self.assertEqual(snapshot.firewall_status.provider, "ufw")
        self.assertEqual(snapshot.firewall_status.enabled, False)
        self.assertEqual(snapshot.mounts[0].mount_point, "/")

    def test_can_collect_effective_sshd_config_with_explicit_binary(self) -> None:
        with TemporaryDirectory() as temp_dir:
            fake_sshd = Path(temp_dir) / "sshd"
            fake_sshd.write_text(
                "\n".join(
                    [
                        "#!/bin/sh",
                        "printf '%s\\n' 'permitrootlogin no' 'passwordauthentication no' 'permitemptypasswords no'",
                    ]
                ),
                encoding="utf-8",
            )
            fake_sshd.chmod(0o755)

            snapshot = collect_host_snapshot(
                root=FIXTURE_ROOT,
                proc_root=FIXTURE_ROOT / "proc",
                etc_root=FIXTURE_ROOT / "etc",
                sshd_mode="effective",
                sshd_binary=fake_sshd,
            )

        self.assertEqual(snapshot.sshd_source, "effective")
        self.assertEqual(snapshot.sshd_options["permitrootlogin"], "no")
        self.assertEqual(snapshot.sshd_options["passwordauthentication"], "no")

    def test_effective_sshd_config_accepts_match_context(self) -> None:
        with TemporaryDirectory() as temp_dir:
            temp_path = Path(temp_dir)
            fake_sshd = temp_path / "sshd"
            argv_log = temp_path / "argv.txt"
            fake_sshd.write_text(
                "\n".join(
                    [
                        "#!/bin/sh",
                        f"printf '%s\\n' \"$@\" > {argv_log}",
                        "printf '%s\\n' 'permitrootlogin no' 'passwordauthentication no'",
                    ]
                ),
                encoding="utf-8",
            )
            fake_sshd.chmod(0o755)

            snapshot = collect_host_snapshot(
                root=FIXTURE_ROOT,
                proc_root=FIXTURE_ROOT / "proc",
                etc_root=FIXTURE_ROOT / "etc",
                sshd_mode="effective",
                sshd_binary=fake_sshd,
                sshd_match_context=("user=admin", "addr=203.0.113.7"),
            )
            argv = argv_log.read_text(encoding="utf-8")

        self.assertEqual(snapshot.sshd_source, "effective")
        self.assertIn("-C\nuser=admin,addr=203.0.113.7", argv)

    def test_collects_firewalld_systemd_enablement_marker(self) -> None:
        with TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            etc = root / "etc"
            marker = etc / "systemd" / "system" / "multi-user.target.wants" / "firewalld.service"
            (etc / "firewalld").mkdir(parents=True)
            marker.parent.mkdir(parents=True)
            (etc / "os-release").write_text('ID="fedora"\n', encoding="utf-8")
            (etc / "firewalld" / "firewalld.conf").write_text("FirewallBackend=nftables\n", encoding="utf-8")
            marker.write_text("", encoding="utf-8")

            snapshot = collect_host_snapshot(root=root, proc_root=root / "proc", etc_root=etc)

        self.assertEqual(snapshot.firewall_status.provider, "firewalld")
        self.assertEqual(snapshot.firewall_status.enabled, True)
        self.assertEqual(snapshot.firewall_status.source, str(marker))

    def test_collects_nftables_config_without_claiming_service_state(self) -> None:
        with TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            etc = root / "etc"
            etc.mkdir()
            (etc / "os-release").write_text('ID="debian"\n', encoding="utf-8")
            (etc / "nftables.conf").write_text("table inet filter {}\n", encoding="utf-8")

            snapshot = collect_host_snapshot(root=root, proc_root=root / "proc", etc_root=etc)

        self.assertEqual(snapshot.firewall_status.provider, "nftables")
        self.assertIsNone(snapshot.firewall_status.enabled)
        self.assertEqual(snapshot.firewall_status.source, str(etc / "nftables.conf"))

    def test_collects_enabled_systemd_service_external_bind_exposure(self) -> None:
        with TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            etc = root / "etc"
            unit_dir = root / "usr" / "lib" / "systemd" / "system"
            wants_dir = etc / "systemd" / "system" / "multi-user.target.wants"
            unit_dir.mkdir(parents=True)
            wants_dir.mkdir(parents=True)
            (etc / "os-release").parent.mkdir(parents=True, exist_ok=True)
            (etc / "os-release").write_text('ID="debian"\n', encoding="utf-8")

            external_unit = unit_dir / "fixture-api.service"
            external_unit.write_text(
                "\n".join(
                    [
                        "[Service]",
                        "ExecStart=/usr/bin/python -m http.server --bind 0.0.0.0 8080",
                    ]
                ),
                encoding="utf-8",
            )
            (wants_dir / "fixture-api.service").symlink_to("/usr/lib/systemd/system/fixture-api.service")

            local_unit = unit_dir / "fixture-admin.service"
            local_unit.write_text(
                "\n".join(
                    [
                        "[Service]",
                        "ExecStart=/usr/bin/server --listen 127.0.0.1:9000",
                    ]
                ),
                encoding="utf-8",
            )
            (wants_dir / "fixture-admin.service").symlink_to("/usr/lib/systemd/system/fixture-admin.service")

            disabled_unit = unit_dir / "fixture-disabled.service"
            disabled_unit.write_text(
                "\n".join(
                    [
                        "[Service]",
                        "ExecStart=/usr/bin/server --listen 0.0.0.0:9001",
                    ]
                ),
                encoding="utf-8",
            )

            snapshot = collect_host_snapshot(root=root, proc_root=root / "proc", etc_root=etc)

        self.assertEqual(len(snapshot.systemd_service_exposures), 1)
        exposure = snapshot.systemd_service_exposures[0]
        self.assertEqual(exposure.name, "fixture-api.service")
        self.assertEqual(exposure.bind, "0.0.0.0")
        self.assertEqual(exposure.source, str(external_unit))
        self.assertEqual(exposure.enabled_source, str(wants_dir / "fixture-api.service"))
        self.assertIn("--bind 0.0.0.0", exposure.exec_start)


if __name__ == "__main__":
    unittest.main()
