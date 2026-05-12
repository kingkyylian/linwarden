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


if __name__ == "__main__":
    unittest.main()
