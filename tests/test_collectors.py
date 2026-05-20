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

    def test_collects_bridge_interfaces_and_forwarding_posture(self) -> None:
        with TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            etc = root / "etc"
            proc = root / "proc"
            bridge = root / "sys" / "class" / "net" / "docker0"
            (etc).mkdir(parents=True)
            (proc / "sys" / "net" / "bridge").mkdir(parents=True)
            (proc / "sys" / "net" / "ipv4" / "conf" / "docker0").mkdir(parents=True)
            (proc / "sys" / "net" / "ipv6" / "conf" / "docker0").mkdir(parents=True)
            (bridge / "bridge").mkdir(parents=True)
            (bridge / "brif" / "veth123").mkdir(parents=True)
            (etc / "os-release").write_text('ID="debian"\n', encoding="utf-8")
            (proc / "sys" / "net" / "bridge" / "bridge-nf-call-iptables").write_text("0\n", encoding="utf-8")
            (proc / "sys" / "net" / "bridge" / "bridge-nf-call-ip6tables").write_text("1\n", encoding="utf-8")
            (proc / "sys" / "net" / "ipv4" / "conf" / "docker0" / "forwarding").write_text("1\n", encoding="utf-8")
            (proc / "sys" / "net" / "ipv6" / "conf" / "docker0" / "forwarding").write_text("0\n", encoding="utf-8")

            snapshot = collect_host_snapshot(root=root, proc_root=proc, etc_root=etc)

        self.assertEqual(snapshot.sysctls["net.bridge.bridge-nf-call-iptables"], "0")
        self.assertEqual(snapshot.sysctls["net.bridge.bridge-nf-call-ip6tables"], "1")
        self.assertEqual(len(snapshot.bridge_interfaces), 1)
        bridge_interface = snapshot.bridge_interfaces[0]
        self.assertEqual(bridge_interface.name, "docker0")
        self.assertEqual(bridge_interface.members, ("veth123",))
        self.assertEqual(bridge_interface.ipv4_forwarding, True)
        self.assertEqual(bridge_interface.ipv6_forwarding, False)
        self.assertEqual(bridge_interface.source, str(bridge / "bridge"))

    def test_collects_bridge_interfaces_from_explicit_sys_root(self) -> None:
        with TemporaryDirectory() as temp_dir:
            base = Path(temp_dir)
            root = base / "root"
            etc = base / "etc"
            proc = base / "proc"
            sys_root = base / "sys-root"
            bridge = sys_root / "class" / "net" / "br0"
            etc.mkdir(parents=True)
            (proc / "sys" / "net" / "ipv4" / "conf" / "br0").mkdir(parents=True)
            (bridge / "bridge").mkdir(parents=True)
            (etc / "os-release").write_text('ID="debian"\n', encoding="utf-8")
            (proc / "sys" / "net" / "ipv4" / "conf" / "br0" / "forwarding").write_text("1\n", encoding="utf-8")

            snapshot = collect_host_snapshot(root=root, proc_root=proc, etc_root=etc, sys_root=sys_root)

        self.assertEqual(len(snapshot.bridge_interfaces), 1)
        self.assertEqual(snapshot.bridge_interfaces[0].name, "br0")
        self.assertEqual(snapshot.bridge_interfaces[0].source, str(bridge / "bridge"))

    def test_collects_container_runtime_static_posture_signals(self) -> None:
        with TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            etc = root / "etc"
            docker_config = etc / "docker" / "daemon.json"
            docker_unit = etc / "systemd" / "system" / "multi-user.target.wants" / "docker.service"
            podman_unit = etc / "systemd" / "system" / "multi-user.target.wants" / "podman.service"
            podman_socket = etc / "systemd" / "system" / "sockets.target.wants" / "podman.socket"
            etc.mkdir(parents=True)
            docker_config.parent.mkdir(parents=True)
            docker_unit.parent.mkdir(parents=True)
            podman_socket.parent.mkdir(parents=True)
            (etc / "os-release").write_text('ID="debian"\n', encoding="utf-8")
            (etc / "group").write_text(
                "root:x:0:\n"
                "docker:x:998:deploy,ci-runner\n",
                encoding="utf-8",
            )
            docker_config.write_text(
                '{"hosts": ["unix:///var/run/docker.sock", "tcp://0.0.0.0:2375", "tcp://127.0.0.1:2376"]}\n',
                encoding="utf-8",
            )
            docker_unit.write_text(
                "[Service]\nExecStart=/usr/bin/dockerd --host tcp://192.0.2.10:2376\n",
                encoding="utf-8",
            )
            podman_unit.write_text(
                "[Service]\nExecStart=/usr/bin/podman system service tcp://[::]:8080\n",
                encoding="utf-8",
            )
            podman_socket.write_text(
                "[Socket]\nListenStream=0.0.0.0:8081\n",
                encoding="utf-8",
            )

            snapshot = collect_host_snapshot(root=root, proc_root=root / "proc", etc_root=etc)

        signals = snapshot.container_runtime_signals
        self.assertEqual(len(signals), 5)
        by_evidence = {signal.evidence: signal for signal in signals}
        self.assertEqual(by_evidence["tcp://0.0.0.0:2375"].runtime, "docker")
        self.assertEqual(by_evidence["tcp://0.0.0.0:2375"].signal, "tcp_api")
        self.assertEqual(by_evidence["tcp://192.0.2.10:2376"].source, str(docker_unit))
        self.assertEqual(by_evidence["tcp://[::]:8080"].runtime, "podman")
        self.assertEqual(by_evidence["tcp://0.0.0.0:8081"].source, str(podman_socket))
        self.assertEqual(by_evidence["docker group members: deploy, ci-runner"].signal, "docker_group_members")
        self.assertNotIn("tcp://127.0.0.1:2376", by_evidence)

    def test_collects_container_runtime_systemd_drop_in_exposure(self) -> None:
        with TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            etc = root / "etc"
            unit_dir = root / "usr" / "lib" / "systemd" / "system"
            wants_dir = etc / "systemd" / "system" / "multi-user.target.wants"
            drop_in_dir = etc / "systemd" / "system" / "docker.service.d"
            etc.mkdir(parents=True)
            unit_dir.mkdir(parents=True)
            wants_dir.mkdir(parents=True)
            drop_in_dir.mkdir(parents=True)
            (etc / "os-release").write_text('ID="debian"\n', encoding="utf-8")
            (unit_dir / "docker.service").write_text(
                "[Service]\nExecStart=/usr/bin/dockerd --host unix:///var/run/docker.sock\n",
                encoding="utf-8",
            )
            override = drop_in_dir / "override.conf"
            override.write_text(
                "[Service]\nExecStart=\nExecStart=/usr/bin/dockerd --host tcp://0.0.0.0:2375\n",
                encoding="utf-8",
            )
            (wants_dir / "docker.service").symlink_to("/usr/lib/systemd/system/docker.service")

            snapshot = collect_host_snapshot(root=root, proc_root=root / "proc", etc_root=etc)

        by_evidence = {signal.evidence: signal for signal in snapshot.container_runtime_signals}
        self.assertEqual(by_evidence["tcp://0.0.0.0:2375"].runtime, "docker")
        self.assertIn(str(override), by_evidence["tcp://0.0.0.0:2375"].source)

    def test_systemd_drop_in_exec_start_reset_avoids_stale_runtime_endpoint(self) -> None:
        with TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            etc = root / "etc"
            unit_dir = root / "usr" / "lib" / "systemd" / "system"
            wants_dir = etc / "systemd" / "system" / "multi-user.target.wants"
            drop_in_dir = etc / "systemd" / "system" / "docker.service.d"
            etc.mkdir(parents=True)
            unit_dir.mkdir(parents=True)
            wants_dir.mkdir(parents=True)
            drop_in_dir.mkdir(parents=True)
            (etc / "os-release").write_text('ID="debian"\n', encoding="utf-8")
            (unit_dir / "docker.service").write_text(
                "[Service]\nExecStart=/usr/bin/dockerd --host tcp://0.0.0.0:2375\n",
                encoding="utf-8",
            )
            (drop_in_dir / "override.conf").write_text(
                "[Service]\nExecStart=\nExecStart=/usr/bin/dockerd --host unix:///var/run/docker.sock\n",
                encoding="utf-8",
            )
            (wants_dir / "docker.service").symlink_to("/usr/lib/systemd/system/docker.service")

            snapshot = collect_host_snapshot(root=root, proc_root=root / "proc", etc_root=etc)

        self.assertEqual(snapshot.container_runtime_signals, ())

    def test_collects_package_vulnerabilities_from_local_feed(self) -> None:
        feed = Path(__file__).parent / "fixtures" / "vulnerability-feed.json"

        snapshot = collect_host_snapshot(
            root=FIXTURE_ROOT,
            proc_root=FIXTURE_ROOT / "proc",
            etc_root=FIXTURE_ROOT / "etc",
            vulnerability_feed=feed,
        )

        self.assertEqual(len(snapshot.package_vulnerabilities), 2)
        vulnerability = snapshot.package_vulnerabilities[0]
        self.assertEqual(vulnerability.package, "openssl")
        self.assertEqual(vulnerability.installed_version, "3.0.2-0ubuntu1")
        self.assertEqual(vulnerability.fixed_version, "3.0.2-0ubuntu1.20")
        self.assertEqual(vulnerability.vulnerability_id, "CVE-2026-0001")
        self.assertEqual(vulnerability.severity, "critical")
        self.assertEqual(vulnerability.source, str(feed))

    def test_collects_package_vulnerabilities_from_trivy_json_feed(self) -> None:
        feed = Path(__file__).parent / "fixtures" / "trivy-vulnerability-report.json"

        snapshot = collect_host_snapshot(
            root=FIXTURE_ROOT,
            proc_root=FIXTURE_ROOT / "proc",
            etc_root=FIXTURE_ROOT / "etc",
            vulnerability_feed=feed,
            vulnerability_feed_format="trivy",
        )

        self.assertEqual(len(snapshot.package_vulnerabilities), 2)
        first = snapshot.package_vulnerabilities[0]
        self.assertEqual(first.package, "openssl")
        self.assertEqual(first.installed_version, "3.0.2-0ubuntu1")
        self.assertEqual(first.fixed_version, "3.0.2-0ubuntu1.20")
        self.assertEqual(first.vulnerability_id, "CVE-2026-1001")
        self.assertEqual(first.severity, "critical")
        self.assertEqual(first.summary, "openssl: fixture critical vulnerability")
        self.assertEqual(first.url, "https://avd.aquasec.com/nvd/cve-2026-1001")
        self.assertIn("trivy-vulnerability-report.json#fixture-image:latest", first.source)

        second = snapshot.package_vulnerabilities[1]
        self.assertEqual(second.package, "curl")
        self.assertEqual(second.fixed_version, "")
        self.assertEqual(second.severity, "high")
        self.assertEqual(second.url, "https://example.invalid/CVE-2026-1002")

    def test_collects_package_vulnerabilities_from_grype_json_feed(self) -> None:
        feed = Path(__file__).parent / "fixtures" / "grype-vulnerability-report.json"

        snapshot = collect_host_snapshot(
            root=FIXTURE_ROOT,
            proc_root=FIXTURE_ROOT / "proc",
            etc_root=FIXTURE_ROOT / "etc",
            vulnerability_feed=feed,
            vulnerability_feed_format="grype",
        )

        self.assertEqual(len(snapshot.package_vulnerabilities), 2)
        first = snapshot.package_vulnerabilities[0]
        self.assertEqual(first.package, "openssl")
        self.assertEqual(first.installed_version, "3.0.2-0ubuntu1")
        self.assertEqual(first.fixed_version, "3.0.2-0ubuntu1.22")
        self.assertEqual(first.vulnerability_id, "CVE-2026-2001")
        self.assertEqual(first.severity, "critical")
        self.assertEqual(first.summary, "Fixture OpenSSL vulnerability from Grype")
        self.assertEqual(first.url, "https://nvd.nist.gov/vuln/detail/CVE-2026-2001")
        self.assertIn("grype-vulnerability-report.json#fixture-image:latest", first.source)

        second = snapshot.package_vulnerabilities[1]
        self.assertEqual(second.package, "curl")
        self.assertEqual(second.fixed_version, "")
        self.assertEqual(second.severity, "high")
        self.assertEqual(second.url, "https://example.invalid/GHSA-2026-2002")
        self.assertNotIn(
            "CVE-2026-IGNORED",
            {vulnerability.vulnerability_id for vulnerability in snapshot.package_vulnerabilities},
        )

    def test_collects_package_vulnerabilities_from_osv_json_feed(self) -> None:
        feed = Path(__file__).parent / "fixtures" / "osv-vulnerability-report.json"

        snapshot = collect_host_snapshot(
            root=FIXTURE_ROOT,
            proc_root=FIXTURE_ROOT / "proc",
            etc_root=FIXTURE_ROOT / "etc",
            vulnerability_feed=feed,
            vulnerability_feed_format="osv",
        )

        self.assertEqual(len(snapshot.package_vulnerabilities), 2)
        first = snapshot.package_vulnerabilities[0]
        self.assertEqual(first.package, "openssl")
        self.assertEqual(first.installed_version, "3.0.2-0ubuntu1")
        self.assertEqual(first.fixed_version, "3.0.2-0ubuntu1.24")
        self.assertEqual(first.vulnerability_id, "GHSA-2026-3001")
        self.assertEqual(first.severity, "critical")
        self.assertEqual(first.summary, "Fixture OpenSSL vulnerability from OSV")
        self.assertEqual(first.url, "https://osv.dev/vulnerability/GHSA-2026-3001")
        self.assertIn("osv-vulnerability-report.json#/workspace/package-lock.json", first.source)

        second = snapshot.package_vulnerabilities[1]
        self.assertEqual(second.package, "curl")
        self.assertEqual(second.fixed_version, "")
        self.assertEqual(second.severity, "high")
        self.assertEqual(second.url, "https://example.invalid/CVE-2026-3002")
        self.assertNotIn(
            "OSV-2026-ALIAS",
            {vulnerability.vulnerability_id for vulnerability in snapshot.package_vulnerabilities},
        )

    def test_rejects_invalid_package_vulnerability_feed(self) -> None:
        feed = Path(__file__).parent / "fixtures" / "invalid-vulnerability-feed.json"

        with self.assertRaisesRegex(ValueError, "vulnerability feed"):
            collect_host_snapshot(
                root=FIXTURE_ROOT,
                proc_root=FIXTURE_ROOT / "proc",
                etc_root=FIXTURE_ROOT / "etc",
                vulnerability_feed=feed,
            )


if __name__ == "__main__":
    unittest.main()
