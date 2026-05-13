import unittest
from dataclasses import replace
from pathlib import Path
from tempfile import TemporaryDirectory

from linwarden.collectors import collect_host_snapshot
from linwarden.rules import evaluate_snapshot, summarize_findings

FIXTURE_ROOT = Path(__file__).parent / "fixtures" / "linux-root"


class RuleTests(unittest.TestCase):
    def test_evaluates_security_findings_with_actionable_metadata(self) -> None:
        snapshot = collect_host_snapshot(
            root=FIXTURE_ROOT,
            proc_root=FIXTURE_ROOT / "proc",
            etc_root=FIXTURE_ROOT / "etc",
        )

        findings = evaluate_snapshot(snapshot)
        by_rule = {finding.rule_id: finding for finding in findings}

        self.assertEqual(by_rule["LNX-SSH-001"].severity, "high")
        self.assertIn("PermitRootLogin", by_rule["LNX-SSH-001"].evidence)
        self.assertIn("no", by_rule["LNX-SSH-001"].remediation)
        self.assertEqual(by_rule["LNX-SSH-003"].severity, "high")
        self.assertEqual(by_rule["LNX-SSH-004"].severity, "medium")
        self.assertIn("MaxAuthTries 6", by_rule["LNX-SSH-004"].evidence)
        self.assertEqual(by_rule["LNX-SSH-005"].severity, "medium")
        self.assertIn("AllowTcpForwarding yes", by_rule["LNX-SSH-005"].evidence)
        self.assertEqual(by_rule["LNX-KRN-001"].severity, "high")
        self.assertEqual(by_rule["LNX-NET-001"].severity, "medium")
        self.assertEqual(by_rule["LNX-NET-002"].severity, "low")
        self.assertEqual(by_rule["LNX-NET-003"].severity, "medium")
        self.assertEqual(by_rule["LNX-NET-004"].severity, "low")
        self.assertEqual(by_rule["LNX-FS-001"].severity, "high")
        self.assertEqual(by_rule["LNX-FS-002"].severity, "high")
        self.assertEqual(by_rule["LNX-KRN-003"].severity, "medium")
        self.assertEqual(by_rule["LNX-PKG-001"].severity, "medium")
        self.assertEqual(by_rule["LNX-PKG-002"].severity, "high")
        self.assertEqual(by_rule["LNX-FW-001"].severity, "medium")

    def test_summarizes_findings_into_score_and_counts(self) -> None:
        snapshot = collect_host_snapshot(
            root=FIXTURE_ROOT,
            proc_root=FIXTURE_ROOT / "proc",
            etc_root=FIXTURE_ROOT / "etc",
        )
        summary = summarize_findings(evaluate_snapshot(snapshot))

        self.assertEqual(summary.total, 17)
        self.assertEqual(summary.by_severity["high"], 7)
        self.assertEqual(summary.by_severity["medium"], 8)
        self.assertEqual(summary.by_severity["low"], 2)
        self.assertEqual(summary.score, 0)

    def test_flags_allow_tcp_forwarding_all_as_broad_forwarding(self) -> None:
        snapshot = collect_host_snapshot(
            root=FIXTURE_ROOT,
            proc_root=FIXTURE_ROOT / "proc",
            etc_root=FIXTURE_ROOT / "etc",
        )
        snapshot = replace(snapshot, sshd_options={"allowtcpforwarding": "all"})
        by_rule = {finding.rule_id: finding for finding in evaluate_snapshot(snapshot)}

        self.assertIn("AllowTcpForwarding all", by_rule["LNX-SSH-005"].evidence)

    def test_flags_enabled_systemd_service_with_external_bind(self) -> None:
        with TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            etc = root / "etc"
            unit_dir = root / "usr" / "lib" / "systemd" / "system"
            wants_dir = etc / "systemd" / "system" / "multi-user.target.wants"
            unit_dir.mkdir(parents=True)
            wants_dir.mkdir(parents=True)
            (etc / "os-release").parent.mkdir(parents=True, exist_ok=True)
            (etc / "os-release").write_text('ID="debian"\n', encoding="utf-8")
            unit = unit_dir / "fixture-api.service"
            unit.write_text(
                "\n".join(
                    [
                        "[Service]",
                        "ExecStart=/usr/bin/python -m http.server --bind 0.0.0.0 8080",
                    ]
                ),
                encoding="utf-8",
            )
            (wants_dir / "fixture-api.service").symlink_to("/usr/lib/systemd/system/fixture-api.service")

            snapshot = collect_host_snapshot(root=root, proc_root=root / "proc", etc_root=etc)

        by_rule = {finding.rule_id: finding for finding in evaluate_snapshot(snapshot)}

        self.assertEqual(by_rule["LNX-SVC-001"].severity, "medium")
        self.assertIn("fixture-api.service", by_rule["LNX-SVC-001"].evidence)
        self.assertIn("0.0.0.0", by_rule["LNX-SVC-001"].evidence)
        self.assertIn("review", by_rule["LNX-SVC-001"].remediation.lower())

    def test_flags_bridge_netfilter_and_bridge_forwarding_posture(self) -> None:
        with TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            etc = root / "etc"
            proc = root / "proc"
            bridge = root / "sys" / "class" / "net" / "docker0"
            etc.mkdir(parents=True)
            (proc / "sys" / "net" / "bridge").mkdir(parents=True)
            (proc / "sys" / "net" / "ipv4" / "conf" / "docker0").mkdir(parents=True)
            (proc / "sys" / "net" / "ipv6" / "conf" / "docker0").mkdir(parents=True)
            (bridge / "bridge").mkdir(parents=True)
            (bridge / "brif" / "veth123").mkdir(parents=True)
            (etc / "os-release").write_text('ID="debian"\n', encoding="utf-8")
            (proc / "sys" / "net" / "bridge" / "bridge-nf-call-iptables").write_text("0\n", encoding="utf-8")
            (proc / "sys" / "net" / "bridge" / "bridge-nf-call-ip6tables").write_text("0\n", encoding="utf-8")
            (proc / "sys" / "net" / "ipv4" / "conf" / "docker0" / "forwarding").write_text("1\n", encoding="utf-8")
            (proc / "sys" / "net" / "ipv6" / "conf" / "docker0" / "forwarding").write_text("0\n", encoding="utf-8")

            snapshot = collect_host_snapshot(root=root, proc_root=proc, etc_root=etc)

        by_rule = {finding.rule_id: finding for finding in evaluate_snapshot(snapshot)}

        self.assertEqual(by_rule["LNX-NET-005"].severity, "medium")
        self.assertIn("bridge-nf-call-iptables=0", by_rule["LNX-NET-005"].evidence)
        self.assertEqual(by_rule["LNX-NET-006"].severity, "medium")
        self.assertIn("bridge-nf-call-ip6tables=0", by_rule["LNX-NET-006"].evidence)
        self.assertEqual(by_rule["LNX-NET-007"].severity, "medium")
        self.assertIn("docker0", by_rule["LNX-NET-007"].evidence)

    def test_ignores_bridge_netfilter_without_bridge_interfaces(self) -> None:
        with TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            etc = root / "etc"
            proc = root / "proc"
            etc.mkdir(parents=True)
            (proc / "sys" / "net" / "bridge").mkdir(parents=True)
            (etc / "os-release").write_text('ID="debian"\n', encoding="utf-8")
            (proc / "sys" / "net" / "bridge" / "bridge-nf-call-iptables").write_text("0\n", encoding="utf-8")

            snapshot = collect_host_snapshot(root=root, proc_root=proc, etc_root=etc)

        self.assertNotIn("LNX-NET-005", {finding.rule_id for finding in evaluate_snapshot(snapshot)})

    def test_flags_package_vulnerabilities_from_local_feed(self) -> None:
        feed = Path(__file__).parent / "fixtures" / "vulnerability-feed.json"
        snapshot = collect_host_snapshot(
            root=FIXTURE_ROOT,
            proc_root=FIXTURE_ROOT / "proc",
            etc_root=FIXTURE_ROOT / "etc",
            vulnerability_feed=feed,
        )

        findings = [finding for finding in evaluate_snapshot(snapshot) if finding.rule_id == "LNX-PKG-004"]

        self.assertEqual(len(findings), 2)
        self.assertEqual(findings[0].severity, "critical")
        self.assertIn("openssl", findings[0].evidence)
        self.assertIn("CVE-2026-0001", findings[0].evidence)
        self.assertIn("3.0.2-0ubuntu1.20", findings[0].remediation)


if __name__ == "__main__":
    unittest.main()
