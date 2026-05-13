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


if __name__ == "__main__":
    unittest.main()
