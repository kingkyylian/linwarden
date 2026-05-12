from pathlib import Path
import unittest

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
        self.assertEqual(by_rule["LNX-KRN-001"].severity, "high")
        self.assertEqual(by_rule["LNX-NET-001"].severity, "medium")
        self.assertEqual(by_rule["LNX-NET-002"].severity, "low")

    def test_summarizes_findings_into_score_and_counts(self) -> None:
        snapshot = collect_host_snapshot(
            root=FIXTURE_ROOT,
            proc_root=FIXTURE_ROOT / "proc",
            etc_root=FIXTURE_ROOT / "etc",
        )
        summary = summarize_findings(evaluate_snapshot(snapshot))

        self.assertEqual(summary.total, 6)
        self.assertEqual(summary.by_severity["high"], 3)
        self.assertEqual(summary.by_severity["medium"], 2)
        self.assertEqual(summary.by_severity["low"], 1)
        self.assertEqual(summary.score, 17)


if __name__ == "__main__":
    unittest.main()
