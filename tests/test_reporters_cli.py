from io import StringIO
from pathlib import Path
import json
import unittest

from linwarden.cli import main
from linwarden.collectors import collect_host_snapshot
from linwarden.reporters import render_json, render_markdown
from linwarden.rules import evaluate_snapshot


FIXTURE_ROOT = Path(__file__).parent / "fixtures" / "linux-root"


class ReporterAndCliTests(unittest.TestCase):
    def test_renders_json_report_with_stable_schema(self) -> None:
        snapshot = collect_host_snapshot(
            root=FIXTURE_ROOT,
            proc_root=FIXTURE_ROOT / "proc",
            etc_root=FIXTURE_ROOT / "etc",
        )
        payload = json.loads(render_json(snapshot, evaluate_snapshot(snapshot)))

        self.assertEqual(payload["host"]["hostname"], "fixture-box")
        self.assertEqual(payload["summary"]["score"], 17)
        self.assertEqual(payload["findings"][0]["rule_id"], "LNX-SSH-001")

    def test_renders_markdown_report_for_github_artifacts(self) -> None:
        snapshot = collect_host_snapshot(
            root=FIXTURE_ROOT,
            proc_root=FIXTURE_ROOT / "proc",
            etc_root=FIXTURE_ROOT / "etc",
        )
        report = render_markdown(snapshot, evaluate_snapshot(snapshot))

        self.assertIn("# Linwarden Report", report)
        self.assertIn("| Severity | Rule | Title | Evidence |", report)
        self.assertIn("LNX-SSH-001", report)

    def test_cli_returns_failure_code_when_threshold_is_met(self) -> None:
        out = StringIO()
        err = StringIO()

        exit_code = main(
            [
                "scan",
                "--root",
                str(FIXTURE_ROOT),
                "--format",
                "json",
                "--fail-on",
                "high",
            ],
            stdout=out,
            stderr=err,
        )

        self.assertEqual(exit_code, 2)
        self.assertEqual(err.getvalue(), "")
        self.assertEqual(json.loads(out.getvalue())["summary"]["by_severity"]["high"], 3)


if __name__ == "__main__":
    unittest.main()
