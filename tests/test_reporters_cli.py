import json
import unittest
from io import StringIO
from pathlib import Path
from tempfile import TemporaryDirectory

from linwarden.cli import main
from linwarden.collectors import collect_host_snapshot
from linwarden.config import apply_config, load_config
from linwarden.reporters import render_json, render_markdown, render_sarif
from linwarden.rules import evaluate_snapshot

FIXTURE_ROOT = Path(__file__).parent / "fixtures" / "linux-root"
FIXTURE_CONFIG = Path(__file__).parent / "fixtures" / "linwarden.json"


class ReporterAndCliTests(unittest.TestCase):
    def test_renders_json_report_with_stable_schema(self) -> None:
        snapshot = collect_host_snapshot(
            root=FIXTURE_ROOT,
            proc_root=FIXTURE_ROOT / "proc",
            etc_root=FIXTURE_ROOT / "etc",
        )
        payload = json.loads(render_json(snapshot, evaluate_snapshot(snapshot)))

        self.assertEqual(payload["schema_version"], "1.6")
        self.assertEqual(payload["host"]["hostname"], "fixture-box")
        self.assertEqual(payload["host"]["sshd_match_context"], [])
        self.assertEqual(payload["host"]["package_status"]["metadata_source"], "not found")
        self.assertEqual(payload["host"]["bridge_interfaces"], [])
        self.assertEqual(payload["host"]["package_vulnerabilities"], [])
        self.assertEqual(payload["host"]["systemd_service_exposures"], [])
        self.assertEqual(payload["summary"]["score"], 0)
        self.assertEqual(payload["findings"][0]["rule_id"], "LNX-SSH-001")
        self.assertEqual(payload["suppressed_findings"], [])

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

    def test_renders_sarif_report_for_github_code_scanning(self) -> None:
        snapshot = collect_host_snapshot(
            root=FIXTURE_ROOT,
            proc_root=FIXTURE_ROOT / "proc",
            etc_root=FIXTURE_ROOT / "etc",
        )
        payload = json.loads(render_sarif(snapshot, evaluate_snapshot(snapshot)))

        self.assertEqual(payload["version"], "2.1.0")
        self.assertEqual(payload["runs"][0]["tool"]["driver"]["name"], "Linwarden")
        self.assertEqual(payload["runs"][0]["results"][0]["ruleId"], "LNX-SSH-001")
        self.assertEqual(payload["runs"][0]["results"][0]["level"], "error")
        self.assertEqual(
            payload["runs"][0]["results"][0]["locations"][0]["physicalLocation"]["artifactLocation"]["uri"],
            "docs/rules.md",
        )

    def test_renders_configured_suppressions_transparently(self) -> None:
        snapshot = collect_host_snapshot(
            root=FIXTURE_ROOT,
            proc_root=FIXTURE_ROOT / "proc",
            etc_root=FIXTURE_ROOT / "etc",
        )
        result = apply_config(evaluate_snapshot(snapshot), load_config(FIXTURE_CONFIG))
        payload = json.loads(
            render_json(
                snapshot,
                result.active_findings,
                suppressed_findings=result.suppressed_findings,
            )
        )

        self.assertNotIn("LNX-SSH-002", {finding["rule_id"] for finding in payload["findings"]})
        self.assertIn("LNX-SSH-002", {finding["rule_id"] for finding in payload["suppressed_findings"]})
        self.assertEqual(payload["summary"]["total"], 13)

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
        self.assertEqual(json.loads(out.getvalue())["summary"]["by_severity"]["high"], 7)

    def test_cli_lists_profile_catalog_as_json(self) -> None:
        out = StringIO()
        err = StringIO()

        exit_code = main(["profiles", "--format", "json"], stdout=out, stderr=err)

        payload = json.loads(out.getvalue())
        profiles = {profile["name"]: profile for profile in payload["profiles"]}
        self.assertEqual(exit_code, 0)
        self.assertEqual(err.getvalue(), "")
        self.assertIn("server", profiles)
        self.assertIn("workstation", profiles)
        self.assertIn("router", profiles)
        self.assertIn("container", profiles)
        self.assertEqual(profiles["server"]["suppressed_rules"], [])
        self.assertIn(
            "LNX-NET-007",
            {rule["rule_id"] for rule in profiles["router"]["suppressed_rules"]},
        )
        self.assertIn(
            "LNX-KRN-002",
            {rule["rule_id"] for rule in profiles["container"]["suppressed_rules"]},
        )
        self.assertIn("routes traffic", profiles["router"]["description"])

    def test_cli_can_use_effective_sshd_config(self) -> None:
        with TemporaryDirectory() as temp_dir:
            fake_sshd = Path(temp_dir) / "sshd"
            fake_sshd.write_text(
                "\n".join(
                    [
                        "#!/bin/sh",
                        (
                            "printf '%s\\n' 'permitrootlogin no' 'passwordauthentication no' "
                            "'permitemptypasswords no' 'maxauthtries 6' 'allowtcpforwarding yes'"
                        ),
                    ]
                ),
                encoding="utf-8",
            )
            fake_sshd.chmod(0o755)
            out = StringIO()
            err = StringIO()

            exit_code = main(
                [
                    "scan",
                    "--root",
                    str(FIXTURE_ROOT),
                    "--sshd-mode",
                    "effective",
                    "--sshd-binary",
                    str(fake_sshd),
                    "--sshd-match",
                    "user=deploy",
                    "--sshd-match",
                    "addr=198.51.100.4",
                    "--format",
                    "json",
                    "--fail-on",
                    "critical",
                ],
                stdout=out,
                stderr=err,
            )

        payload = json.loads(out.getvalue())
        self.assertEqual(exit_code, 0)
        self.assertEqual(err.getvalue(), "")
        self.assertEqual(payload["host"]["sshd_source"], "effective")
        self.assertEqual(payload["host"]["sshd_match_context"], ["user=deploy", "addr=198.51.100.4"])
        self.assertNotIn("LNX-SSH-001", {finding["rule_id"] for finding in payload["findings"]})
        self.assertIn("LNX-SSH-004", {finding["rule_id"] for finding in payload["findings"]})
        self.assertIn("LNX-SSH-005", {finding["rule_id"] for finding in payload["findings"]})

    def test_cli_accepts_local_package_vulnerability_feed(self) -> None:
        out = StringIO()
        err = StringIO()
        feed = Path(__file__).parent / "fixtures" / "vulnerability-feed.json"

        exit_code = main(
            [
                "scan",
                "--root",
                str(FIXTURE_ROOT),
                "--vulnerability-feed",
                str(feed),
                "--format",
                "json",
                "--fail-on",
                "critical",
            ],
            stdout=out,
            stderr=err,
        )

        payload = json.loads(out.getvalue())
        self.assertEqual(exit_code, 2)
        self.assertEqual(err.getvalue(), "")
        self.assertEqual(len(payload["host"]["package_vulnerabilities"]), 2)
        self.assertIn("LNX-PKG-004", {finding["rule_id"] for finding in payload["findings"]})

    def test_cli_accepts_trivy_package_vulnerability_feed(self) -> None:
        out = StringIO()
        err = StringIO()
        feed = Path(__file__).parent / "fixtures" / "trivy-vulnerability-report.json"

        exit_code = main(
            [
                "scan",
                "--root",
                str(FIXTURE_ROOT),
                "--vulnerability-feed",
                str(feed),
                "--vulnerability-feed-format",
                "trivy",
                "--format",
                "json",
                "--fail-on",
                "critical",
            ],
            stdout=out,
            stderr=err,
        )

        payload = json.loads(out.getvalue())
        self.assertEqual(exit_code, 2)
        self.assertEqual(err.getvalue(), "")
        self.assertEqual(len(payload["host"]["package_vulnerabilities"]), 2)
        self.assertIn(
            "CVE-2026-1001",
            {finding["vulnerability_id"] for finding in payload["host"]["package_vulnerabilities"]},
        )
        self.assertIn("LNX-PKG-004", {finding["rule_id"] for finding in payload["findings"]})

    def test_cli_accepts_grype_package_vulnerability_feed(self) -> None:
        out = StringIO()
        err = StringIO()
        feed = Path(__file__).parent / "fixtures" / "grype-vulnerability-report.json"

        exit_code = main(
            [
                "scan",
                "--root",
                str(FIXTURE_ROOT),
                "--vulnerability-feed",
                str(feed),
                "--vulnerability-feed-format",
                "grype",
                "--format",
                "json",
                "--fail-on",
                "critical",
            ],
            stdout=out,
            stderr=err,
        )

        payload = json.loads(out.getvalue())
        self.assertEqual(exit_code, 2)
        self.assertEqual(err.getvalue(), "")
        self.assertEqual(len(payload["host"]["package_vulnerabilities"]), 2)
        self.assertIn(
            "CVE-2026-2001",
            {finding["vulnerability_id"] for finding in payload["host"]["package_vulnerabilities"]},
        )
        self.assertNotIn(
            "CVE-2026-IGNORED",
            {finding["vulnerability_id"] for finding in payload["host"]["package_vulnerabilities"]},
        )

    def test_cli_accepts_osv_package_vulnerability_feed(self) -> None:
        out = StringIO()
        err = StringIO()
        feed = Path(__file__).parent / "fixtures" / "osv-vulnerability-report.json"

        exit_code = main(
            [
                "scan",
                "--root",
                str(FIXTURE_ROOT),
                "--vulnerability-feed",
                str(feed),
                "--vulnerability-feed-format",
                "osv",
                "--format",
                "json",
                "--fail-on",
                "critical",
            ],
            stdout=out,
            stderr=err,
        )

        payload = json.loads(out.getvalue())
        self.assertEqual(exit_code, 2)
        self.assertEqual(err.getvalue(), "")
        self.assertEqual(len(payload["host"]["package_vulnerabilities"]), 2)
        self.assertIn(
            "GHSA-2026-3001",
            {finding["vulnerability_id"] for finding in payload["host"]["package_vulnerabilities"]},
        )
        self.assertIn("LNX-PKG-004", {finding["rule_id"] for finding in payload["findings"]})

    def test_cli_rejects_invalid_local_package_vulnerability_feed(self) -> None:
        out = StringIO()
        err = StringIO()
        feed = Path(__file__).parent / "fixtures" / "invalid-vulnerability-feed.json"

        exit_code = main(
            [
                "scan",
                "--root",
                str(FIXTURE_ROOT),
                "--vulnerability-feed",
                str(feed),
                "--format",
                "json",
            ],
            stdout=out,
            stderr=err,
        )

        self.assertEqual(exit_code, 1)
        self.assertEqual(out.getvalue(), "")
        self.assertIn("vulnerability feed", err.getvalue())

    def test_cli_applies_config_and_outputs_sarif(self) -> None:
        out = StringIO()
        err = StringIO()

        exit_code = main(
            [
                "scan",
                "--root",
                str(FIXTURE_ROOT),
                "--config",
                str(FIXTURE_CONFIG),
                "--format",
                "sarif",
                "--fail-on",
                "critical",
            ],
            stdout=out,
            stderr=err,
        )

        payload = json.loads(out.getvalue())
        self.assertEqual(exit_code, 0)
        self.assertEqual(err.getvalue(), "")
        self.assertEqual(payload["runs"][0]["results"][0]["ruleId"], "LNX-SSH-001")
        self.assertNotIn(
            "LNX-SSH-002",
            {result["ruleId"] for result in payload["runs"][0]["results"]},
        )

    def test_vulnerability_feed_contract_is_documented(self) -> None:
        text = Path("docs/package-vulnerability-feed.md").read_text(encoding="utf-8")

        self.assertIn('"version": 1', text)
        self.assertIn('"vulnerabilities"', text)
        self.assertIn("--vulnerability-feed", text)
        self.assertIn("--vulnerability-feed-format trivy", text)
        self.assertIn("--vulnerability-feed-format grype", text)
        self.assertIn("--vulnerability-feed-format osv", text)
        self.assertIn("OSV Scanner JSON Mapping", text)


if __name__ == "__main__":
    unittest.main()
