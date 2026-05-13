import unittest
from pathlib import Path

ACTION = Path(__file__).resolve().parents[1] / "action.yml"
DOCS = Path(__file__).resolve().parents[1] / "docs" / "github-actions.md"
CI_WORKFLOW = Path(__file__).resolve().parents[1] / ".github" / "workflows" / "ci.yml"
RELEASE_WORKFLOW = Path(__file__).resolve().parents[1] / ".github" / "workflows" / "release.yml"
RELEASE_DOCS = Path(__file__).resolve().parents[1] / "docs" / "release.md"


class ActionMetadataTests(unittest.TestCase):
    def test_composite_action_wraps_linwarden_scan(self) -> None:
        text = ACTION.read_text(encoding="utf-8")

        self.assertIn("name: Linwarden", text)
        self.assertIn("using: composite", text)
        self.assertIn("python -m pip install \"$GITHUB_ACTION_PATH\"", text)
        self.assertIn("linwarden \"${args[@]}\"", text)
        self.assertIn("exit-code", text)
        self.assertIn("github/codeql-action/upload-sarif@v4", text)
        self.assertIn("cat \"$report_path\" >> \"$GITHUB_STEP_SUMMARY\"", text)

    def test_action_inputs_cover_scan_options(self) -> None:
        text = ACTION.read_text(encoding="utf-8")

        for input_name in (
            "root",
            "format",
            "output",
            "fail-on",
            "config",
            "sshd-mode",
            "sshd-binary",
            "sshd-match",
            "upload-sarif",
            "add-summary",
        ):
            self.assertIn(f"  {input_name}:", text)

    def test_github_actions_docs_use_the_composite_action(self) -> None:
        text = DOCS.read_text(encoding="utf-8")

        self.assertIn("uses: kingkyylian/linwarden@v0.10.1", text)
        self.assertIn("upload-sarif: \"true\"", text)
        self.assertIn("add-summary: \"true\"", text)

    def test_github_actions_docs_cover_unpacked_container_roots(self) -> None:
        text = DOCS.read_text(encoding="utf-8")

        self.assertIn("## Unpacked Container Root", text)
        self.assertIn("docker export", text)
        self.assertIn("tar -xf", text)
        self.assertIn("root: container-root", text)

    def test_action_uses_safe_output_expression_syntax(self) -> None:
        text = ACTION.read_text(encoding="utf-8")

        self.assertIn("steps.scan.outputs['report-path']", text)
        self.assertIn("steps.scan.outputs['exit-code']", text)
        self.assertNotIn("steps.scan.outputs.report-path", text)
        self.assertNotIn("steps.scan.outputs.exit-code", text)

    def test_description_values_with_colons_are_quoted(self) -> None:
        for line in ACTION.read_text(encoding="utf-8").splitlines():
            stripped = line.strip()
            if not stripped.startswith("description: "):
                continue

            value = stripped.removeprefix("description: ")
            if ": " in value:
                self.assertTrue(
                    value.startswith('"') and value.endswith('"'),
                    f"description value with colon must be quoted: {stripped}",
                )

    def test_ci_exercises_local_composite_action_paths(self) -> None:
        text = CI_WORKFLOW.read_text(encoding="utf-8")

        self.assertIn("uses: ./", text)
        self.assertIn("linwarden-action.sarif", text)
        self.assertIn("linwarden-action.md", text)
        self.assertIn("upload-sarif:", text)
        self.assertIn('add-summary: "true"', text)

    def test_release_workflow_attests_dist_artifacts(self) -> None:
        text = RELEASE_WORKFLOW.read_text(encoding="utf-8")
        docs = RELEASE_DOCS.read_text(encoding="utf-8")

        self.assertIn("id-token: write", text)
        self.assertIn("attestations: write", text)
        self.assertIn("artifact-metadata: write", text)
        self.assertIn("uses: actions/attest@v4", text)
        self.assertIn("subject-path: dist/*", text)
        self.assertIn("gh attestation verify", docs)
        self.assertIn("for artifact in dist/*", docs)
        self.assertIn('gh attestation verify "$artifact" --repo kingkyylian/linwarden', docs)


if __name__ == "__main__":
    unittest.main()
