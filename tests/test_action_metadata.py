import unittest
from pathlib import Path

ACTION = Path(__file__).resolve().parents[1] / "action.yml"
DOCS = Path(__file__).resolve().parents[1] / "docs" / "github-actions.md"
CI_WORKFLOW = Path(__file__).resolve().parents[1] / ".github" / "workflows" / "ci.yml"
RELEASE_WORKFLOW = Path(__file__).resolve().parents[1] / ".github" / "workflows" / "release.yml"
PYPI_SMOKE_WORKFLOW = Path(__file__).resolve().parents[1] / ".github" / "workflows" / "pypi-smoke.yml"
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
            "sys-root",
            "vulnerability-feed",
            "vulnerability-feed-format",
            "sshd-mode",
            "sshd-binary",
            "sshd-match",
            "upload-sarif",
            "add-summary",
        ):
            self.assertIn(f"  {input_name}:", text)

        self.assertIn("VULNERABILITY_FEED", text)
        self.assertIn("VULNERABILITY_FEED_FORMAT", text)
        self.assertIn("--vulnerability-feed", text)
        self.assertIn("--vulnerability-feed-format", text)
        self.assertIn("linwarden, trivy, grype, or osv", text)

    def test_github_actions_docs_use_the_composite_action(self) -> None:
        text = DOCS.read_text(encoding="utf-8")

        self.assertIn("uses: kingkyylian/linwarden@v0.13.1", text)
        self.assertIn("upload-sarif: \"true\"", text)
        self.assertIn("add-summary: \"true\"", text)
        self.assertIn("vulnerability-feed-format: osv", text)

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

    def test_release_workflow_gates_pypi_publish_after_github_artifacts(self) -> None:
        text = RELEASE_WORKFLOW.read_text(encoding="utf-8")

        self.assertIn("publish-pypi:", text)
        self.assertIn("needs: build", text)
        self.assertIn(
            "if: github.event_name == 'push' && startsWith(github.ref, 'refs/tags/v') && vars.PUBLISH_PYPI == 'true'",
            text,
        )
        self.assertIn("name: pypi", text)
        self.assertIn("id-token: write", text)
        self.assertIn("uses: actions/upload-artifact@v7", text)
        self.assertIn("uses: actions/download-artifact@v7", text)
        self.assertIn("uses: pypa/gh-action-pypi-publish@release/v1", text)
        self.assertLess(text.index("Create GitHub release"), text.index("publish-pypi:"))

    def test_release_workflow_supports_manual_dry_run_without_publishing(self) -> None:
        text = RELEASE_WORKFLOW.read_text(encoding="utf-8")

        self.assertIn("workflow_dispatch:", text)
        self.assertIn("dry-run:", text)
        self.assertIn("default: true", text)
        self.assertIn("Upload release dry-run artifacts", text)
        self.assertIn("name: release-dry-run-artifacts", text)
        self.assertIn("if: github.event_name == 'workflow_dispatch'", text)
        self.assertIn("if: github.event_name == 'push' && startsWith(github.ref, 'refs/tags/v')", text)

    def test_release_workflow_verifies_tag_version_before_release_outputs(self) -> None:
        text = RELEASE_WORKFLOW.read_text(encoding="utf-8")

        self.assertIn("Verify release version", text)
        self.assertIn(
            "python scripts/verify_release_version.py --ref-name \"$GITHUB_REF_NAME\" "
            "--dist-dir dist --changelog CHANGELOG.md",
            text,
        )
        self.assertLess(text.index("Verify release version"), text.index("Upload release dry-run artifacts"))
        self.assertLess(text.index("Verify release version"), text.index("Generate artifact attestations"))
        self.assertLess(text.index("Verify release version"), text.index("Create GitHub release"))

    def test_release_workflow_uses_changelog_for_github_release_body(self) -> None:
        text = RELEASE_WORKFLOW.read_text(encoding="utf-8")
        docs = RELEASE_DOCS.read_text(encoding="utf-8")

        self.assertIn("Write release notes", text)
        self.assertIn(
            "python scripts/changelog_release_notes.py --ref-name \"$GITHUB_REF_NAME\" "
            "--changelog CHANGELOG.md --output release-notes.md",
            text,
        )
        self.assertIn("--notes-file release-notes.md", text)
        self.assertNotIn("--generate-notes", text)
        self.assertLess(text.index("Verify release version"), text.index("Write release notes"))
        self.assertLess(text.index("Write release notes"), text.index("Create GitHub release"))
        self.assertIn("GitHub release body is written from the matching `CHANGELOG.md` section", docs)

    def test_release_docs_cover_pypi_trusted_publisher_setup_and_rollback(self) -> None:
        docs = RELEASE_DOCS.read_text(encoding="utf-8")

        self.assertIn("PyPI project: `linwarden`", docs)
        self.assertIn("Owner: `kingkyylian`", docs)
        self.assertIn("Repository: `linwarden`", docs)
        self.assertIn("Workflow: `release.yml`", docs)
        self.assertIn("Environment name: `pypi`", docs)
        self.assertIn("Repository variable: `PUBLISH_PYPI=true`", docs)
        self.assertIn("set `PUBLISH_PYPI=false` or remove the variable", docs)
        self.assertIn("GitHub release artifacts are still produced by the `build` job", docs)

    def test_release_docs_cover_manual_dry_run(self) -> None:
        docs = RELEASE_DOCS.read_text(encoding="utf-8")

        self.assertIn("## Release Dry Run", docs)
        self.assertIn("gh workflow run release.yml", docs)
        self.assertIn("release-dry-run-artifacts", docs)
        self.assertIn("does not create a GitHub release", docs)
        self.assertIn("does not publish to PyPI", docs)

    def test_release_docs_cover_version_guard(self) -> None:
        docs = RELEASE_DOCS.read_text(encoding="utf-8")

        self.assertIn("Release Version Guard", docs)
        self.assertIn("scripts/verify_release_version.py", docs)
        self.assertIn("tag name matches `pyproject.toml`", docs)
        self.assertIn("runtime `__version__` matches `pyproject.toml`", docs)
        self.assertIn("distribution filenames match that version", docs)
        self.assertIn("`CHANGELOG.md` has a dated section for the release version", docs)

    def test_release_docs_cover_pypi_smoke_script(self) -> None:
        docs = RELEASE_DOCS.read_text(encoding="utf-8")

        self.assertIn("scripts/smoke_pypi_release.py", docs)
        self.assertIn("linwarden --version", docs)
        self.assertIn("fixture scan", docs)

    def test_pypi_smoke_workflow_runs_release_smoke_script(self) -> None:
        text = PYPI_SMOKE_WORKFLOW.read_text(encoding="utf-8")
        docs = RELEASE_DOCS.read_text(encoding="utf-8")

        self.assertIn("workflow_dispatch:", text)
        self.assertIn("version:", text)
        self.assertIn("required: true", text)
        self.assertIn("actions/checkout@v6", text)
        self.assertIn("actions/setup-python@v6", text)
        self.assertIn('python scripts/smoke_pypi_release.py "${{ inputs.version }}"', text)
        self.assertIn("gh workflow run pypi-smoke.yml", docs)
        self.assertIn("workflow run verifies", docs)


if __name__ == "__main__":
    unittest.main()
