import hashlib
import unittest
from pathlib import Path
from tempfile import TemporaryDirectory
from types import SimpleNamespace

from scripts.release_assets import write_sha256sums
from scripts.smoke_pypi_release import smoke_pypi_release
from scripts.verify_release_version import verify_release_version

ROOT = Path(__file__).resolve().parents[1]


class ReleaseAssetTests(unittest.TestCase):
    def test_writes_stable_sha256_manifest_for_dist_files(self) -> None:
        with TemporaryDirectory() as temp_dir:
            dist = Path(temp_dir)
            wheel = dist / "linwarden-0.13.0-py3-none-any.whl"
            sdist = dist / "linwarden-0.13.0.tar.gz"
            wheel.write_bytes(b"wheel")
            sdist.write_bytes(b"sdist")

            manifest = write_sha256sums(dist)

            self.assertEqual(manifest, dist / "SHA256SUMS")
            self.assertEqual(
                manifest.read_text(encoding="utf-8"),
                "\n".join(
                    [
                        f"{hashlib.sha256(wheel.read_bytes()).hexdigest()}  {wheel.name}",
                        f"{hashlib.sha256(sdist.read_bytes()).hexdigest()}  {sdist.name}",
                        "",
                    ]
                ),
            )

    def test_source_distribution_excludes_local_checkpoints(self) -> None:
        manifest = (ROOT / "MANIFEST.in").read_text(encoding="utf-8")

        self.assertIn("recursive-exclude docs/checkpoints *", manifest)

    def test_verify_release_version_accepts_matching_tag_and_dist_files(self) -> None:
        with TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            dist = root / "dist"
            package_init = root / "src" / "linwarden" / "__init__.py"
            changelog = root / "CHANGELOG.md"
            dist.mkdir()
            package_init.parent.mkdir(parents=True)
            (root / "pyproject.toml").write_text(
                '[project]\nname = "linwarden"\nversion = "1.2.3"\n',
                encoding="utf-8",
            )
            package_init.write_text('__version__ = "1.2.3"\n', encoding="utf-8")
            changelog.write_text("# Changelog\n\n## 1.2.3 - 2026-05-20\n\n- Added release notes.\n", encoding="utf-8")
            (dist / "linwarden-1.2.3.tar.gz").write_bytes(b"sdist")
            (dist / "linwarden-1.2.3-py3-none-any.whl").write_bytes(b"wheel")

            verify_release_version(
                pyproject=root / "pyproject.toml",
                package_init=package_init,
                ref_name="v1.2.3",
                dist_dir=dist,
                changelog=changelog,
            )

    def test_verify_release_version_rejects_mismatched_tag(self) -> None:
        with TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            package_init = root / "src" / "linwarden" / "__init__.py"
            package_init.parent.mkdir(parents=True)
            (root / "pyproject.toml").write_text(
                '[project]\nname = "linwarden"\nversion = "1.2.3"\n',
                encoding="utf-8",
            )
            package_init.write_text('__version__ = "1.2.3"\n', encoding="utf-8")

            with self.assertRaisesRegex(ValueError, "tag v1.2.4 does not match pyproject version 1.2.3"):
                verify_release_version(
                    pyproject=root / "pyproject.toml",
                    package_init=package_init,
                    ref_name="v1.2.4",
                )

    def test_verify_release_version_rejects_mismatched_runtime_version(self) -> None:
        with TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            package_init = root / "src" / "linwarden" / "__init__.py"
            package_init.parent.mkdir(parents=True)
            (root / "pyproject.toml").write_text(
                '[project]\nname = "linwarden"\nversion = "1.2.3"\n',
                encoding="utf-8",
            )
            package_init.write_text('__version__ = "1.2.4"\n', encoding="utf-8")

            with self.assertRaisesRegex(ValueError, "runtime version 1.2.4 does not match pyproject version 1.2.3"):
                verify_release_version(
                    pyproject=root / "pyproject.toml",
                    package_init=package_init,
                    ref_name="v1.2.3",
                )

    def test_verify_release_version_rejects_mismatched_dist_files(self) -> None:
        with TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            dist = root / "dist"
            package_init = root / "src" / "linwarden" / "__init__.py"
            dist.mkdir()
            package_init.parent.mkdir(parents=True)
            (root / "pyproject.toml").write_text(
                '[project]\nname = "linwarden"\nversion = "1.2.3"\n',
                encoding="utf-8",
            )
            package_init.write_text('__version__ = "1.2.3"\n', encoding="utf-8")
            (dist / "linwarden-1.2.4.tar.gz").write_bytes(b"sdist")

            with self.assertRaisesRegex(ValueError, "dist file linwarden-1.2.4.tar.gz does not match version 1.2.3"):
                verify_release_version(
                    pyproject=root / "pyproject.toml",
                    package_init=package_init,
                    ref_name="v1.2.3",
                    dist_dir=dist,
                )

    def test_verify_release_version_rejects_missing_changelog_section(self) -> None:
        with TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            package_init = root / "src" / "linwarden" / "__init__.py"
            changelog = root / "CHANGELOG.md"
            package_init.parent.mkdir(parents=True)
            (root / "pyproject.toml").write_text(
                '[project]\nname = "linwarden"\nversion = "1.2.3"\n',
                encoding="utf-8",
            )
            package_init.write_text('__version__ = "1.2.3"\n', encoding="utf-8")
            changelog.write_text("# Changelog\n\n## 1.2.2 - 2026-05-19\n\n- Previous notes.\n", encoding="utf-8")

            with self.assertRaisesRegex(ValueError, "changelog section for version 1.2.3 not found"):
                verify_release_version(
                    pyproject=root / "pyproject.toml",
                    package_init=package_init,
                    ref_name="v1.2.3",
                    changelog=changelog,
                )

    def test_verify_release_version_rejects_empty_changelog_section(self) -> None:
        with TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            package_init = root / "src" / "linwarden" / "__init__.py"
            changelog = root / "CHANGELOG.md"
            package_init.parent.mkdir(parents=True)
            (root / "pyproject.toml").write_text(
                '[project]\nname = "linwarden"\nversion = "1.2.3"\n',
                encoding="utf-8",
            )
            package_init.write_text('__version__ = "1.2.3"\n', encoding="utf-8")
            changelog.write_text("# Changelog\n\n## 1.2.3 - 2026-05-20\n\n## 1.2.2 - 2026-05-19\n", encoding="utf-8")

            with self.assertRaisesRegex(ValueError, "changelog section for version 1.2.3 has no entries"):
                verify_release_version(
                    pyproject=root / "pyproject.toml",
                    package_init=package_init,
                    ref_name="v1.2.3",
                    changelog=changelog,
                )

    def test_writes_release_notes_from_changelog_section(self) -> None:
        with TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            changelog = root / "CHANGELOG.md"
            output = root / "release-notes.md"
            changelog.write_text(
                "\n".join(
                    [
                        "# Changelog",
                        "",
                        "## 1.2.3 - 2026-05-20",
                        "",
                        "- Added release notes from changelog.",
                        "- Fixed publish notes drift.",
                        "",
                        "## 1.2.2 - 2026-05-19",
                        "",
                        "- Previous notes.",
                        "",
                    ]
                ),
                encoding="utf-8",
            )
            from scripts.changelog_release_notes import write_changelog_release_notes

            write_changelog_release_notes(changelog=changelog, ref_name="v1.2.3", output=output)

            self.assertEqual(
                output.read_text(encoding="utf-8"),
                "\n".join(
                    [
                        "## 1.2.3 - 2026-05-20",
                        "",
                        "- Added release notes from changelog.",
                        "- Fixed publish notes drift.",
                        "",
                    ]
                ),
            )

    def test_writes_release_notes_from_pyproject_version_for_dry_run_ref(self) -> None:
        with TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            changelog = root / "CHANGELOG.md"
            output = root / "release-notes.md"
            pyproject = root / "pyproject.toml"
            pyproject.write_text('[project]\nname = "linwarden"\nversion = "1.2.3"\n', encoding="utf-8")
            changelog.write_text(
                "\n".join(
                    [
                        "# Changelog",
                        "",
                        "## 1.2.3 - 2026-05-20",
                        "",
                        "- Dry-run notes come from the project version.",
                        "",
                    ]
                ),
                encoding="utf-8",
            )
            from scripts.changelog_release_notes import write_changelog_release_notes

            write_changelog_release_notes(changelog=changelog, ref_name="main", output=output, pyproject=pyproject)

            self.assertIn("Dry-run notes come from the project version.", output.read_text(encoding="utf-8"))

    def test_smoke_pypi_release_runs_install_and_cli_checks(self) -> None:
        with TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            fixture_root = root / "tests" / "fixtures" / "linux-root"
            venv = root / "venv"
            fixture_root.mkdir(parents=True)
            commands: list[list[str]] = []

            def fake_run(command: list[str], **kwargs: object) -> SimpleNamespace:
                commands.append(command)
                if command[-1] == "--version":
                    return SimpleNamespace(stdout="linwarden 1.2.3\n")
                return SimpleNamespace(stdout="")

            smoke_pypi_release(
                "v1.2.3",
                fixture_root=fixture_root,
                venv_path=venv,
                python="python3",
                runner=fake_run,
            )

        self.assertEqual(commands[0], ["python3", "-m", "venv", str(venv)])
        self.assertEqual(commands[1][-4:], ["install", "--no-cache-dir", "--upgrade", "linwarden==1.2.3"])
        self.assertEqual(commands[2], [str(venv / "bin" / "linwarden"), "--version"])
        self.assertEqual(commands[3], [str(venv / "bin" / "linwarden"), "--help"])
        self.assertEqual(
            commands[4],
            [
                str(venv / "bin" / "linwarden"),
                "scan",
                "--root",
                str(fixture_root),
                "--format",
                "json",
                "--fail-on",
                "off",
            ],
        )

    def test_smoke_pypi_release_rejects_mismatched_cli_version(self) -> None:
        with TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            fixture_root = root / "tests" / "fixtures" / "linux-root"
            fixture_root.mkdir(parents=True)

            def fake_run(command: list[str], **kwargs: object) -> SimpleNamespace:
                if command[-1] == "--version":
                    return SimpleNamespace(stdout="linwarden 1.2.4\n")
                return SimpleNamespace(stdout="")

            with self.assertRaisesRegex(RuntimeError, "installed linwarden version did not match 1.2.3"):
                smoke_pypi_release(
                    "1.2.3",
                    fixture_root=fixture_root,
                    venv_path=root / "venv",
                    python="python3",
                    runner=fake_run,
                )


if __name__ == "__main__":
    unittest.main()
