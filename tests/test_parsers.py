import unittest
from pathlib import Path
from tempfile import TemporaryDirectory

from linwarden.parsers import parse_sshd_config


class ParserTests(unittest.TestCase):
    def test_sshd_config_includes_files_and_keeps_first_value(self) -> None:
        with TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            include_dir = root / "sshd_config.d"
            include_dir.mkdir()
            (root / "sshd_config").write_text(
                "\n".join(
                    [
                        "PasswordAuthentication no",
                        "Include sshd_config.d/*.conf",
                        "PasswordAuthentication yes",
                    ]
                ),
                encoding="utf-8",
            )
            (include_dir / "extra.conf").write_text(
                "\n".join(
                    [
                        "PasswordAuthentication yes",
                        "X11Forwarding yes",
                    ]
                ),
                encoding="utf-8",
            )

            options = parse_sshd_config(root / "sshd_config")

        self.assertEqual(options["passwordauthentication"], "no")
        self.assertEqual(options["x11forwarding"], "yes")


if __name__ == "__main__":
    unittest.main()
