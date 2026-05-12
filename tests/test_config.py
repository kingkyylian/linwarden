from pathlib import Path
import unittest

from linwarden.collectors import collect_host_snapshot
from linwarden.config import apply_config, load_config
from linwarden.rules import evaluate_snapshot


FIXTURE_ROOT = Path(__file__).parent / "fixtures" / "linux-root"
FIXTURE_CONFIG = Path(__file__).parent / "fixtures" / "linwarden.json"


class ConfigTests(unittest.TestCase):
    def test_loads_json_config_with_profile_and_suppressions(self) -> None:
        config = load_config(FIXTURE_CONFIG)

        self.assertEqual(config.profile, "router")
        self.assertEqual(config.disabled_rules, ("LNX-NET-002",))
        self.assertEqual(config.suppressions["LNX-SSH-002"], "Fixture keeps password auth enabled.")

    def test_applies_profile_disabled_rules_and_suppressions(self) -> None:
        snapshot = collect_host_snapshot(
            root=FIXTURE_ROOT,
            proc_root=FIXTURE_ROOT / "proc",
            etc_root=FIXTURE_ROOT / "etc",
        )
        result = apply_config(evaluate_snapshot(snapshot), load_config(FIXTURE_CONFIG))
        active_rule_ids = {finding.rule_id for finding in result.active_findings}
        suppressed_by_rule = {finding.rule_id: finding for finding in result.suppressed_findings}

        self.assertNotIn("LNX-NET-001", active_rule_ids)
        self.assertNotIn("LNX-NET-003", active_rule_ids)
        self.assertNotIn("LNX-NET-002", active_rule_ids)
        self.assertNotIn("LNX-SSH-002", active_rule_ids)
        self.assertEqual(suppressed_by_rule["LNX-NET-001"].source, "profile")
        self.assertEqual(suppressed_by_rule["LNX-NET-002"].source, "disabled_rule")
        self.assertEqual(suppressed_by_rule["LNX-SSH-002"].source, "suppression")
        self.assertEqual(len(result.active_findings), 7)


if __name__ == "__main__":
    unittest.main()
