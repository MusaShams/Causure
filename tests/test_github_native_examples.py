"""Regression coverage for the credential-free GitHub-native example kit."""

from __future__ import annotations

import re
import unittest

from scripts.qualify_github_native_examples import SCENARIOS, qualify
from tests.helpers import PROJECT_ROOT


class GitHubNativeExampleTests(unittest.TestCase):
    def test_each_hosted_scenario_changes_its_configured_component(self) -> None:
        example_root = PROJECT_ROOT / "examples" / "github-native"

        for scenario, component_path, _, _ in SCENARIOS:
            with self.subTest(scenario=scenario):
                base = example_root / "template" / component_path
                candidate = example_root / "scenarios" / scenario / component_path

                self.assertNotEqual(base.read_bytes(), candidate.read_bytes())

    def test_local_stories_cover_all_published_example_decisions(self) -> None:
        receipt = qualify()

        self.assertEqual("passed", receipt["result"])
        self.assertFalse(receipt["credentialed_services_used"])
        self.assertFalse(receipt["candidate_code_executed"])
        decisions = {item["scenario"]: item["decision"] for item in receipt["scenarios"]}
        self.assertEqual(
            {
                "abstain": "reject",
                "approve": "approve",
                "needs-evidence": "needs_evidence",
            },
            decisions,
        )
        self.assertIn("not remote GitHub evidence", receipt["scope"])

    def test_workflow_template_keeps_control_and_candidate_checkouts_separate(self) -> None:
        workflow = (PROJECT_ROOT / "examples" / "github-native" / "causure.template.yml").read_text(
            encoding="utf-8"
        )

        self.assertIn("ref: ${{ github.event.pull_request.base.sha }}", workflow)
        self.assertIn("path: trusted-control", workflow)
        self.assertIn("ref: ${{ github.event.pull_request.head.sha }}", workflow)
        self.assertIn("path: candidate", workflow)
        self.assertIn("/trusted-case-generator@__CAUSURE_ACTION_SHA__", workflow)
        self.assertIn("repository-root: candidate", workflow)
        self.assertEqual(2, workflow.count("__CAUSURE_ACTION_SHA__"))
        self.assertNotIn("uses: ./", workflow)
        external_pins = re.findall(r"uses: actions/[^@\s]+@([0-9a-f]{40})", workflow)
        self.assertEqual(3, len(external_pins))


if __name__ == "__main__":
    unittest.main()
