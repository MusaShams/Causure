"""Gate-policy parsing."""

from __future__ import annotations

import math
import unittest

from causure.errors import DocumentValidationError
from causure.policy import GatePolicy, parse_policy, policy_to_dict


class PolicyTests(unittest.TestCase):
    def test_defaults_are_explicit_and_serializable(self) -> None:
        policy = parse_policy(None)

        self.assertEqual(GatePolicy(), policy)
        self.assertEqual("default-v1", policy_to_dict(policy)["name"])

    def test_sparse_override_preserves_other_defaults(self) -> None:
        policy = parse_policy({"name": "team-policy", "min_reproduction_trials": 7})

        self.assertEqual("team-policy", policy.name)
        self.assertEqual(7, policy.min_reproduction_trials)
        self.assertEqual(0.67, policy.min_reproduction_rate)

    def test_rejects_unknown_policy_fields(self) -> None:
        with self.assertRaises(DocumentValidationError) as caught:
            parse_policy({"approve_everything": True})

        self.assertIn("$.approve_everything", str(caught.exception))

    def test_rejects_rates_outside_zero_and_one(self) -> None:
        with self.assertRaises(DocumentValidationError) as caught:
            parse_policy({"min_reproduction_rate": 1.1})

        self.assertIn("between 0 and 1", str(caught.exception))

    def test_rejects_boolean_values_for_integer_thresholds(self) -> None:
        with self.assertRaises(DocumentValidationError):
            parse_policy({"min_reproduction_trials": True})

    def test_rejects_nonfinite_ratio_limits(self) -> None:
        with self.assertRaises(DocumentValidationError):
            parse_policy({"max_cost_increase_ratio": math.inf})


if __name__ == "__main__":
    unittest.main()
