import unittest

from marketing_intelligence.estimate import (
    R25_LIMITS,
    ResourceBudgetExceeded,
    estimate_probe_resources,
    enforce_r25,
)


class EstimateTests(unittest.TestCase):
    def test_estimate_is_deterministic_and_includes_prompt_overhead(self):
        first = estimate_probe_resources(
            packet_bytes=(4000, 8000),
            prompt_tokens=120,
            output_tokens_per_call=300,
            calls=2,
            concurrency=2,
            per_call_minutes=5,
        )
        second = estimate_probe_resources(
            packet_bytes=(4000, 8000),
            prompt_tokens=120,
            output_tokens_per_call=300,
            calls=2,
            concurrency=2,
            per_call_minutes=5,
        )

        self.assertEqual(first, second)
        self.assertGreater(first.input_tokens, (4000 + 8000) // 4)
        self.assertLessEqual(first.calls, R25_LIMITS.max_calls)

    def test_input_token_ceiling_is_rejected_before_dispatch(self):
        estimate = estimate_probe_resources(
            packet_bytes=(2_100_000,),
            prompt_tokens=0,
            output_tokens_per_call=0,
            calls=1,
            concurrency=1,
            per_call_minutes=1,
        )

        with self.assertRaises(ResourceBudgetExceeded) as caught:
            enforce_r25(estimate)
        self.assertEqual(caught.exception.dimension, "input_tokens")

    def test_call_and_wall_time_ceilings_are_enforced(self):
        estimate = estimate_probe_resources(
            packet_bytes=(10,),
            prompt_tokens=0,
            output_tokens_per_call=0,
            calls=25,
            concurrency=1,
            per_call_minutes=1,
        )

        with self.assertRaises(ResourceBudgetExceeded) as caught:
            enforce_r25(estimate)
        self.assertIn(caught.exception.dimension, {"calls", "wall_minutes"})


if __name__ == "__main__":
    unittest.main()
