import unittest

from marketing_intelligence.estimate import (
    FULL_POC_LIMITS,
    R25_LIMITS,
    ResourceBudgetExceeded,
    estimate_tiered_stage,
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

    def test_tiered_estimate_uses_manifest_counts_and_full_poc_limits(self):
        first = estimate_tiered_stage(
            artifact_count=12,
            dependence_group_count=4,
            in_window_event_count=80,
            full_extract_fraction=0.25,
            mixed_sample_fraction=0.25,
            classification_packet_bytes=100,
            full_packet_bytes=500,
            max_packet_bytes=1_000,
            max_packet_tokens=500,
            bytes_per_token=3,
            prompt_tokens=20,
            output_tokens_per_call=40,
            concurrency=2,
            per_call_minutes=5,
        )
        second = estimate_tiered_stage(
            artifact_count=12,
            dependence_group_count=4,
            in_window_event_count=80,
            full_extract_fraction=0.25,
            mixed_sample_fraction=0.25,
            classification_packet_bytes=100,
            full_packet_bytes=500,
            max_packet_bytes=1_000,
            max_packet_tokens=500,
            bytes_per_token=3,
            prompt_tokens=20,
            output_tokens_per_call=40,
            concurrency=2,
            per_call_minutes=5,
        )

        self.assertEqual(first, second)
        self.assertEqual(first.classification_representative_count, 4)
        self.assertEqual(first.full_extract_group_count, 1)
        self.assertEqual(first.mixed_sample_group_count, 1)
        self.assertEqual(first.full_stage_group_count, 2)
        self.assertEqual(first.classification_groups_per_call, 10)
        self.assertEqual(first.full_extract_groups_per_call, 2)
        self.assertEqual(first.classification_calls, 1)
        self.assertEqual(first.full_extract_calls, 1)
        self.assertEqual(first.resource_estimate.calls, 2)
        self.assertEqual(FULL_POC_LIMITS.max_calls, 300)

    def test_tiered_estimate_batches_every_group_inside_ktd15_packet_caps(self):
        estimate = estimate_tiered_stage(
            artifact_count=335,
            dependence_group_count=290,
            in_window_event_count=35_479,
            classification_packet_bytes=1_024,
            full_packet_bytes=10_240,
            max_packet_bytes=100 * 1024,
            max_packet_tokens=32_000,
            bytes_per_token=3,
            prompt_tokens=800,
            output_tokens_per_call=5_000,
            concurrency=2,
            per_call_minutes=20,
        )

        self.assertEqual(estimate.classification_representative_count, 290)
        self.assertEqual(estimate.full_extract_group_count, 29)
        self.assertEqual(estimate.mixed_sample_group_count, 15)
        self.assertEqual(estimate.full_stage_group_count, 44)
        self.assertEqual(estimate.classification_groups_per_call, 93)
        self.assertEqual(estimate.full_extract_groups_per_call, 9)
        self.assertEqual(estimate.classification_calls, 4)
        self.assertEqual(estimate.full_extract_calls, 5)
        self.assertEqual(estimate.resource_estimate.calls, 9)
        self.assertEqual(estimate.resource_estimate.wall_minutes, 100)
        self.assertLessEqual(estimate.resource_estimate.calls, FULL_POC_LIMITS.max_calls)
        self.assertLessEqual(estimate.resource_estimate.wall_minutes, FULL_POC_LIMITS.max_wall_minutes)
        self.assertLessEqual(estimate.resource_estimate.input_tokens, FULL_POC_LIMITS.max_input_tokens)

    def test_tiered_estimate_rejects_a_representative_that_cannot_fit_a_ktd15_packet(self):
        with self.assertRaises(ValueError):
            estimate_tiered_stage(
                artifact_count=1,
                dependence_group_count=1,
                in_window_event_count=1,
                classification_packet_bytes=100_001,
                full_packet_bytes=1,
                max_packet_bytes=100_000,
                max_packet_tokens=32_000,
                bytes_per_token=3,
                prompt_tokens=1,
                output_tokens_per_call=1,
                concurrency=1,
                per_call_minutes=1,
            )


if __name__ == "__main__":
    unittest.main()
