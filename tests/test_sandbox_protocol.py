"""Versioned sandbox policy and worker wire-format contracts."""

from __future__ import annotations

import json
import unittest

from causure.adapters import EvaluationOutcome, ReplayOutcome
from causure.constants import (
    SANDBOX_POLICY_SCHEMA_VERSION,
    SANDBOX_WORKER_SCHEMA_VERSION,
    SandboxNetworkMode,
    SandboxWorkerMode,
)
from causure.sandbox_protocol import (
    MAX_SANDBOX_INPUT_BYTES,
    QuotaLease,
    SandboxDocumentError,
    SandboxPolicy,
    SandboxWorkerBudget,
    SandboxWorkerRequest,
    WorkerQuotaAccess,
    parse_sandbox_policy,
    parse_sandbox_worker_request,
    parse_sandbox_worker_response,
    render_sandbox_policy,
    render_sandbox_worker_request,
    render_sandbox_worker_response,
)

_IMAGE = f"registry.example/causure/worker@sha256:{'a' * 64}"
_TOKEN = "lease-secret-token-value"


def _policy() -> SandboxPolicy:
    return SandboxPolicy(
        schema_version=SANDBOX_POLICY_SCHEMA_VERSION,
        policy_id="offline-v1",
        worker_protocol=SANDBOX_WORKER_SCHEMA_VERSION,
        image=_IMAGE,
        network_mode=SandboxNetworkMode.NONE,
        cpu_limit=0.5,
        memory_mb=256,
        pids_limit=64,
        tmpfs_mb=32,
        max_output_bytes=65_536,
        user="65532:65532",
    )


def _replay_request(*, quota: WorkerQuotaAccess | None = None) -> SandboxWorkerRequest:
    return SandboxWorkerRequest(
        schema_version=SANDBOX_WORKER_SCHEMA_VERSION,
        mode=SandboxWorkerMode.REPLAY,
        case_id="case-001",
        input_ref="trace://one",
        budget=SandboxWorkerBudget(
            timeout_seconds=30,
            max_concurrency=1,
            max_cases=1,
            max_cost_usd=0.1,
        ),
        baseline_ref="agent://baseline",
        candidate_ref="agent://candidate",
        seed=7,
        quota=quota,
    )


class SandboxProtocolTests(unittest.TestCase):
    def test_policy_round_trips_and_requires_a_digest_pinned_non_root_image(self) -> None:
        policy = _policy()

        parsed = parse_sandbox_policy(json.loads(render_sandbox_policy(policy)))

        self.assertEqual(policy, parsed)
        for changes in (
            {"image": "registry.example/worker:latest"},
            {"image": f"registry.example/worker@sha256:{'A' * 64}"},
            {"user": "0:0"},
            {"memory_mb": 63},
            {"cpu_limit": float("inf")},
        ):
            values = {
                "schema_version": policy.schema_version,
                "policy_id": policy.policy_id,
                "worker_protocol": policy.worker_protocol,
                "image": policy.image,
                "network_mode": policy.network_mode,
                "cpu_limit": policy.cpu_limit,
                "memory_mb": policy.memory_mb,
                "pids_limit": policy.pids_limit,
                "tmpfs_mb": policy.tmpfs_mb,
                "max_output_bytes": policy.max_output_bytes,
                "user": policy.user,
                **changes,
            }
            with self.subTest(changes=changes):
                with self.assertRaises(ValueError):
                    SandboxPolicy(**values)

    def test_worker_request_round_trips_without_exposing_the_lease_in_repr(self) -> None:
        quota = WorkerQuotaAccess(
            lease_id="lease-001",
            lease_token=_TOKEN,
            proxy_url="https://quota-proxy:8443/v1",
        )
        request = _replay_request(quota=quota)

        payload = render_sandbox_worker_request(request)
        parsed = parse_sandbox_worker_request(payload)

        self.assertEqual(request, parsed)
        self.assertIn(_TOKEN.encode(), payload)
        self.assertNotIn(_TOKEN, repr(request))
        self.assertNotIn(_TOKEN, repr(quota))

    def test_quota_contract_requires_an_https_proxy_without_url_credentials(self) -> None:
        invalid_urls = (
            "http://quota-proxy/v1",
            "https://user:password@quota-proxy/v1",
            "https://quota-proxy/v1?token=bad",
            "https://quota-proxy/v1#fragment",
            "https://quota-proxy:bad/v1",
            "https://quota-proxy:70000/v1",
            "https://quota-proxy:/v1",
        )
        for proxy_url in invalid_urls:
            with self.subTest(proxy_url=proxy_url):
                with self.assertRaises(ValueError):
                    WorkerQuotaAccess(
                        lease_id="lease-001",
                        lease_token=_TOKEN,
                        proxy_url=proxy_url,
                    )

        with self.assertRaises(ValueError):
            QuotaLease(
                lease_id="lease-001",
                lease_token=_TOKEN,
                proxy_url="https://different-proxy/v1",
                proxy_container_name="quota-proxy",
                network_name="quota-network",
                expires_at="2026-07-28T13:00:00Z",
                max_cost_usd=1,
                max_concurrency=1,
                max_operations=1,
            )

    def test_worker_request_parser_is_closed_bounded_and_mode_specific(self) -> None:
        document = json.loads(render_sandbox_worker_request(_replay_request()))

        invalid_documents = []
        unknown = dict(document)
        unknown["private"] = "value"
        invalid_documents.append(unknown)
        mixed_mode = dict(document)
        mixed_mode["evaluator_ref"] = "evaluator://policy"
        invalid_documents.append(mixed_mode)
        invalid_seed = dict(document)
        invalid_seed["seed"] = 2**63
        invalid_documents.append(invalid_seed)
        for invalid in invalid_documents:
            with self.subTest(document=invalid):
                with self.assertRaises(SandboxDocumentError):
                    parse_sandbox_worker_request(
                        json.dumps(invalid, separators=(",", ":")).encode()
                    )

        duplicate_key = render_sandbox_worker_request(_replay_request()).replace(
            b'{"baseline_ref"',
            b'{"baseline_ref":"agent://shadow","baseline_ref"',
            1,
        )
        with self.assertRaises(SandboxDocumentError):
            parse_sandbox_worker_request(duplicate_key)
        with self.assertRaises(SandboxDocumentError):
            parse_sandbox_worker_request(b"x" * (MAX_SANDBOX_INPUT_BYTES + 1))

    def test_replay_and_evaluation_responses_round_trip(self) -> None:
        replay = ReplayOutcome(
            trial_id="trial-001",
            reproduced=True,
            evidence_ref="artifact://replay/one",
            latency_ms=12.5,
            cost_usd=0.01,
        )
        evaluation = EvaluationOutcome(
            validation_case_id="validation-001",
            passed=True,
            evidence_ref="artifact://evaluation/one",
            latency_ms=8.5,
            cost_usd=0.002,
            score=0.95,
        )

        parsed_replay = parse_sandbox_worker_response(
            render_sandbox_worker_response(
                SandboxWorkerMode.REPLAY,
                case_id="case-001",
                input_ref="trace://one",
                outcome=replay,
            ),
            expected_mode=SandboxWorkerMode.REPLAY,
            expected_case_id="case-001",
            expected_input_ref="trace://one",
            max_bytes=65_536,
        )
        parsed_evaluation = parse_sandbox_worker_response(
            render_sandbox_worker_response(
                SandboxWorkerMode.EVALUATION,
                case_id="case-001",
                input_ref="replay://one",
                outcome=evaluation,
            ),
            expected_mode=SandboxWorkerMode.EVALUATION,
            expected_case_id="case-001",
            expected_input_ref="replay://one",
            max_bytes=65_536,
        )

        self.assertEqual(replay, parsed_replay)
        self.assertEqual(evaluation, parsed_evaluation)

    def test_worker_response_rejects_mismatch_duplicates_unknowns_and_nonfinite_values(
        self,
    ) -> None:
        outcome = ReplayOutcome(
            trial_id="trial-001",
            reproduced=True,
            evidence_ref="artifact://replay/one",
            latency_ms=1,
            cost_usd=0.01,
        )
        payload = render_sandbox_worker_response(
            SandboxWorkerMode.REPLAY,
            case_id="case-001",
            input_ref="trace://one",
            outcome=outcome,
        )

        with self.assertRaises(SandboxDocumentError):
            parse_sandbox_worker_response(
                payload,
                expected_mode=SandboxWorkerMode.REPLAY,
                expected_case_id="different-case",
                expected_input_ref="trace://one",
                max_bytes=65_536,
            )

        unknown = json.loads(payload)
        unknown["outcome"]["private"] = "value"
        duplicate = payload.replace(
            b'{"case_id"',
            b'{"case_id":"shadow","case_id"',
            1,
        )
        nonfinite = payload.replace(b'"cost_usd":0.01', b'"cost_usd":NaN')
        for invalid in (
            json.dumps(unknown, separators=(",", ":")).encode(),
            duplicate,
            nonfinite,
        ):
            with self.subTest(invalid=invalid):
                with self.assertRaises(SandboxDocumentError):
                    parse_sandbox_worker_response(
                        invalid,
                        expected_mode=SandboxWorkerMode.REPLAY,
                        expected_case_id="case-001",
                        expected_input_ref="trace://one",
                        max_bytes=65_536,
                    )


if __name__ == "__main__":
    unittest.main()
