"""OCI sandbox scheduling, isolation-plan, and hard-quota contracts."""

from __future__ import annotations

import json
import sys
import threading
import time
import unittest
from datetime import UTC, datetime, timedelta

from causure.adapters import (
    EvaluationOutcome,
    EvaluationRequest,
    ExecutionBudget,
    ReplayOutcome,
    ReplayRequest,
)
from causure.constants import (
    SANDBOX_POLICY_SCHEMA_VERSION,
    SANDBOX_WORKER_SCHEMA_VERSION,
    SandboxNetworkMode,
    SandboxWorkerMode,
)
from causure.sandbox import (
    DockerCliSandboxRuntime,
    SandboxBudgetError,
    SandboxedAdapterRunner,
    SandboxInvocation,
    SandboxProtocolError,
    SandboxQuotaError,
    SandboxRuntimeError,
    SandboxTimeoutError,
)
from causure.sandbox_protocol import (
    QuotaLease,
    QuotaReservation,
    QuotaSettlement,
    SandboxPolicy,
    parse_sandbox_worker_request,
    render_sandbox_worker_response,
)

_IMAGE = f"registry.example/causure/worker@sha256:{'b' * 64}"
_TOKEN = "provider-lease-secret-value"
_NOW = datetime(2026, 7, 28, 12, 0, tzinfo=UTC)


def _policy(
    network_mode: SandboxNetworkMode = SandboxNetworkMode.NONE,
) -> SandboxPolicy:
    return SandboxPolicy(
        schema_version=SANDBOX_POLICY_SCHEMA_VERSION,
        policy_id=f"sandbox-{network_mode.value}",
        worker_protocol=SANDBOX_WORKER_SCHEMA_VERSION,
        image=_IMAGE,
        network_mode=network_mode,
        cpu_limit=0.75,
        memory_mb=256,
        pids_limit=64,
        tmpfs_mb=32,
        max_output_bytes=65_536,
        user="65532:65532",
    )


def _replay_request(
    *,
    refs: tuple[str, ...] = ("trace://one", "trace://two"),
    max_concurrency: int = 2,
    max_cases: int | None = None,
    max_cost_usd: float | None = 0.2,
) -> ReplayRequest:
    return ReplayRequest(
        case_id="case-001",
        trace_refs=refs,
        baseline_ref="agent://baseline",
        candidate_ref="agent://candidate",
        seed=7,
        budget=ExecutionBudget(
            timeout_seconds=2,
            max_concurrency=max_concurrency,
            max_cases=len(refs) if max_cases is None else max_cases,
            max_cost_usd=max_cost_usd,
        ),
    )


class _FakeRuntime:
    def __init__(
        self,
        *,
        events: list[str] | None = None,
        delay_seconds: float = 0,
        cost_usd: float = 0.01,
        duplicate_ids: bool = False,
        fail_ref: str | None = None,
        timeout_ref: str | None = None,
    ) -> None:
        self.events = events if events is not None else []
        self.delay_seconds = delay_seconds
        self.cost_usd = cost_usd
        self.duplicate_ids = duplicate_ids
        self.fail_ref = fail_ref
        self.timeout_ref = timeout_ref
        self.preflights: list[tuple[SandboxPolicy, QuotaLease | None]] = []
        self.invocations: list[SandboxInvocation] = []
        self.cancelled: list[str] = []
        self.active = 0
        self.peak_active = 0
        self._lock = threading.Lock()
        self._both_started = threading.Event()

    def preflight(self, policy: SandboxPolicy, lease: QuotaLease | None) -> None:
        self.events.append("preflight")
        self.preflights.append((policy, lease))

    def run(self, invocation: SandboxInvocation, *, timeout_seconds: float) -> bytes:
        request = parse_sandbox_worker_request(invocation.payload)
        with self._lock:
            self.invocations.append(invocation)
            self.active += 1
            self.peak_active = max(self.peak_active, self.active)
            if self.active >= 2:
                self._both_started.set()
        self.events.append(f"run:{request.input_ref}")
        try:
            if request.input_ref == self.timeout_ref:
                self._both_started.wait(0.5)
                raise SandboxTimeoutError("timeout_exceeded", "fake timeout")
            if request.input_ref == self.fail_ref:
                self._both_started.wait(0.5)
                raise SandboxRuntimeError("fake_worker_failed", "fake worker failed")
            if self.delay_seconds:
                time.sleep(self.delay_seconds)
            identity = (
                "duplicate" if self.duplicate_ids else request.input_ref.rsplit("/", maxsplit=1)[-1]
            )
            if request.mode is SandboxWorkerMode.REPLAY:
                outcome: ReplayOutcome | EvaluationOutcome = ReplayOutcome(
                    trial_id=f"trial-{identity}",
                    reproduced=True,
                    evidence_ref=f"artifact://replay/{identity}",
                    latency_ms=10,
                    cost_usd=self.cost_usd,
                )
            else:
                outcome = EvaluationOutcome(
                    validation_case_id=f"validation-{identity}",
                    passed=True,
                    evidence_ref=f"artifact://evaluation/{identity}",
                    latency_ms=8,
                    cost_usd=self.cost_usd,
                    score=0.9,
                )
            return render_sandbox_worker_response(
                request.mode,
                case_id=request.case_id,
                input_ref=request.input_ref,
                outcome=outcome,
            )
        finally:
            with self._lock:
                self.active -= 1

    def cancel(self, container_name: str) -> bool:
        self.cancelled.append(container_name)
        return True


class _FakeQuotaController:
    def __init__(
        self,
        *,
        events: list[str] | None = None,
        lease_concurrency: int | None = None,
        operation_delta: int = 0,
        actual_cost_usd: float = 0.025,
    ) -> None:
        self.events = events if events is not None else []
        self.lease_concurrency = lease_concurrency
        self.operation_delta = operation_delta
        self.actual_cost_usd = actual_cost_usd
        self.reservations: list[QuotaReservation] = []
        self.settlements: list[tuple[str, int]] = []
        self.cancellations: list[tuple[str, str]] = []

    def reserve(self, reservation: QuotaReservation) -> QuotaLease:
        self.events.append("reserve")
        self.reservations.append(reservation)
        return QuotaLease(
            lease_id="lease-001",
            lease_token=_TOKEN,
            proxy_url="https://quota-proxy:8443/v1",
            proxy_container_name="quota-proxy",
            network_name="quota-network",
            expires_at="2026-07-28T12:10:00Z",
            max_cost_usd=reservation.max_cost_usd,
            max_concurrency=(
                reservation.max_concurrency
                if self.lease_concurrency is None
                else self.lease_concurrency
            ),
            max_operations=reservation.max_operations + self.operation_delta,
        )

    def settle(
        self,
        lease_id: str,
        *,
        completed_operations: int,
    ) -> QuotaSettlement:
        self.events.append("settle")
        self.settlements.append((lease_id, completed_operations))
        return QuotaSettlement(
            lease_id=lease_id,
            status="settled",
            actual_cost_usd=self.actual_cost_usd,
            completed_operations=completed_operations,
        )

    def cancel(self, lease_id: str, *, reason_code: str) -> None:
        self.events.append("cancel")
        self.cancellations.append((lease_id, reason_code))


class _ScriptedDockerRuntime(DockerCliSandboxRuntime):
    def __init__(self, responses: list[bytes]) -> None:
        super().__init__(("docker",))
        self.responses = responses
        self.control_calls: list[tuple[str, ...]] = []

    def _control(
        self,
        arguments,
        *,
        timeout_seconds: float = 10,
    ) -> bytes:
        del timeout_seconds
        self.control_calls.append(tuple(arguments))
        return self.responses.pop(0)


class _LocalProcessRuntime(DockerCliSandboxRuntime):
    def __init__(self, script: str) -> None:
        super().__init__((sys.executable, "-c", script))
        self.cancelled: list[str] = []

    def cancel(self, container_name: str) -> bool:
        self.cancelled.append(container_name)
        return True


def _image_inspection(*, volumes=None) -> bytes:
    return json.dumps(
        {
            "RepoDigests": [_IMAGE],
            "Os": "linux",
            "Config": {"Volumes": volumes},
        }
    ).encode()


def _quota_lease(*, operations: int = 2) -> QuotaLease:
    return QuotaLease(
        lease_id="lease-001",
        lease_token=_TOKEN,
        proxy_url="https://quota-proxy:8443/v1",
        proxy_container_name="quota-proxy",
        network_name="quota-network",
        expires_at="2026-07-28T12:10:00Z",
        max_cost_usd=0.2,
        max_concurrency=2,
        max_operations=operations,
    )


class SandboxRunnerTests(unittest.TestCase):
    def test_offline_replay_is_ordered_and_parent_concurrency_is_bounded(self) -> None:
        runtime = _FakeRuntime(delay_seconds=0.03)
        runner = SandboxedAdapterRunner(runtime)
        request = _replay_request(
            refs=("trace://one", "trace://two", "trace://three", "trace://four"),
            max_concurrency=2,
        )

        result = runner.run_replay(_policy(), request)

        self.assertEqual(
            ("trial-one", "trial-two", "trial-three", "trial-four"),
            tuple(outcome.trial_id for outcome in result.outcomes),
        )
        self.assertAlmostEqual(0.04, result.total_cost_usd)
        self.assertAlmostEqual(0.04, result.reported_cost_usd)
        self.assertEqual(2, result.max_parallel_workers)
        self.assertEqual(2, runtime.peak_active)
        self.assertEqual([(_policy(), None)], runtime.preflights)

    def test_offline_evaluation_uses_the_evaluation_protocol(self) -> None:
        runtime = _FakeRuntime()
        request = EvaluationRequest(
            case_id="case-001",
            replay_refs=("replay://one",),
            evaluator_ref="evaluator://policy",
            budget=ExecutionBudget(
                timeout_seconds=2,
                max_concurrency=1,
                max_cases=1,
                max_cost_usd=0.1,
            ),
        )

        result = SandboxedAdapterRunner(runtime).run_evaluation(_policy(), request)

        self.assertEqual("validation-one", result.outcomes[0].validation_case_id)
        worker_request = parse_sandbox_worker_request(runtime.invocations[0].payload)
        self.assertIs(SandboxWorkerMode.EVALUATION, worker_request.mode)
        self.assertEqual("evaluator://policy", worker_request.evaluator_ref)

    def test_case_reported_cost_and_duplicate_identity_limits_fail_closed(self) -> None:
        case_runtime = _FakeRuntime()
        with self.assertRaises(SandboxBudgetError) as case_error:
            SandboxedAdapterRunner(case_runtime).run_replay(
                _policy(),
                _replay_request(max_cases=1),
            )
        self.assertEqual("case_limit_exceeded", case_error.exception.code)
        self.assertEqual([], case_runtime.preflights)

        expensive_runtime = _FakeRuntime(cost_usd=0.2)
        with self.assertRaises(SandboxBudgetError) as cost_error:
            SandboxedAdapterRunner(expensive_runtime).run_replay(
                _policy(),
                _replay_request(max_cost_usd=0.1),
            )
        self.assertEqual("reported_cost_limit_exceeded", cost_error.exception.code)

        duplicate_runtime = _FakeRuntime(duplicate_ids=True)
        with self.assertRaises(SandboxProtocolError) as duplicate_error:
            SandboxedAdapterRunner(duplicate_runtime).run_replay(
                _policy(),
                _replay_request(),
            )
        self.assertEqual("duplicate_outcome_identity", duplicate_error.exception.code)

    def test_timeout_cancels_the_remaining_container_names(self) -> None:
        runtime = _FakeRuntime(timeout_ref="trace://one", delay_seconds=0.1)

        with self.assertRaises(SandboxTimeoutError):
            SandboxedAdapterRunner(runtime).run_replay(
                _policy(),
                _replay_request(),
            )

        self.assertGreaterEqual(len(runtime.cancelled), 1)

    def test_provider_run_reserves_before_launch_and_uses_authoritative_cost(self) -> None:
        events: list[str] = []
        runtime = _FakeRuntime(events=events, delay_seconds=0.01)
        controller = _FakeQuotaController(
            events=events,
            lease_concurrency=2,
            actual_cost_usd=0.025,
        )
        request = _replay_request(
            refs=("trace://one", "trace://two", "trace://three"),
            max_concurrency=4,
            max_cost_usd=0.2,
        )

        result = SandboxedAdapterRunner(
            runtime,
            clock=lambda: _NOW,
        ).run_replay(
            _policy(SandboxNetworkMode.QUOTA_PROXY),
            request,
            quota_controller=controller,
        )

        self.assertEqual(["reserve", "preflight"], events[:2])
        self.assertEqual("settle", events[-1])
        reservation = controller.reservations[0]
        self.assertEqual(3, reservation.max_concurrency)
        self.assertEqual(3, reservation.max_operations)
        self.assertEqual([("lease-001", 3)], controller.settlements)
        self.assertEqual([], controller.cancellations)
        self.assertEqual(2, result.max_parallel_workers)
        self.assertAlmostEqual(0.03, result.reported_cost_usd)
        self.assertAlmostEqual(0.025, result.total_cost_usd)
        self.assertEqual(0.025, result.quota.actual_cost_usd if result.quota else None)
        for invocation in runtime.invocations:
            worker_request = parse_sandbox_worker_request(invocation.payload)
            self.assertEqual(_TOKEN, worker_request.quota.lease_token)
            self.assertEqual("quota-network", invocation.network_name)
            self.assertNotIn(_TOKEN, repr(invocation))
        self.assertNotIn(_TOKEN, repr(result))

    def test_missing_or_invalid_hard_quota_prevents_container_launch(self) -> None:
        runtime = _FakeRuntime()
        policy = _policy(SandboxNetworkMode.QUOTA_PROXY)
        runner = SandboxedAdapterRunner(runtime, clock=lambda: _NOW)

        with self.assertRaises(SandboxQuotaError) as missing:
            runner.run_replay(policy, _replay_request())
        self.assertEqual("quota_controller_required", missing.exception.code)
        self.assertEqual([], runtime.preflights)

        controller = _FakeQuotaController(operation_delta=1)
        with self.assertRaises(SandboxQuotaError) as invalid:
            runner.run_replay(
                policy,
                _replay_request(),
                quota_controller=controller,
            )
        self.assertEqual("invalid_quota_lease", invalid.exception.code)
        self.assertEqual(
            [("lease-001", "invalid_quota_lease")],
            controller.cancellations,
        )
        self.assertEqual([], runtime.preflights)

    def test_lease_window_is_rechecked_after_runtime_preflight(self) -> None:
        runtime = _FakeRuntime()
        controller = _FakeQuotaController()
        clock_values = iter((_NOW, _NOW + timedelta(minutes=9, seconds=40)))
        runner = SandboxedAdapterRunner(
            runtime,
            clock=lambda: next(clock_values),
        )

        with self.assertRaises(SandboxQuotaError) as raised:
            runner.run_replay(
                _policy(SandboxNetworkMode.QUOTA_PROXY),
                _replay_request(),
                quota_controller=controller,
            )

        self.assertEqual("quota_lease_too_short", raised.exception.code)
        self.assertEqual(
            [("lease-001", "quota_lease_too_short")],
            controller.cancellations,
        )
        self.assertEqual([], runtime.invocations)

    def test_worker_failure_cancels_provider_quota_without_settlement(self) -> None:
        runtime = _FakeRuntime(fail_ref="trace://one", delay_seconds=0.1)
        controller = _FakeQuotaController()

        with self.assertRaises(SandboxRuntimeError) as raised:
            SandboxedAdapterRunner(runtime, clock=lambda: _NOW).run_replay(
                _policy(SandboxNetworkMode.QUOTA_PROXY),
                _replay_request(),
                quota_controller=controller,
            )

        self.assertEqual("fake_worker_failed", raised.exception.code)
        self.assertEqual([], controller.settlements)
        self.assertEqual(
            [("lease-001", "fake_worker_failed")],
            controller.cancellations,
        )
        self.assertTrue(runtime.cancelled)


class DockerSandboxPlanTests(unittest.TestCase):
    def test_runtime_streams_worker_input_without_blocking_the_deadline(self) -> None:
        runtime = _LocalProcessRuntime("import time; time.sleep(5)")
        invocation = SandboxInvocation(
            container_name="causure-repl-12345678-0-cafefeed",
            policy=_policy(),
            payload=b"x" * (64 * 1024),
        )

        with self.assertRaises(SandboxTimeoutError) as raised:
            runtime.run(invocation, timeout_seconds=0.05)

        self.assertEqual("timeout_exceeded", raised.exception.code)
        self.assertEqual([invocation.container_name], runtime.cancelled)

    def test_runtime_round_trips_bounded_standard_input_and_output(self) -> None:
        runtime = _LocalProcessRuntime(
            "import sys; payload = sys.stdin.buffer.read(); sys.stdout.buffer.write(payload)"
        )
        invocation = SandboxInvocation(
            container_name="causure-repl-12345678-0-decafbad",
            policy=_policy(),
            payload=b'{"ok":true}',
        )

        output = runtime.run(invocation, timeout_seconds=2)

        self.assertEqual(invocation.payload, output)
        self.assertEqual([], runtime.cancelled)

    def test_offline_command_contains_all_hardening_flags_and_no_secret(self) -> None:
        runtime = DockerCliSandboxRuntime(("docker",))
        invocation = SandboxInvocation(
            container_name="causure-repl-12345678-0-deadbeef",
            policy=_policy(),
            payload=f'{{"lease_token":"{_TOKEN}"}}'.encode(),
        )

        command = runtime.build_run_command(invocation)

        expected_pairs = (
            ("--platform", "linux"),
            ("--pull", "never"),
            ("--network", "none"),
            ("--cap-drop", "ALL"),
            ("--security-opt", "no-new-privileges=true"),
            ("--security-opt", "seccomp=builtin"),
            ("--cgroupns", "private"),
            ("--pids-limit", "64"),
            ("--memory", "256m"),
            ("--memory-swap", "256m"),
            ("--cpus", "0.75"),
            ("--user", "65532:65532"),
            ("--workdir", "/tmp"),
            ("--log-driver", "none"),
        )
        for option, value in expected_pairs:
            with self.subTest(option=option):
                indices = [index for index, item in enumerate(command) if item == option]
                self.assertTrue(
                    any(command[index + 1] == value for index in indices),
                    (option, value, command),
                )
        self.assertIn("--read-only", command)
        self.assertIn("--rm", command)
        self.assertNotIn("--mount", command)
        self.assertNotIn("--volume", command)
        self.assertNotIn("--privileged", command)
        self.assertEqual(_IMAGE, command[-1])
        self.assertNotIn(_TOKEN, " ".join(command))
        self.assertNotIn(_TOKEN, repr(invocation))

    def test_quota_command_uses_only_the_internal_network_name(self) -> None:
        runtime = DockerCliSandboxRuntime(("docker",))
        invocation = SandboxInvocation(
            container_name="causure-repl-12345678-0-feedface",
            policy=_policy(SandboxNetworkMode.QUOTA_PROXY),
            payload=f'{{"lease_token":"{_TOKEN}"}}'.encode(),
            network_name="quota-network",
        )

        command = runtime.build_run_command(invocation)

        network_index = command.index("--network")
        self.assertEqual("quota-network", command[network_index + 1])
        self.assertNotIn(_TOKEN, " ".join(command))

    def test_preflight_rejects_declared_volumes_external_and_shared_networks(self) -> None:
        volumes_runtime = _ScriptedDockerRuntime(
            [
                b"linux\n",
                _image_inspection(volumes={"/data": {}}),
            ]
        )
        with self.assertRaises(SandboxRuntimeError) as volumes:
            volumes_runtime.preflight(_policy(), None)
        self.assertEqual("image_volumes_rejected", volumes.exception.code)

        external_runtime = _ScriptedDockerRuntime(
            [
                b"linux\n",
                _image_inspection(),
                json.dumps(
                    {
                        "Internal": False,
                        "Containers": {"proxy": {"Name": "quota-proxy"}},
                    }
                ).encode(),
            ]
        )
        with self.assertRaises(SandboxRuntimeError) as external:
            external_runtime.preflight(
                _policy(SandboxNetworkMode.QUOTA_PROXY),
                _quota_lease(),
            )
        self.assertEqual("external_network_rejected", external.exception.code)

        shared_runtime = _ScriptedDockerRuntime(
            [
                b"linux\n",
                _image_inspection(),
                json.dumps(
                    {
                        "Internal": True,
                        "Containers": {
                            "proxy": {"Name": "quota-proxy"},
                            "other": {"Name": "untrusted-neighbor"},
                        },
                    }
                ).encode(),
            ]
        )
        with self.assertRaises(SandboxRuntimeError) as shared:
            shared_runtime.preflight(
                _policy(SandboxNetworkMode.QUOTA_PROXY),
                _quota_lease(),
            )
        self.assertEqual("quota_network_not_dedicated", shared.exception.code)


if __name__ == "__main__":
    unittest.main()
