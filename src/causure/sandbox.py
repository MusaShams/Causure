"""OCI-isolated, quota-gated execution for adapter worker images."""

from __future__ import annotations

import hashlib
import json
import math
import re
import secrets
import subprocess
import threading
import time
from collections.abc import Callable, Sequence
from concurrent.futures import (
    Future,
    ThreadPoolExecutor,
    as_completed,
)
from concurrent.futures import (
    TimeoutError as FuturesTimeoutError,
)
from dataclasses import dataclass, field
from datetime import UTC, datetime, timedelta
from typing import Protocol, runtime_checkable

from causure.adapters import (
    EvaluationOutcome,
    EvaluationRequest,
    ReplayOutcome,
    ReplayRequest,
)
from causure.constants import (
    SANDBOX_WORKER_SCHEMA_VERSION,
    QuotaEnforcement,
    SandboxNetworkMode,
    SandboxWorkerMode,
)
from causure.sandbox_protocol import (
    MAX_SANDBOX_INPUT_BYTES,
    ProviderQuotaController,
    QuotaLease,
    QuotaReceipt,
    QuotaReservation,
    QuotaSettlement,
    SandboxDocumentError,
    SandboxPolicy,
    SandboxWorkerBudget,
    SandboxWorkerRequest,
    WorkerQuotaAccess,
    parse_sandbox_worker_response,
    render_sandbox_worker_request,
    timestamp_value,
)

_CONTROL_TIMEOUT_SECONDS = 10.0
_PROCESS_STOP_SECONDS = 2.0
_LEASE_MARGIN_SECONDS = 30
_READ_CHUNK_BYTES = 64 * 1024
_CANCELLATION_TOMBSTONE_SECONDS = 86_460
_CONTAINER_NAME_PATTERN = re.compile(r"^[a-z0-9][a-z0-9.-]{1,62}$")
_NETWORK_NAME_PATTERN = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_.-]{1,127}$")


class SandboxRunError(RuntimeError):
    """Base error with a stable, non-sensitive machine code."""

    def __init__(self, code: str, message: str) -> None:
        self.code = code
        super().__init__(message)


class SandboxPolicyError(SandboxRunError):
    """Raised when policy and requested execution mode are inconsistent."""


class SandboxRuntimeError(SandboxRunError):
    """Raised when the OCI runtime cannot establish or preserve isolation."""


class SandboxTimeoutError(SandboxRunError):
    """Raised when the global or per-container wall-clock budget is exceeded."""


class SandboxProtocolError(SandboxRunError):
    """Raised when a worker image violates its standard-input/output protocol."""


class SandboxQuotaError(SandboxRunError):
    """Raised when a hard quota cannot be reserved, settled, or cancelled."""


class SandboxBudgetError(SandboxRunError):
    """Raised when request, outcome, or accounting limits are exceeded."""


@dataclass(frozen=True, slots=True)
class SandboxInvocation:
    """One pre-named container invocation containing one evidence reference."""

    container_name: str
    policy: SandboxPolicy
    payload: bytes = field(repr=False)
    network_name: str | None = None

    def __post_init__(self) -> None:
        if not isinstance(self.container_name, str) or not _CONTAINER_NAME_PATTERN.fullmatch(
            self.container_name
        ):
            raise ValueError("container_name must be a valid lowercase container name")
        if not isinstance(self.policy, SandboxPolicy):
            raise ValueError("policy must be a SandboxPolicy")
        if not isinstance(self.payload, bytes) or not self.payload:
            raise ValueError("payload must contain worker request bytes")
        if len(self.payload) > MAX_SANDBOX_INPUT_BYTES:
            raise ValueError(f"payload must not exceed {MAX_SANDBOX_INPUT_BYTES} bytes")
        if self.policy.network_mode is SandboxNetworkMode.NONE:
            if self.network_name is not None:
                raise ValueError("network-disabled invocation must not name a network")
        elif not isinstance(self.network_name, str) or not _NETWORK_NAME_PATTERN.fullmatch(
            self.network_name
        ):
            raise ValueError("quota-proxy invocation requires a valid network name")


@dataclass(frozen=True, slots=True)
class SandboxReplayRunResult:
    case_id: str
    total_cost_usd: float
    reported_cost_usd: float
    max_parallel_workers: int
    outcomes: tuple[ReplayOutcome, ...]
    quota: QuotaReceipt | None


@dataclass(frozen=True, slots=True)
class SandboxEvaluationRunResult:
    case_id: str
    total_cost_usd: float
    reported_cost_usd: float
    max_parallel_workers: int
    outcomes: tuple[EvaluationOutcome, ...]
    quota: QuotaReceipt | None


@runtime_checkable
class SandboxRuntime(Protocol):
    """Trusted backend that applies an OS/container isolation policy."""

    def preflight(
        self,
        policy: SandboxPolicy,
        lease: QuotaLease | None,
    ) -> None: ...

    def run(self, invocation: SandboxInvocation, *, timeout_seconds: float) -> bytes: ...

    def cancel(self, container_name: str) -> bool: ...


class _BoundedPipeReader(threading.Thread):
    def __init__(self, pipe, *, limit: int, overflow: threading.Event) -> None:
        super().__init__(daemon=True)
        self._pipe = pipe
        self._limit = limit
        self._overflow = overflow
        self._parts: list[bytes] = []
        self._total = 0
        self._stored = 0
        self.error: Exception | None = None

    @property
    def content(self) -> bytes:
        return b"".join(self._parts)

    def run(self) -> None:
        try:
            while True:
                chunk = self._pipe.read(_READ_CHUNK_BYTES)
                if not chunk:
                    break
                self._total += len(chunk)
                remaining = max(0, self._limit + 1 - self._stored)
                if remaining:
                    retained = chunk[:remaining]
                    self._parts.append(retained)
                    self._stored += len(retained)
                if self._total > self._limit:
                    self._overflow.set()
        except (OSError, ValueError) as exc:
            self.error = exc
        finally:
            try:
                self._pipe.close()
            except (OSError, ValueError) as exc:
                if self.error is None:
                    self.error = exc


class _PipeWriter(threading.Thread):
    def __init__(self, pipe, payload: bytes) -> None:
        super().__init__(daemon=True)
        self._pipe = pipe
        self._payload = payload
        self.error: Exception | None = None
        self.done = threading.Event()

    def run(self) -> None:
        try:
            written = self._pipe.write(self._payload)
            self._pipe.flush()
            if written != len(self._payload):
                raise OSError("worker input pipe accepted only a partial request")
        except (BrokenPipeError, OSError, ValueError) as exc:
            self.error = exc
        finally:
            try:
                self._pipe.close()
            except (OSError, ValueError) as exc:
                if self.error is None:
                    self.error = exc
            self.done.set()


class DockerCliSandboxRuntime:
    """Execute digest-pinned Linux images through a hardened Docker CLI plan."""

    def __init__(self, runtime_command: Sequence[str] = ("docker",)) -> None:
        command = tuple(runtime_command)
        if not command or any(not isinstance(item, str) or not item for item in command):
            raise ValueError("runtime_command must contain non-empty command arguments")
        self._runtime_command = command
        self._state_lock = threading.Lock()
        self._active_processes: dict[str, subprocess.Popen[bytes]] = {}
        self._cancelled_names: dict[str, float] = {}

    def _prune_cancellations_locked(self, now: float) -> None:
        expired = [
            name
            for name, cancelled_at in self._cancelled_names.items()
            if now - cancelled_at > _CANCELLATION_TOMBSTONE_SECONDS
        ]
        for name in expired:
            del self._cancelled_names[name]

    def _control(
        self,
        arguments: Sequence[str],
        *,
        timeout_seconds: float = _CONTROL_TIMEOUT_SECONDS,
    ) -> bytes:
        try:
            completed = subprocess.run(
                [*self._runtime_command, *arguments],
                stdin=subprocess.DEVNULL,
                capture_output=True,
                check=False,
                timeout=timeout_seconds,
            )
        except FileNotFoundError as exc:
            raise SandboxRuntimeError(
                "runtime_unavailable",
                "Docker CLI is not installed or not on the configured path",
            ) from exc
        except (OSError, subprocess.TimeoutExpired) as exc:
            raise SandboxRuntimeError(
                "runtime_control_failed",
                "Docker control command did not complete",
            ) from exc
        if completed.returncode != 0:
            raise SandboxRuntimeError(
                "runtime_control_failed",
                "Docker control command failed",
            )
        if len(completed.stdout) > 1024 * 1024:
            raise SandboxRuntimeError(
                "runtime_control_output_exceeded",
                "Docker control output exceeded its limit",
            )
        return completed.stdout

    def preflight(
        self,
        policy: SandboxPolicy,
        lease: QuotaLease | None,
    ) -> None:
        """Verify Linux runtime, local image digest, and optional internal network."""

        try:
            server_os = (
                self._control(
                    ("version", "--format", "{{.Server.Os}}"),
                )
                .decode("utf-8", errors="strict")
                .strip()
            )
        except UnicodeDecodeError as exc:
            raise SandboxRuntimeError(
                "runtime_control_output_invalid",
                "Docker control output was not valid UTF-8",
            ) from exc
        if server_os != "linux":
            raise SandboxRuntimeError(
                "linux_runtime_required",
                "sandbox policy requires a Linux container runtime",
            )

        raw_image = self._control(
            (
                "image",
                "inspect",
                policy.image,
                "--format",
                "{{json .}}",
            )
        )
        try:
            image = json.loads(raw_image)
        except (UnicodeDecodeError, json.JSONDecodeError) as exc:
            raise SandboxRuntimeError(
                "image_inspect_invalid",
                "Docker image inspection returned invalid data",
            ) from exc
        if not isinstance(image, dict):
            raise SandboxRuntimeError(
                "image_inspect_invalid",
                "Docker image inspection did not return an object",
            )
        repo_digests = image.get("RepoDigests")
        requested_digest = policy.image.rsplit("@", maxsplit=1)[1]
        if not isinstance(repo_digests, list) or not any(
            isinstance(item, str) and item.endswith(f"@{requested_digest}") for item in repo_digests
        ):
            raise SandboxRuntimeError(
                "image_digest_unavailable",
                "the exact digest-pinned worker image is not available locally",
            )
        if image.get("Os") != "linux":
            raise SandboxRuntimeError(
                "linux_image_required",
                "sandbox policy requires a Linux worker image",
            )
        image_config = image.get("Config")
        if not isinstance(image_config, dict):
            raise SandboxRuntimeError(
                "image_inspect_invalid",
                "Docker image configuration is missing",
            )
        declared_volumes = image_config.get("Volumes")
        if declared_volumes not in (None, {}):
            raise SandboxRuntimeError(
                "image_volumes_rejected",
                "worker images must not declare writable volumes",
            )

        if policy.network_mode is SandboxNetworkMode.NONE:
            if lease is not None:
                raise SandboxRuntimeError(
                    "unexpected_network_lease",
                    "network-disabled policy must not receive a quota lease",
                )
            return
        if lease is None:
            raise SandboxRuntimeError(
                "quota_lease_required",
                "quota-proxy policy requires a provider quota lease",
            )

        raw_network = self._control(
            (
                "network",
                "inspect",
                lease.network_name,
                "--format",
                "{{json .}}",
            )
        )
        try:
            network = json.loads(raw_network)
        except (UnicodeDecodeError, json.JSONDecodeError) as exc:
            raise SandboxRuntimeError(
                "network_inspect_invalid",
                "Docker network inspection returned invalid data",
            ) from exc
        if not isinstance(network, dict) or network.get("Internal") is not True:
            raise SandboxRuntimeError(
                "external_network_rejected",
                "quota-proxy network must be marked internal",
            )
        containers = network.get("Containers")
        if containers is None:
            containers = {}
        if not isinstance(containers, dict):
            raise SandboxRuntimeError(
                "network_inspect_invalid",
                "Docker network container inventory is invalid",
            )
        if any(
            not isinstance(value, dict) or not isinstance(value.get("Name"), str)
            for value in containers.values()
        ):
            raise SandboxRuntimeError(
                "network_inspect_invalid",
                "Docker network container inventory contains an invalid entry",
            )
        connected_names = {value["Name"] for value in containers.values()}
        if connected_names != {lease.proxy_container_name}:
            raise SandboxRuntimeError(
                "quota_network_not_dedicated",
                "quota-proxy network must contain only the named proxy before launch",
            )

    def build_run_command(self, invocation: SandboxInvocation) -> tuple[str, ...]:
        """Build the no-shell Docker command applied to one worker."""

        policy = invocation.policy
        network = (
            "none" if policy.network_mode is SandboxNetworkMode.NONE else invocation.network_name
        )
        if not network:
            raise SandboxPolicyError(
                "network_name_required",
                "quota-proxy invocation requires a network name",
            )
        cpu_limit = f"{policy.cpu_limit:.3f}".rstrip("0").rstrip(".")
        return (
            *self._runtime_command,
            "container",
            "run",
            "--rm",
            "--interactive",
            "--init",
            "--name",
            invocation.container_name,
            "--platform",
            "linux",
            "--pull",
            "never",
            "--network",
            network,
            "--read-only",
            "--cap-drop",
            "ALL",
            "--security-opt",
            "no-new-privileges=true",
            "--security-opt",
            "seccomp=builtin",
            "--cgroupns",
            "private",
            "--pids-limit",
            str(policy.pids_limit),
            "--memory",
            f"{policy.memory_mb}m",
            "--memory-swap",
            f"{policy.memory_mb}m",
            "--cpus",
            cpu_limit,
            "--user",
            policy.user,
            "--tmpfs",
            f"/tmp:rw,noexec,nosuid,nodev,size={policy.tmpfs_mb}m",
            "--workdir",
            "/tmp",
            "--ulimit",
            "core=0:0",
            "--ulimit",
            "nofile=128:128",
            "--log-driver",
            "none",
            "--stop-timeout",
            "1",
            policy.image,
        )

    def cancel(self, container_name: str) -> bool:
        """Suppress launch, force-remove a container, and confirm that it is absent."""

        if not isinstance(container_name, str) or not _CONTAINER_NAME_PATTERN.fullmatch(
            container_name
        ):
            raise ValueError("container_name must be a valid lowercase container name")
        now = time.monotonic()
        with self._state_lock:
            self._prune_cancellations_locked(now)
            self._cancelled_names[container_name] = now
            active_process = self._active_processes.get(container_name)

        deadline = now + _CONTROL_TIMEOUT_SECONDS
        while time.monotonic() < deadline:
            remaining = max(0.05, min(1.0, deadline - time.monotonic()))
            try:
                removed = subprocess.run(
                    [
                        *self._runtime_command,
                        "container",
                        "rm",
                        "--force",
                        container_name,
                    ],
                    stdin=subprocess.DEVNULL,
                    stdout=subprocess.DEVNULL,
                    stderr=subprocess.DEVNULL,
                    check=False,
                    timeout=remaining,
                )
                if removed.returncode == 0:
                    return True
                listed = subprocess.run(
                    [
                        *self._runtime_command,
                        "container",
                        "ls",
                        "--all",
                        "--quiet",
                        "--filter",
                        f"name=^/{container_name}$",
                    ],
                    stdin=subprocess.DEVNULL,
                    capture_output=True,
                    check=False,
                    timeout=remaining,
                )
            except (OSError, subprocess.TimeoutExpired):
                return False
            if listed.returncode != 0:
                return False
            if listed.stdout.strip():
                continue
            if active_process is None or active_process.poll() is not None:
                return True
            time.sleep(0.01)
        return False

    def run(self, invocation: SandboxInvocation, *, timeout_seconds: float) -> bytes:
        """Run one container while bounding wall time and stdout/stderr memory."""

        if not math.isfinite(timeout_seconds) or timeout_seconds <= 0:
            raise SandboxTimeoutError(
                "timeout_exceeded",
                "no wall-clock budget remains for the worker",
            )
        command = self.build_run_command(invocation)
        with self._state_lock:
            now = time.monotonic()
            self._prune_cancellations_locked(now)
            if invocation.container_name in self._cancelled_names:
                raise SandboxRuntimeError(
                    "execution_cancelled",
                    "worker launch was cancelled before the container started",
                )
            if invocation.container_name in self._active_processes:
                raise SandboxRuntimeError(
                    "duplicate_container_name",
                    "worker container name is already active",
                )
            try:
                process = subprocess.Popen(
                    command,
                    stdin=subprocess.PIPE,
                    stdout=subprocess.PIPE,
                    stderr=subprocess.PIPE,
                )
            except FileNotFoundError as exc:
                raise SandboxRuntimeError(
                    "runtime_unavailable",
                    "Docker CLI is not installed or not on the configured path",
                ) from exc
            except OSError as exc:
                raise SandboxRuntimeError(
                    "container_not_startable",
                    "Docker worker process could not be started",
                ) from exc
            self._active_processes[invocation.container_name] = process

        if process.stdout is None or process.stderr is None or process.stdin is None:
            self.cancel(invocation.container_name)
            process.kill()
            with self._state_lock:
                self._active_processes.pop(invocation.container_name, None)
            raise SandboxRuntimeError(
                "container_pipe_failed",
                "Docker worker pipes could not be created",
            )
        overflow = threading.Event()
        stdout_reader = _BoundedPipeReader(
            process.stdout,
            limit=invocation.policy.max_output_bytes,
            overflow=overflow,
        )
        stderr_reader = _BoundedPipeReader(
            process.stderr,
            limit=invocation.policy.max_output_bytes,
            overflow=overflow,
        )
        input_writer = _PipeWriter(process.stdin, invocation.payload)
        pipe_threads = (input_writer, stdout_reader, stderr_reader)
        deadline = time.monotonic() + timeout_seconds
        failure: SandboxRunError | None = None
        failure_cause: Exception | None = None
        try:
            for pipe_thread in pipe_threads:
                pipe_thread.start()

            while failure is None and process.poll() is None:
                if input_writer.done.is_set() and input_writer.error is not None:
                    failure = SandboxRuntimeError(
                        "container_input_failed",
                        "worker container did not accept its request",
                    )
                    failure_cause = input_writer.error
                elif overflow.is_set():
                    failure = SandboxProtocolError(
                        "worker_output_limit_exceeded",
                        "worker output exceeded the configured byte limit",
                    )
                    break
                if time.monotonic() >= deadline:
                    failure = SandboxTimeoutError(
                        "timeout_exceeded",
                        "worker container exceeded its wall-clock timeout",
                    )
                    break
                time.sleep(0.01)

            if failure is not None:
                removed = self.cancel(invocation.container_name)
                if process.poll() is None:
                    process.kill()
                try:
                    process.wait(_PROCESS_STOP_SECONDS)
                except subprocess.TimeoutExpired:
                    process.kill()
                    process.wait(_PROCESS_STOP_SECONDS)
                for pipe_thread in pipe_threads:
                    pipe_thread.join(_PROCESS_STOP_SECONDS)
                if not removed:
                    raise SandboxRuntimeError(
                        "sandbox_cleanup_unconfirmed",
                        "worker isolation cleanup could not be confirmed",
                    ) from failure
                if any(pipe_thread.is_alive() for pipe_thread in pipe_threads):
                    raise SandboxRuntimeError(
                        "container_pipe_failed",
                        "worker pipes did not close after cleanup",
                    ) from failure
                if failure_cause is not None:
                    raise failure from failure_cause
                raise failure

            return_code = process.wait()
            for pipe_thread in pipe_threads:
                pipe_thread.join(_PROCESS_STOP_SECONDS)
            if any(pipe_thread.is_alive() for pipe_thread in pipe_threads):
                raise SandboxRuntimeError(
                    "container_pipe_failed",
                    "worker pipes did not close",
                )
            if input_writer.error is not None:
                raise SandboxRuntimeError(
                    "container_input_failed",
                    "worker container did not accept its request",
                ) from input_writer.error
            pipe_error = stdout_reader.error or stderr_reader.error
            if pipe_error is not None:
                raise SandboxRuntimeError(
                    "container_pipe_failed",
                    "worker output pipe failed",
                ) from pipe_error
            if overflow.is_set():
                raise SandboxProtocolError(
                    "worker_output_limit_exceeded",
                    "worker output exceeded the configured byte limit",
                )
            if return_code != 0:
                raise SandboxRuntimeError(
                    "container_failed",
                    "worker container returned a non-zero status",
                )
            output = stdout_reader.content
            if not output:
                raise SandboxProtocolError(
                    "empty_worker_output",
                    "worker container returned no response",
                )
            return output
        finally:
            cleanup_confirmed = True
            pipes_closed = True
            try:
                if process.poll() is None:
                    cleanup_confirmed = self.cancel(invocation.container_name)
                    process.kill()
                    try:
                        process.wait(_PROCESS_STOP_SECONDS)
                    except subprocess.TimeoutExpired:
                        pass
                for pipe_thread in pipe_threads:
                    if pipe_thread.ident is not None:
                        pipe_thread.join(_PROCESS_STOP_SECONDS)
                    if pipe_thread.is_alive():
                        pipes_closed = False
            finally:
                with self._state_lock:
                    self._active_processes.pop(invocation.container_name, None)
            if not cleanup_confirmed:
                raise SandboxRuntimeError(
                    "sandbox_cleanup_unconfirmed",
                    "worker isolation cleanup could not be confirmed",
                )
            if not pipes_closed:
                raise SandboxRuntimeError(
                    "container_pipe_failed",
                    "worker pipes did not close after cleanup",
                )


def _reported_cost(outcomes: Sequence[ReplayOutcome | EvaluationOutcome]) -> float:
    try:
        total = math.fsum(outcome.cost_usd for outcome in outcomes)
    except OverflowError as exc:
        raise SandboxBudgetError(
            "reported_cost_overflow",
            "worker-reported cost is outside the finite numeric range",
        ) from exc
    if not math.isfinite(total):
        raise SandboxBudgetError(
            "reported_cost_overflow",
            "worker-reported cost is outside the finite numeric range",
        )
    return total


class SandboxedAdapterRunner:
    """Schedule one reference per isolated worker with optional hard quota leases."""

    def __init__(
        self,
        runtime: SandboxRuntime | None = None,
        *,
        clock: Callable[[], datetime] | None = None,
    ) -> None:
        self._runtime = runtime or DockerCliSandboxRuntime()
        self._clock = clock or (lambda: datetime.now(UTC))

    def _minimum_lease_expiration(
        self,
        request: ReplayRequest | EvaluationRequest,
    ) -> datetime:
        try:
            now = self._clock()
            if not isinstance(now, datetime) or now.tzinfo is None or now.utcoffset() is None:
                raise SandboxQuotaError(
                    "invalid_clock",
                    "sandbox runner clock must return a timezone-aware datetime",
                )
            return now.astimezone(UTC) + timedelta(
                seconds=request.budget.timeout_seconds + _LEASE_MARGIN_SECONDS
            )
        except SandboxQuotaError:
            raise
        except Exception as exc:
            raise SandboxQuotaError(
                "invalid_clock",
                "sandbox runner clock could not provide a valid time",
            ) from exc

    def _validate_lease_window(
        self,
        request: ReplayRequest | EvaluationRequest,
        lease: QuotaLease,
    ) -> None:
        if timestamp_value(lease.expires_at) < self._minimum_lease_expiration(request):
            raise SandboxQuotaError(
                "quota_lease_too_short",
                "quota lease does not cover the execution deadline and cleanup margin",
            )

    def _reserve_quota(
        self,
        policy: SandboxPolicy,
        request: ReplayRequest | EvaluationRequest,
        reference_count: int,
        controller: ProviderQuotaController | None,
    ) -> QuotaLease | None:
        if policy.network_mode is SandboxNetworkMode.NONE:
            if controller is not None:
                raise SandboxPolicyError(
                    "unexpected_quota_controller",
                    "network-disabled policy must not receive a quota controller",
                )
            return None
        if controller is None or not isinstance(controller, ProviderQuotaController):
            raise SandboxQuotaError(
                "quota_controller_required",
                "quota-proxy policy requires a provider quota controller",
            )
        if request.budget.max_cost_usd is None:
            raise SandboxQuotaError(
                "hard_cost_limit_required",
                "quota-proxy execution requires max_cost_usd",
            )
        reservation = QuotaReservation(
            case_id=request.case_id,
            max_cost_usd=request.budget.max_cost_usd,
            max_concurrency=min(request.budget.max_concurrency, reference_count),
            max_operations=reference_count,
            timeout_seconds=request.budget.timeout_seconds,
        )
        try:
            lease = controller.reserve(reservation)
        except Exception as exc:
            raise SandboxQuotaError(
                "quota_reservation_failed",
                "provider hard quota could not be reserved",
            ) from exc
        if not isinstance(lease, QuotaLease):
            raise SandboxQuotaError(
                "invalid_quota_lease",
                "quota controller returned an invalid lease",
            )
        try:
            if lease.enforcement is not QuotaEnforcement.PROVIDER_HARD_LIMIT:
                raise SandboxQuotaError(
                    "invalid_quota_lease",
                    "quota lease does not enforce a provider hard limit",
                )
            if lease.max_cost_usd > reservation.max_cost_usd:
                raise SandboxQuotaError(
                    "invalid_quota_lease",
                    "quota lease exceeds the requested cost limit",
                )
            if not 1 <= lease.max_concurrency <= reservation.max_concurrency:
                raise SandboxQuotaError(
                    "invalid_quota_lease",
                    "quota lease concurrency exceeds the request",
                )
            if lease.max_operations != reference_count:
                raise SandboxQuotaError(
                    "invalid_quota_lease",
                    "quota lease operation count must exactly match the request",
                )
            self._validate_lease_window(request, lease)
        except SandboxQuotaError as exc:
            self._cancel_quota(controller, lease, exc.code)
            raise
        return lease

    @staticmethod
    def _container_name(
        mode: SandboxWorkerMode,
        case_id: str,
        index: int,
    ) -> str:
        case_hash = hashlib.sha256(case_id.encode("utf-8")).hexdigest()[:8]
        return f"causure-{mode.value[:4]}-{case_hash}-{index}-{secrets.token_hex(4)}"

    def _worker_request(
        self,
        mode: SandboxWorkerMode,
        request: ReplayRequest | EvaluationRequest,
        input_ref: str,
        lease: QuotaLease | None,
        timeout_seconds: float,
    ) -> SandboxWorkerRequest:
        quota = (
            WorkerQuotaAccess(
                lease_id=lease.lease_id,
                lease_token=lease.lease_token,
                proxy_url=lease.proxy_url,
            )
            if lease is not None
            else None
        )
        budget = SandboxWorkerBudget(
            timeout_seconds=timeout_seconds,
            max_concurrency=1,
            max_cases=1,
            max_cost_usd=(lease.max_cost_usd if lease is not None else request.budget.max_cost_usd),
        )
        if mode is SandboxWorkerMode.REPLAY:
            if not isinstance(request, ReplayRequest):
                raise SandboxProtocolError(
                    "invalid_replay_request",
                    "replay mode requires ReplayRequest",
                )
            return SandboxWorkerRequest(
                schema_version=SANDBOX_WORKER_SCHEMA_VERSION,
                mode=mode,
                case_id=request.case_id,
                input_ref=input_ref,
                budget=budget,
                baseline_ref=request.baseline_ref,
                candidate_ref=request.candidate_ref,
                seed=request.seed,
                quota=quota,
            )
        if not isinstance(request, EvaluationRequest):
            raise SandboxProtocolError(
                "invalid_evaluation_request",
                "evaluation mode requires EvaluationRequest",
            )
        return SandboxWorkerRequest(
            schema_version=SANDBOX_WORKER_SCHEMA_VERSION,
            mode=mode,
            case_id=request.case_id,
            input_ref=input_ref,
            budget=budget,
            evaluator_ref=request.evaluator_ref,
            quota=quota,
        )

    def _cancel_containers(self, names: Sequence[str]) -> None:
        failed = False
        for name in names:
            try:
                if not self._runtime.cancel(name):
                    failed = True
            except Exception:
                failed = True
        if failed:
            raise SandboxRuntimeError(
                "sandbox_cleanup_unconfirmed",
                "one or more worker cancellations could not be confirmed",
            )

    @staticmethod
    def _cancel_quota(
        controller: ProviderQuotaController,
        lease: QuotaLease,
        reason_code: str,
    ) -> None:
        try:
            controller.cancel(lease.lease_id, reason_code=reason_code)
        except Exception as exc:
            raise SandboxQuotaError(
                "quota_cancellation_failed",
                "provider quota lease cancellation could not be confirmed",
            ) from exc

    def _run_one(
        self,
        mode: SandboxWorkerMode,
        request: ReplayRequest | EvaluationRequest,
        policy: SandboxPolicy,
        input_ref: str,
        container_name: str,
        lease: QuotaLease | None,
        deadline: float,
        stopped: threading.Event,
    ) -> ReplayOutcome | EvaluationOutcome:
        if stopped.is_set():
            raise SandboxRuntimeError(
                "execution_cancelled",
                "worker launch was cancelled after another worker failed",
            )
        remaining = deadline - time.monotonic()
        if remaining <= 0:
            raise SandboxTimeoutError(
                "timeout_exceeded",
                "sandbox execution exceeded its global wall-clock timeout",
            )
        worker_request = self._worker_request(
            mode,
            request,
            input_ref,
            lease,
            remaining,
        )
        invocation = SandboxInvocation(
            container_name=container_name,
            policy=policy,
            payload=render_sandbox_worker_request(worker_request),
            network_name=lease.network_name if lease is not None else None,
        )
        output = self._runtime.run(invocation, timeout_seconds=remaining)
        try:
            return parse_sandbox_worker_response(
                output,
                expected_mode=mode,
                expected_case_id=request.case_id,
                expected_input_ref=input_ref,
                max_bytes=policy.max_output_bytes,
            )
        except SandboxDocumentError as exc:
            raise SandboxProtocolError(
                "invalid_worker_response",
                "worker returned a malformed or mismatched response",
            ) from exc

    def _execute_workers(
        self,
        mode: SandboxWorkerMode,
        request: ReplayRequest | EvaluationRequest,
        policy: SandboxPolicy,
        references: tuple[str, ...],
        lease: QuotaLease | None,
    ) -> tuple[tuple[ReplayOutcome | EvaluationOutcome, ...], int]:
        max_workers = min(
            len(references),
            request.budget.max_concurrency,
            lease.max_concurrency if lease is not None else request.budget.max_concurrency,
        )
        names = tuple(
            self._container_name(mode, request.case_id, index) for index in range(len(references))
        )
        stopped = threading.Event()
        deadline = time.monotonic() + request.budget.timeout_seconds
        executor = ThreadPoolExecutor(
            max_workers=max_workers,
            thread_name_prefix="causure-sandbox",
        )
        futures: dict[Future[ReplayOutcome | EvaluationOutcome], int] = {}
        results: list[ReplayOutcome | EvaluationOutcome | None] = [None] * len(references)
        try:
            for index, input_ref in enumerate(references):
                future = executor.submit(
                    self._run_one,
                    mode,
                    request,
                    policy,
                    input_ref,
                    names[index],
                    lease,
                    deadline,
                    stopped,
                )
                futures[future] = index
            try:
                for future in as_completed(
                    futures,
                    timeout=max(0.0, deadline - time.monotonic()),
                ):
                    results[futures[future]] = future.result()
            except FuturesTimeoutError as exc:
                raise SandboxTimeoutError(
                    "timeout_exceeded",
                    "sandbox execution exceeded its global wall-clock timeout",
                ) from exc
            if any(result is None for result in results):
                raise SandboxRuntimeError(
                    "worker_result_missing",
                    "one or more sandbox workers returned no result",
                )
            return tuple(result for result in results if result is not None), max_workers
        except Exception:
            stopped.set()
            active_names = []
            for future, index in futures.items():
                if future.cancel():
                    continue
                if not future.done():
                    active_names.append(names[index])
            self._cancel_containers(active_names)
            raise
        finally:
            executor.shutdown(wait=True, cancel_futures=True)

    def _settle_quota(
        self,
        controller: ProviderQuotaController,
        lease: QuotaLease,
        *,
        completed_operations: int,
        budget_cost: float,
    ) -> QuotaReceipt:
        try:
            settlement = controller.settle(
                lease.lease_id,
                completed_operations=completed_operations,
            )
        except Exception as exc:
            raise SandboxQuotaError(
                "quota_settlement_failed",
                "provider quota lease could not be settled and revoked",
            ) from exc
        if not isinstance(settlement, QuotaSettlement):
            raise SandboxQuotaError(
                "invalid_quota_settlement",
                "quota controller returned an invalid settlement",
            )
        if settlement.lease_id != lease.lease_id:
            raise SandboxQuotaError(
                "invalid_quota_settlement",
                "quota settlement does not match the reserved lease",
            )
        if settlement.completed_operations != completed_operations:
            raise SandboxQuotaError(
                "invalid_quota_settlement",
                "quota settlement operation count does not match completed work",
            )
        if (
            settlement.actual_cost_usd > lease.max_cost_usd
            or settlement.actual_cost_usd > budget_cost
        ):
            raise SandboxQuotaError(
                "quota_enforcement_failed",
                "provider settlement exceeded a hard cost limit",
            )
        return QuotaReceipt(
            lease_id=lease.lease_id,
            enforcement=lease.enforcement,
            expires_at=lease.expires_at,
            max_cost_usd=lease.max_cost_usd,
            max_concurrency=lease.max_concurrency,
            max_operations=lease.max_operations,
            actual_cost_usd=settlement.actual_cost_usd,
            completed_operations=settlement.completed_operations,
        )

    def _run(
        self,
        mode: SandboxWorkerMode,
        request: ReplayRequest | EvaluationRequest,
        policy: SandboxPolicy,
        controller: ProviderQuotaController | None,
    ) -> tuple[
        tuple[ReplayOutcome | EvaluationOutcome, ...],
        float,
        float,
        int,
        QuotaReceipt | None,
    ]:
        if not isinstance(policy, SandboxPolicy):
            raise SandboxPolicyError(
                "invalid_sandbox_policy",
                "policy must be a SandboxPolicy",
            )
        references = (
            request.trace_refs if isinstance(request, ReplayRequest) else request.replay_refs
        )
        if len(references) > request.budget.max_cases:
            raise SandboxBudgetError(
                "case_limit_exceeded",
                "request contains more references than the case budget allows",
            )

        lease: QuotaLease | None = None
        try:
            lease = self._reserve_quota(
                policy,
                request,
                len(references),
                controller,
            )
            self._runtime.preflight(policy, lease)
            if lease is not None:
                self._validate_lease_window(request, lease)
            outcomes, max_workers = self._execute_workers(
                mode,
                request,
                policy,
                references,
                lease,
            )
            identities = [
                (
                    outcome.trial_id
                    if isinstance(outcome, ReplayOutcome)
                    else outcome.validation_case_id
                )
                for outcome in outcomes
            ]
            if len(set(identities)) != len(identities):
                raise SandboxProtocolError(
                    "duplicate_outcome_identity",
                    "sandbox worker outcome identities must be unique",
                )
            reported_cost = _reported_cost(outcomes)
            if (
                request.budget.max_cost_usd is not None
                and reported_cost > request.budget.max_cost_usd
            ):
                raise SandboxBudgetError(
                    "reported_cost_limit_exceeded",
                    "worker-reported cost exceeds the configured budget",
                )
            quota_receipt = None
            total_cost = reported_cost
            if lease is not None:
                if controller is None or request.budget.max_cost_usd is None:
                    raise SandboxQuotaError(
                        "quota_controller_required",
                        "quota controller became unavailable before settlement",
                    )
                quota_receipt = self._settle_quota(
                    controller,
                    lease,
                    completed_operations=len(outcomes),
                    budget_cost=request.budget.max_cost_usd,
                )
                total_cost = quota_receipt.actual_cost_usd
            return (
                outcomes,
                total_cost,
                reported_cost,
                max_workers,
                quota_receipt,
            )
        except SandboxRunError as exc:
            if lease is not None and controller is not None:
                self._cancel_quota(controller, lease, exc.code)
            raise
        except Exception as exc:
            if lease is not None and controller is not None:
                self._cancel_quota(controller, lease, "sandbox_execution_failed")
            raise SandboxRuntimeError(
                "sandbox_execution_failed",
                "sandbox execution failed without a valid result",
            ) from exc

    def run_replay(
        self,
        policy: SandboxPolicy,
        request: ReplayRequest,
        *,
        quota_controller: ProviderQuotaController | None = None,
    ) -> SandboxReplayRunResult:
        """Run each trace reference in an independently bounded container."""

        if not isinstance(request, ReplayRequest):
            raise SandboxProtocolError(
                "invalid_replay_request",
                "request must be a ReplayRequest",
            )
        outcomes, total, reported, workers, quota = self._run(
            SandboxWorkerMode.REPLAY,
            request,
            policy,
            quota_controller,
        )
        if any(not isinstance(outcome, ReplayOutcome) for outcome in outcomes):
            raise SandboxProtocolError(
                "invalid_replay_result",
                "sandbox runner returned an invalid replay result",
            )
        return SandboxReplayRunResult(
            case_id=request.case_id,
            total_cost_usd=total,
            reported_cost_usd=reported,
            max_parallel_workers=workers,
            outcomes=tuple(outcome for outcome in outcomes if isinstance(outcome, ReplayOutcome)),
            quota=quota,
        )

    def run_evaluation(
        self,
        policy: SandboxPolicy,
        request: EvaluationRequest,
        *,
        quota_controller: ProviderQuotaController | None = None,
    ) -> SandboxEvaluationRunResult:
        """Run each replay reference in an independently bounded container."""

        if not isinstance(request, EvaluationRequest):
            raise SandboxProtocolError(
                "invalid_evaluation_request",
                "request must be an EvaluationRequest",
            )
        outcomes, total, reported, workers, quota = self._run(
            SandboxWorkerMode.EVALUATION,
            request,
            policy,
            quota_controller,
        )
        if any(not isinstance(outcome, EvaluationOutcome) for outcome in outcomes):
            raise SandboxProtocolError(
                "invalid_evaluation_result",
                "sandbox runner returned an invalid evaluation result",
            )
        return SandboxEvaluationRunResult(
            case_id=request.case_id,
            total_cost_usd=total,
            reported_cost_usd=reported,
            max_parallel_workers=workers,
            outcomes=tuple(
                outcome for outcome in outcomes if isinstance(outcome, EvaluationOutcome)
            ),
            quota=quota,
        )
