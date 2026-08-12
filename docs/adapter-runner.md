# Process-bounded adapter runner

`ProcessAdapterRunner` invokes company-owned replay and evaluator implementations in a
spawned child process. It adds a killable wall-clock boundary and validates the accounting
contract before results can enter evidence assembly.

The runner is intended for trusted integration code. It does not execute commands or load
adapter implementations named by an evidence file.

## Minimal replay example

Define adapters at module scope so Python can import and pickle them when using the `spawn`
start method:

```python
from causure import (
    ExecutionBudget,
    ProcessAdapterRunner,
    ReplayOutcome,
    ReplayRequest,
)


class CompanyReplayAdapter:
    def replay(self, request: ReplayRequest) -> tuple[ReplayOutcome, ...]:
        return (
            ReplayOutcome(
                trial_id="refund-replay-01",
                reproduced=True,
                evidence_ref="artifact://replays/refund-replay-01",
                latency_ms=842.0,
                cost_usd=0.014,
            ),
        )


if __name__ == "__main__":
    source_hash = "a" * 64
    trace_hash = "b" * 64
    request = ReplayRequest(
        case_id="refund-incident-01",
        trace_refs=(f"trace-sha256://{source_hash}/traces/{trace_hash}",),
        baseline_ref="agent://refund/v17",
        candidate_ref="agent://refund/v18",
        seed=7,
        budget=ExecutionBudget(
            timeout_seconds=30,
            max_concurrency=1,
            max_cases=1,
            max_cost_usd=0.05,
        ),
    )
    result = ProcessAdapterRunner().run_replay(CompanyReplayAdapter(), request)
    print(result.total_cost_usd)
```

Windows scripts and executable entry points need the normal
`if __name__ == "__main__"` guard. Adapters and their state must be importable and
picklable; closures, lambdas, and interactive-only definitions are not portable inputs.

`run_evaluation` follows the same pattern with `EvaluationRequest` and
`EvaluationOutcome`. Both replay and evaluation outcomes must report non-negative finite
`latency_ms` and `cost_usd`.

## Enforced by the runner

- A wall-clock deadline from `timeout_seconds`; an overrun is terminated and then killed if
  necessary.
- Input-reference and returned-outcome limits from `max_cases`.
- Non-empty outcome sequences with the expected immutable outcome type.
- Unique replay trial IDs or evaluator validation-case IDs.
- Aggregate reported cost no greater than `max_cost_usd` when configured.
- Stable error categories and codes without forwarding adapter exception messages.
- Suppression of adapter stdout and stderr at the child boundary.

Each invocation uses a fresh process. Results cross the boundary only after validation.
`AdapterTimeoutError`, `AdapterBudgetError`, `AdapterProtocolError`, and
`AdapterExecutionError` expose a stable `code` for automation.

## Not enforced by the runner

This process boundary is not an OS or container security sandbox:

- The adapter inherits the parent account's filesystem and network permissions.
- `max_concurrency` is cooperative; the runner cannot police threads or subprocesses that
  adapter code creates.
- Cost is checked from returned outcomes, after calls have happened. Use a provider-side hard
  quota to prevent overspend from a crash, timeout, or dishonest adapter.
- Killing the child may not cancel work already submitted to a remote service.
- CPU, memory, file, process, and network consumption are not independently limited.

Production deployments should put the runner inside a lower-privilege OS/container sandbox,
use network and filesystem allowlists, enforce provider quotas and remote cancellation, and
record producer identity. Treat adapter code as part of the trusted deployment, never as
data supplied by an incident or evidence bundle.

Causure now provides `SandboxedAdapterRunner` as that separate container boundary
for digest-pinned worker images. It independently schedules one reference per container,
denies networking by default, and requires a company-supplied provider hard-quota
controller/proxy before connected work. It does not change the trust claims of
`ProcessAdapterRunner`. See the [sandboxed adapter-runner
guide](sandboxed-adapter-runner.md).
