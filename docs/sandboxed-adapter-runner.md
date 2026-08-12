# Sandboxed adapter runner

`SandboxedAdapterRunner` executes replay and evaluation work as one evidence reference per
digest-pinned Linux container. It is the deployment boundary for code that should not
inherit the Causure process's filesystem, network, or operating-system identity.

It complements `ProcessAdapterRunner`; it does not silently upgrade that process boundary
into a sandbox.

## Execution model

The parent validates a trusted `SandboxPolicy`, performs runtime preflight checks, and
schedules at most the request budget's `max_concurrency` containers. Every container gets
exactly one reference and a per-worker budget over standard input, then must return exactly
one replay or evaluation outcome over standard output.

The worker request and response are closed, versioned contracts:

- [Sandbox policy schema](../schemas/sandbox-policy.schema.json)
- [Worker request schema](../schemas/sandbox-worker-request.schema.json)
- [Worker response schema](../schemas/sandbox-worker-response.schema.json)

The runner rejects unknown or duplicate JSON fields, invalid UTF-8, mismatched case or input
references, wrong-mode outcomes, non-finite measurements, duplicate outcome identities,
oversized output, and aggregate reported cost above the request budget.

## Policy example

Images must be selected by a trusted deployment policy and pinned to a local repository
digest. Tags alone are rejected.

```json
{
  "schema_version": "1.0",
  "policy_id": "offline-replay-v1",
  "worker_protocol": "1.0",
  "image": "registry.example/causure/worker@sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
  "network_mode": "none",
  "cpu_limit": 1.0,
  "memory_mb": 512,
  "pids_limit": 64,
  "tmpfs_mb": 64,
  "max_output_bytes": 1048576,
  "user": "65532:65532"
}
```

Load trusted policy JSON with `parse_sandbox_policy`, then pass the resulting object and an
ordinary `ReplayRequest` or `EvaluationRequest` to the runner:

```python
import json

from causure import (
    ExecutionBudget,
    ReplayRequest,
    SandboxedAdapterRunner,
    parse_sandbox_policy,
)

policy = parse_sandbox_policy(json.loads(open("sandbox-policy.json", encoding="utf-8").read()))
request = ReplayRequest(
    case_id="refund-incident-01",
    trace_refs=("trace-sha256://source/traces/trace",),
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

result = SandboxedAdapterRunner().run_replay(policy, request)
```

`DockerCliSandboxRuntime` is the default runtime. The Python package does not install or
start Docker; the deployment must provide a compatible Docker CLI and Linux container
engine.

## Applied container controls

Before launch, the default runtime confirms:

- the Docker server and worker image are Linux;
- the exact requested repository digest is present locally;
- the image does not declare writable volumes;
- a provider-connected network, when used, is marked internal and contains only the named
  quota proxy before workers attach.

The generated command uses `--pull never`, a read-only root filesystem, a bounded
`noexec`/`nosuid`/`nodev` `/tmp`, a numeric non-root user, `--cap-drop ALL`,
`no-new-privileges`, Docker's built-in seccomp profile, a private cgroup namespace, and
explicit CPU, memory, no-swap, PID, file-descriptor, core-dump, and output limits. It adds
no host mount, device, environment secret, or privileged mode.

Offline policy uses Docker's [`none` network
driver](https://docs.docker.com/engine/network/drivers/none/). Provider-connected policy
uses only the lease's internal Docker network. Docker documents the individual
[`docker container run` controls](https://docs.docker.com/reference/cli/docker/container/run/);
the Causure policy fixes their required combination rather than accepting
free-form runtime arguments.

The lease token is serialized only into the bounded standard-input request. It is absent
from command arguments, environment variables, result objects, and dataclass
representations. Docker logging is disabled for the worker. Worker standard error is
bounded and discarded.

Timeout or worker failure causes pending launches to be suppressed and active container
names to be force-removed. A cleanup that cannot be confirmed becomes
`sandbox_cleanup_unconfirmed`, even if another error happened first.

## Network modes

### `none`

This is the fully offline mode. No quota controller may be supplied. CPU, memory, process,
case, concurrency, wall-clock, and output limits are enforced independently, but
`max_cost_usd` remains a check against worker-reported outcomes after execution because no
provider is reachable.

### `quota_proxy`

This mode requires a `ProviderQuotaController` and a request `max_cost_usd`. Before Docker
preflight or worker launch, the controller must return a `QuotaLease` backed by an actual
provider or proxy hard limit.

The lease must:

- use `provider_hard_limit` enforcement;
- stay at or below the requested cost and concurrency;
- authorize exactly the number of requested operations;
- remain valid through the execution deadline plus cleanup margin;
- name a dedicated internal network and its only pre-attached proxy container;
- provide an HTTPS proxy URL whose hostname is that container.

The controller settles and revokes the lease only after every outcome is validated.
Provider accounting becomes `total_cost_usd`; worker-reported accounting remains separately
available as `reported_cost_usd`. Any validation, runtime, budget, or settlement failure
causes lease cancellation. Controller cancellation must be idempotent and must raise if
revocation cannot be confirmed.

A network name by itself is not a spend control. A production implementation must ensure
the proxy is the worker's only provider path, validates the scoped lease token, enforces
operation and monetary limits before forwarding, and obtains authoritative provider
accounting.

Causure now ships one conservative
[OpenAI-compatible reference](openai-compatible-quota-proxy.md). It closes the first
provider surface to non-streaming text Responses, serializes admission in SQLite before
forwarding, and makes ambiguous accounting un-settleable. It is not a live-provider or
managed Docker qualification.

## Worker-image contract

A worker image must:

1. Read at most one JSON request from standard input.
2. Parse it with `parse_sandbox_worker_request`.
3. Process only the supplied reference and mode.
4. Route provider calls through `request.quota.proxy_url` when quota data is present.
5. Emit one response with `render_sandbox_worker_response`.
6. Exit zero without writing any additional standard-output content.

The image may write diagnostics to standard error, but the parent never returns them.
Do not place provider API keys in the image. In quota mode, the proxy owns provider
credentials; the worker receives only its scoped lease token.

## Deployment responsibilities

| Boundary | Repository enforces | Deployment must supply |
| --- | --- | --- |
| Image identity | Digest syntax, local digest match, Linux image, no declared volumes | Image build, scanning, signing, registry admission |
| OS resources | Docker command, parent deadline, cleanup confirmation | Hardened and patched Linux host/daemon |
| Offline network | `--network none` | Host firewall and daemon access controls |
| Connected network | Internal/dedicated-network preflight | Network creation and exclusive orchestration permissions |
| Spend | Lease shape/order plus one OpenAI-compatible transactional controller/proxy reference | Exact provider/model/rate qualification and unsupported billing-surface closure |
| Concurrency | Parent worker-pool cap and one reference per container | Provider account limits and fleet-level admission control |
| Secrets | Token only on bounded stdin; no argv/env/result/log copy | Proxy credentials, token issuance, certificate trust |

The Docker daemon, host kernel, trusted policy, quota controller, proxy, and orchestration
plane remain inside the trusted computing base. This boundary reduces worker authority; it
is not a claim of protection against a kernel/container-runtime escape or a compromised
Docker administrator.

## Qualification status

The default deterministic suite uses fake runtimes and scripted Docker inspection output,
so it can run on TFVC Classic agents without Docker. It verifies scheduling, cancellation,
command construction, parsing, network admission, quota ordering, and accounting logic.

That suite does not certify a particular Docker daemon, Linux kernel, worker image, TLS
configuration, live provider, protected pricing snapshot, or managed quota deployment.
Before production use, add a protected deployment test that runs the exact digest on the
target engine and proves filesystem, network, resource, cancellation, proxy-bypass,
provider reconciliation, restart ambiguity, and hard-spend behavior.
