# Single-host Team service launcher

Causure `0.4.0a15` includes a closed launcher for one Team service process on one
host. It composes the existing SQLite store, Team application, Microsoft Entra bearer
verification, managed trust refresh, and pre-authentication admission control, then serves
the resulting WSGI application with exactly Waitress `3.0.2`.

This is an operator-ready single-host boundary, not a complete production deployment. It
binds only to `127.0.0.1` or `::1` and must sit behind a trusted same-host HTTPS reverse
proxy. The edge still owns TLS, public listener policy, aggregate connection and rate
limits, request deadlines, access-log redaction, and client-source policy.

## Install and prepare protected paths

Install the exact serving and Entra dependencies through the service extra:

```powershell
python -m pip install "causure[service]==0.4.0a15"
```

Create separate protected configuration, state, and data directories. Grant write access
only to the service identity where it is required:

- the Entra refresh configuration and Team host configuration are operator-written,
  service-readable control-plane files;
- the Entra trust snapshot is service-readable and service-writable because refresh
  installs it atomically;
- the SQLite database and its parent are service-readable and service-writable; and
- none of these paths belongs under a web root, synchronized folder, or network share.

Provision each tenant policy with `team-store-policy-put` before routing member traffic.
The launcher initializes or migrates the SQLite schema, but it does not invent access
policy or create an Entra app registration.

## Bind the exact refresh configuration

The host configuration names the expected Entra refresh `store_id` and binds the exact
refresh-configuration bytes by SHA-256 and byte count. This makes a refresh-policy edit an
explicit host-policy change rather than an unnoticed startup input.

Compute the subject after placing the final file at its protected path:

```powershell
$refreshPath = "C:\ProgramData\Causure\config\entra-refresh.json"
$refreshBytes = [System.IO.File]::ReadAllBytes($refreshPath)
$refreshSha = [Convert]::ToHexString(
    [System.Security.Cryptography.SHA256]::HashData($refreshBytes)
).ToLowerInvariant()

[pscustomobject]@{
    refresh_configuration_byte_count = $refreshBytes.Length
    refresh_configuration_sha256     = $refreshSha
}
```

Do not normalize, reformat, or resave that file after computing its subject. A byte-count,
digest, or `store_id` mismatch stops startup before the Team database is initialized.

## Closed host configuration

Create a protected JSON document matching the committed
[Team host configuration schema](../schemas/team-host-config.schema.json). Every field is
required and unknown fields are rejected. This example uses the exact subject of the
committed `examples/team/acme-entra-refresh.json` fixture; recompute both values for the
deployed file:

```json
{
  "schema_version": "1.0",
  "database": {
    "path": "C:\\ProgramData\\Causure\\data\\team.sqlite3",
    "busy_timeout_ms": 5000
  },
  "server": {
    "implementation": "waitress",
    "version": "3.0.2",
    "listen_host": "127.0.0.1",
    "listen_port": 8080,
    "trusted_external_scheme": "https",
    "threads": 8,
    "connection_limit": 64,
    "backlog": 64,
    "channel_timeout_seconds": 30,
    "max_request_header_bytes": 32768
  },
  "identity": {
    "refresh_configuration_path": "C:\\ProgramData\\Causure\\config\\entra-refresh.json",
    "refresh_configuration_sha256": "a15e5a5c9a1783891ffceb42d3191c6347dda0adf0a8108c12a9ec8ec80bce09",
    "refresh_configuration_byte_count": 787,
    "trust_store_path": "C:\\ProgramData\\Causure\\state\\entra-trust.json",
    "store_id": "entra-production",
    "clock_skew_seconds": 60,
    "refresh_timeout_seconds": 10,
    "refresh_interval_seconds": 3600,
    "failure_retry_seconds": 300,
    "unknown_key_refresh_seconds": 300
  },
  "admission": {
    "max_concurrency": 8,
    "global_requests_per_window": 600,
    "per_source_requests_per_window": null,
    "rate_window_seconds": 60,
    "max_tracked_sources": 4096,
    "source_idle_seconds": 600
  }
}
```

All three paths must be local, absolute, and distinct; UNC/device/network-share paths are
rejected on Windows. Only the canonical loopback addresses
`127.0.0.1` and `::1` are accepted. The server implementation, exact Waitress version,
and external scheme are fixed; admission concurrency cannot exceed the Waitress thread
count.

Leave `per_source_requests_per_window` as `null` behind a same-host proxy unless a reviewed
socket-derived source resolver exists. The launcher intentionally ignores `Forwarded`,
`X-Forwarded-For`, `X-Forwarded-Proto`, and every other proxy header. Consequently,
`REMOTE_ADDR` normally identifies the edge itself, so enabling the default per-source
bucket groups all callers behind that edge.

## Start and stop

Start the service with the protected host configuration:

```powershell
python -m causure team-serve `
  C:\ProgramData\Causure\config\team-host.json
```

Startup proceeds in this order:

1. strictly load and revalidate the closed host configuration;
2. verify the refresh configuration's exact byte count, SHA-256, and `store_id`;
3. inspect the database and trust-snapshot parent paths;
4. initialize or migrate the SQLite store;
5. synchronously refresh Entra trust, with only a still-fresh same-store snapshot as
   fallback;
6. start one managed periodic/unknown-key refresh worker; and
7. expose admission control outside Entra authentication outside the Team application.

Any startup failure is fail-closed. After startup, `/healthz` reports process liveness and
`/readyz` checks the store plus the managed Entra verifier. Keep both probes on the trusted
edge or management plane; neither is a substitute for an authenticated functional test.

Normal server return, listener failure, `KeyboardInterrupt`, and other Python exceptions
leave through the same lifecycle boundary and request bounded refresh-worker shutdown.
Configure the service manager with a graceful stop window of at least 30 seconds and avoid
routine force termination. Use one launcher process only; do not configure a prefork or
multi-process wrapper around it.

On Windows, the optional native SCM adapter supplies a tested control-thread stop path,
exact config registration, and a passwordless virtual service account. Follow the
[native Windows service guide](team-windows-service.md); do not wrap `team-serve` in a
second Windows service manager at the same time.

## Trusted edge contract

The loopback hop is deliberately plain HTTP while the WSGI environment is set to the
trusted external scheme `https`. This assertion is safe only when the same-host edge
accepts the public request over HTTPS and is the sole intended loopback caller. Restrict
local process access accordingly.

The edge must:

- expose only HTTPS and reject or redirect plaintext before it reaches the launcher;
- connect only to the configured loopback address and port;
- strip all incoming forwarding and identity-like headers; the launcher trusts none of
  them and clears untrusted proxy headers again;
- preserve the original `Authorization` value only on the protected hop, while redacting
  it from proxy, WSGI, APM, and exception logs;
- apply an allowlisted public host name and its own request-line/header limits;
- cap request bodies at or below the launcher's 24 MiB application limit;
- enforce end-to-end header/body/request deadlines and slow-client protection;
- enforce aggregate connection, concurrency, and rate limits across all workers/hosts;
  and
- send complete responses and honor restrictive application security headers without
  rewriting authentication or tenant context.

Waitress is pinned and configured with bounded threads, connections, backlog, idle channel
timeout, request headers, and request body; tracebacks and request lookahead are disabled.
Those are process safeguards, not distributed abuse controls or a complete execution
deadline. See the
[Waitress server arguments](https://docs.pylonsproject.org/projects/waitress/en/latest/arguments.html)
for the underlying runtime semantics.

## Operations and qualification boundary

Back up SQLite with `team-store-backup`, protect the backup off-host, and rehearse restore
to a new path. Monitor edge rejections, process exits, `/readyz`, Entra refresh age and
stable refresh errors, SQLite capacity, disk space, and audit-export retention. Never log
tokens, request bodies, configuration bodies, or raw identity claims.

This launcher does not provide public TLS termination, signed installer packaging,
container/orchestrator manifests, distributed rate limiting, multi-process refresh
election, multi-host storage, WORM retention, independently anchored audit heads, disaster
recovery, or live Entra/app-registration qualification. It has not been qualified as a
production deployment merely because the process starts. A company must test the exact
edge, identity tenant, app registration, rollover/outage behavior, service manager,
backup/restore path, and abuse controls before treating the deployment as production.
