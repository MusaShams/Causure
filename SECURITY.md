# Security policy

Causure is an early alpha and has not received an independent security review.

## Reporting a vulnerability

Do not open a public work item containing exploit details, secrets, production traces, or
personal data.

Before GitHub publication, report the issue privately to the project owner through the
Azure DevOps project's private communication channel. After publication, use **Security →
Report a vulnerability** in the GitHub repository. That private vulnerability-reporting
path is the only GitHub intake for exploit details; do not use a public issue or pull
request.

Include:

- Affected version or changeset.
- Reproduction steps using synthetic data.
- Security impact.
- Suggested mitigation, if known.

The project owner should acknowledge a report before publishing a disclosure timeline.

## Supported versions

Only the latest checked-in TFVC alpha and, after publication, its matching latest GitHub
release snapshot are supported. A GitHub mirror commit that does not map to the current
authoritative changeset is not a supported release.

## Sensitive data

Evidence bundles must contain opaque references, not raw customer content, credentials,
personal access tokens, model API keys, or signed artifact URLs. See
[`docs/threat-model.md`](docs/threat-model.md) for the current trust boundaries and known
limitations.

Treat canary policy, evaluator definition, assignment configuration, and aggregate cohort
evidence as protected deployment inputs. Commit, attest, or authority-sign the exact
policy before exposure; its self-reported timestamp does not prove prospective selection.
Keep raw prompts, messages, principal IDs, and per-request records out of the bounded
observation. The comparator checks exact bindings and conservative binary-rate intervals,
but it cannot prove routing, evaluator consistency, sample independence, or the truth of
opaque evidence references. Authenticate the review/policy through protected publication,
attestation, or authority controls; hashing alone proves no producer identity. Keep
independent availability/safety rollback automation and segment analysis. See the
[canary outcome guide](docs/canary-outcome-comparison.md).

Never check in producer private keys or PEM passwords. Attestation trust stores contain
public keys and may be versioned in protected source control; private keys belong in an
approved secret manager or KMS/HSM.

Apply the same rule more strictly to approval authorities. Keep approval private keys out
of the build agent and verifier job. Protect the approval trust store and revocation list
from the authority, approver, and evidence producer; otherwise one principal can authorize
its own claims. The local `issue-approval` command is an adapter for an organizational
identity/authorization service, not a substitute for one.

Treat Team access policies, historical policy snapshots, tenant ledger heads, and audit
exports as protected control-plane data. The local `team-authorize` command trusts the
policy file and identity claims it receives; a hosted service must take stable identity
claims from validated SSO, resolve the tenant server-side, and never accept a
client-supplied role. Keep personal data out of IDs where an opaque identity-provider
subject is available.

Hash chaining makes event mutation detectable but does not make writable files immutable.
The optional SQLite store supplies transactional compare-and-swap heads, exact historical
bytes, and normal-API mutation guards for a single host. A database/filesystem owner can
bypass those guards or replace the file. Put production events and exports in
access-controlled append-only or WORM-capable storage that enforces every recorded
retention deadline, and never use a network share or synced folder as SQLite replication.

The Team WSGI boundary is not an authenticator. Put credential-validation and
request-integrity middleware in front of it, select the tenant only from trusted
server-side context, inject the exact `AuthenticatedTeamIdentity`, and strip identity-like
headers at every untrusted proxy hop. Never set the POST integrity signal merely because a
header exists. Use a qualified production WSGI server, TLS, rate limits, request timeouts,
and a single host/local filesystem for this SQLite pilot.
`TeamAdmissionControlMiddleware` is a process-local backstop that must wrap the Entra
adapter so excess work is rejected before bearer parsing. Its default source key uses only
the WSGI server's normalized `REMOTE_ADDR` and ignores forwarding headers. Treat any custom
source resolver as trusted security code; never copy untrusted `Forwarded` or
`X-Forwarded-For` values. Per-process limits multiply across workers and cannot replace
edge connection/body/time/rate/concurrency controls. See the
[Team HTTP API deployment guide](docs/team-http-api.md).

Treat the Entra refresh configuration and installed trust snapshot as authentication
control-plane data. Restrict the configuration, snapshot, owner-lock, request-marker, and
parent directory to the service identity. For one process, use one managed verifier. For
multiple processes on one host/local volume, create and start one
`CoordinatedEntraAccessTokenVerifier` after each worker fork; its OS lock admits one writer,
followers reload only, and the lock is released by process exit. Never delete or replace a
live owner-lock file. Network shares, synced folders, containers on different hosts, and
distributed filesystems are outside this local-lock guarantee; use one external scheduler
with reload-only workers or a separately reviewed distributed coordinator.

Refresh makes direct HTTPS requests without environment proxies or redirects; qualify that
outbound policy and alert before last-known-good trust expires. Managed unknown-key
recovery is asynchronous, globally singleflight per elected local owner, and limited to
one attempt per five minutes. Followers atomically coalesce requests into one bounded
marker, but an unauthenticated caller who knows a trusted tenant ID can still trigger that
bounded work. Rate-limit before token validation; monitor coordinated/managed refresh
status plus admission rejection and active counts; and expect the first genuinely
rolled-key request to fail once. See the
[Microsoft Entra bearer-host guide](docs/team-entra-bearer-host.md).

The read-only Team console minimizes rather than eliminates disclosure. It renders opaque
principal/resource IDs, action metadata, retention values, and payload hashes to every
current tenant member. It never renders payload bodies, caps pages at 100, escapes every
displayed value, and ships no scripts or forms. Keep personal or secret data out of IDs,
protect the console as an internal authenticated surface, and use exact events or verified
exports—not HTML screenshots—as forensic records. See the
[evidence-console guide](docs/team-evidence-console.md).

The joined change-case dashboard minimizes source artifacts but still exposes bounded
titles, change/review summaries, predictions, stable approval subjects, TFVC/build IDs,
and hashes to every current tenant member. Keep customer content and personal data out of
those fields. Raw evidence references, reports, approval justification, and canary
observations must remain in separately authorized artifact storage. Treat displayed
Azure, approval, and canary receipts as point-in-time evidence only: the publishing
integration must perform current build, signature/authority, expiry, revocation, and
deployment-safety checks before recording a revision. Dashboard ingestion does not make
those live checks or operate a deployment. Back up and test restore before the automatic
SQLite v1-to-v2 case-index migration. See the
[change-case dashboard guide](docs/team-change-case-dashboard.md).

Never bake provider API keys into sandbox worker images or place quota-lease tokens in
policy/evidence files, command arguments, environment variables, or diagnostics. A
provider-connected deployment must keep provider credentials in its enforcing quota proxy
and treat Docker, network, controller, and proxy administration as privileged
infrastructure.

For the split-edge quota pilot, create the state parent with reviewed owner/service ACLs
before preparation. Keep prepared configuration, provider/admin secrets, TLS private key,
SQLite volume, and WAL/SHM state off source trees, synced folders, and network shares.
Compose read-only mounts do not compensate for permissive host permissions. Scope the
generated pilot CA to exact clients instead of trusting it machine-wide, rotate state
before its short certificate expiry, and never commit `pilot-state` or qualification smoke
state. The Docker Desktop admin-control bridge is a local loopback-publication compromise;
production requires an independently enforced control ingress with denied arbitrary
egress.

Protect the Azure Classic Pipeline definition, TFVC source mapping, agent pool, configured
server path, and artifact retention. Azure build variables are trusted orchestration input,
not evidence and not secrets. Do not copy `System.AccessToken`, personal access tokens, or
signed artifact URLs into a review publication.

For GitHub automatic selection, grant only `contents: read`, `pull-requests: read`, and the
documented same-repository `checks: write`. Use the unprivileged `pull_request` event and the
short-lived job `github.token`, never a personal access token or repository secret. Protect
the caller workflow, `.causure/config.json`, and its policy with ordinary review or
CODEOWNERS. Automatic mode rejects those governance files when the candidate PR changes
them, caps file discovery, rechecks the exact event head after pagination, and never imports
configured adapter entry points. Fork runs use only the read-only token for discovery and
skip the privileged Check Run write. Dependabot runs preserve the required workflow-job
result but also skip the custom write in automatic mode when GitHub downgrades the token.

For configured case generation, check out the event's exact protected base and candidate
head into separate workspace-confined roots. Invoke only the full-SHA-pinned remote
`trusted-case-generator` Action; never invoke `uses: ./` from the candidate checkout. The
Action verifies both checkout heads, resolves the configured entry point only from the
protected base adapter directory, rejects symlink/containment violations, hashes the bounded
component and adapter tree before and after execution, and requires an exact
repository/PR/head/path reference in the generated case. Generator-backed forks fail before
Git or adapter execution. Do not weaken that boundary with `pull_request_target`, fork
secrets, or a write-capable personal token.

The generator child is not an operating-system sandbox. Protected adapter code inherits the
job's filesystem and network permissions and receives the candidate root so it can read
component data. Review it as privileged supply-chain code, parse candidate files as data,
never import/execute modules from the candidate, and grant only the credentials and egress
its replay/evaluation task requires. Use the digest-pinned OCI and quota controls when a
company adapter needs stronger resource, network, or spend isolation. The minimized
generation receipt proves exact subjects and runner checks; it does not prove that a
malicious protected adapter refrained from side effects.

The Azure requester ID records who queued a build; it does not authenticate a human
approver. `System.AccessToken` authenticates the build service, not a person. A signed
approval assertion is trustworthy only when its protected authority independently
authenticated and authorized the recorded subject. Approval and exception records are
`record_only`; do not treat the publication-verification or approval-verification receipt
as a rewrite of a non-approval decision.
