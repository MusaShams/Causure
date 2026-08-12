"""Server-rendered, read-only evidence console for the Team application service."""

from __future__ import annotations

import html

from causure.constants import (
    PACKAGE_VERSION,
    TeamInvestigationPriority,
    TeamInvestigationStatus,
)
from causure.team_application import (
    TeamCaseDetail,
    TeamCasePage,
    TeamCaseView,
    TeamEventPage,
    TeamEventSummary,
    TeamInvestigationDetail,
    TeamInvestigationPage,
    TeamInvestigationView,
    TeamTenantSummary,
)
from causure.team_cases import TeamCaseChangeSubject

TEAM_DASHBOARD_CSS = (
    b"""
:root {
  color-scheme: dark;
  --bg: #07110e;
  --panel: #0d1a16;
  --panel-raised: #12231d;
  --line: #254038;
  --text: #eef7f2;
  --muted: #9db5aa;
  --accent: #66e3ad;
  --accent-strong: #9af2c9;
  --warning: #ffd083;
  --danger: #ff9c9c;
  --shadow: 0 18px 50px rgb(0 0 0 / 24%);
  font-family: Inter, ui-sans-serif, system-ui, -apple-system, BlinkMacSystemFont, "Segoe UI",
    sans-serif;
}

* {
  box-sizing: border-box;
}

body {
  min-width: 320px;
  margin: 0;
  background:
    radial-gradient(circle at 18% -10%, rgb(35 113 84 / 24%), transparent 34rem),
    var(--bg);
  color: var(--text);
  line-height: 1.5;
}

a {
  color: var(--accent-strong);
}

a:focus-visible {
  outline: 3px solid var(--warning);
  outline-offset: 3px;
}

.topbar {
  border-bottom: 1px solid var(--line);
  background: rgb(7 17 14 / 88%);
}

.topbar-inner,
main,
.footer {
  width: min(1120px, calc(100% - 2rem));
  margin-inline: auto;
}

.topbar-inner {
  display: flex;
  align-items: center;
  justify-content: space-between;
  min-height: 68px;
  gap: 1rem;
}

.brand {
  display: flex;
  align-items: center;
  gap: 0.8rem;
  font-weight: 750;
  letter-spacing: -0.01em;
}

.brand-mark {
  display: inline-grid;
  width: 36px;
  height: 36px;
  place-items: center;
  border: 1px solid #3c6b5b;
  border-radius: 10px;
  background: linear-gradient(145deg, #173d31, #10251e);
  color: var(--accent-strong);
  font-size: 0.78rem;
  letter-spacing: 0.05em;
}

.read-only {
  flex-shrink: 0;
  border: 1px solid #3d6557;
  border-radius: 999px;
  padding: 0.25rem 0.65rem;
  color: var(--muted);
  font-size: 0.76rem;
  font-weight: 700;
  letter-spacing: 0.04em;
  text-transform: uppercase;
  white-space: nowrap;
}

.top-actions {
  display: flex;
  align-items: center;
  gap: 0.65rem;
}

.nav-link {
  border-radius: 8px;
  padding: 0.38rem 0.55rem;
  color: var(--accent-strong);
  font-size: 0.82rem;
  font-weight: 700;
  text-decoration: none;
}

.nav-link:hover {
  background: #112a21;
}

main {
  padding-block: 3.5rem 4rem;
}

.eyebrow {
  margin: 0 0 0.45rem;
  color: var(--accent);
  font-size: 0.78rem;
  font-weight: 750;
  letter-spacing: 0.12em;
  text-transform: uppercase;
}

h1,
h2,
h3,
p {
  overflow-wrap: anywhere;
}

h1 {
  max-width: 18ch;
  margin: 0;
  font-size: clamp(2.15rem, 6vw, 4.5rem);
  line-height: 0.98;
  letter-spacing: -0.055em;
}

.lede {
  max-width: 65ch;
  margin: 1.25rem 0 0;
  color: var(--muted);
  font-size: 1.05rem;
}

.roles {
  display: flex;
  flex-wrap: wrap;
  gap: 0.5rem;
  margin-top: 1.35rem;
}

.chip {
  border: 1px solid #31594c;
  border-radius: 999px;
  padding: 0.32rem 0.7rem;
  background: #0c211a;
  color: #c6ebd9;
  font-family: ui-monospace, "Cascadia Code", "SFMono-Regular", Consolas, monospace;
  font-size: 0.78rem;
}

.metrics {
  display: grid;
  grid-template-columns: repeat(3, minmax(0, 1fr));
  gap: 0.9rem;
  margin-block: 2.4rem 3.2rem;
}

.metric {
  min-width: 0;
  border: 1px solid var(--line);
  border-radius: 16px;
  padding: 1rem 1.05rem;
  background: linear-gradient(145deg, rgb(18 35 29 / 92%), rgb(11 26 21 / 92%));
  box-shadow: var(--shadow);
}

.metric-label {
  display: block;
  margin-bottom: 0.45rem;
  color: var(--muted);
  font-size: 0.73rem;
  font-weight: 700;
  letter-spacing: 0.08em;
  text-transform: uppercase;
}

.metric-value {
  display: block;
  min-width: 0;
  font-size: 1.08rem;
  font-weight: 720;
}

code,
.mono {
  font-family: ui-monospace, "Cascadia Code", "SFMono-Regular", Consolas, monospace;
}

.truncate {
  display: block;
  overflow: hidden;
  text-overflow: ellipsis;
  white-space: nowrap;
}

.section-heading {
  display: flex;
  align-items: end;
  justify-content: space-between;
  gap: 1rem;
  margin-bottom: 1rem;
}

.section-heading h2 {
  margin: 0;
  font-size: 1.45rem;
  letter-spacing: -0.025em;
}

.section-heading p {
  margin: 0;
  color: var(--muted);
  font-size: 0.88rem;
}

.event-list {
  display: grid;
  gap: 0.8rem;
}

.event {
  border: 1px solid var(--line);
  border-radius: 18px;
  padding: 1.15rem;
  background: rgb(13 26 22 / 92%);
}

.event-topline,
.event-title,
.event-footer {
  display: flex;
  align-items: center;
  justify-content: space-between;
  gap: 0.8rem;
}

.sequence {
  color: var(--muted);
  font-size: 0.82rem;
  font-weight: 700;
}

.outcome {
  border: 1px solid currentColor;
  border-radius: 999px;
  padding: 0.22rem 0.6rem;
  font-size: 0.72rem;
  font-weight: 760;
  letter-spacing: 0.05em;
  text-transform: uppercase;
}

.outcome-succeeded {
  color: var(--accent);
}

.outcome-failed {
  color: var(--warning);
}

.outcome-denied {
  color: var(--danger);
}

.event-title {
  align-items: baseline;
  justify-content: flex-start;
  flex-wrap: wrap;
  margin-block: 0.75rem 0.2rem;
}

.event-title h3 {
  margin: 0;
  font-size: 1.05rem;
}

.resource-id {
  color: var(--muted);
  font-size: 0.8rem;
}

.event-meta {
  display: grid;
  grid-template-columns: repeat(4, minmax(0, 1fr));
  gap: 0.8rem;
  margin: 1rem 0;
}

.event-meta div {
  min-width: 0;
}

.event-meta dt {
  margin-bottom: 0.2rem;
  color: var(--muted);
  font-size: 0.68rem;
  font-weight: 700;
  letter-spacing: 0.07em;
  text-transform: uppercase;
}

.event-meta dd {
  margin: 0;
  font-size: 0.82rem;
}

.event-footer {
  align-items: end;
  flex-wrap: wrap;
  border-top: 1px solid #1d352d;
  padding-top: 0.75rem;
  color: var(--muted);
  font-size: 0.72rem;
}

.empty {
  border: 1px dashed #365348;
  border-radius: 18px;
  padding: 2.5rem 1.2rem;
  text-align: center;
  color: var(--muted);
}

.pagination {
  display: flex;
  justify-content: flex-end;
  margin-top: 1.2rem;
}

.button-link {
  display: inline-flex;
  align-items: center;
  min-height: 42px;
  border: 1px solid #41705f;
  border-radius: 10px;
  padding: 0.55rem 0.9rem;
  background: #123226;
  color: var(--text);
  font-weight: 700;
  text-decoration: none;
}

.case-list {
  display: grid;
  gap: 1rem;
}

.case-card,
.panel {
  min-width: 0;
  border: 1px solid var(--line);
  border-radius: 18px;
  background: rgb(13 26 22 / 94%);
  box-shadow: var(--shadow);
}

.case-card {
  padding: 1.25rem;
}

.case-card h2,
.panel h2,
.panel h3 {
  margin-top: 0;
  letter-spacing: -0.025em;
}

.case-card h2 {
  margin-bottom: 0.45rem;
  font-size: 1.25rem;
}

.case-link {
  color: var(--text);
  text-decoration: none;
}

.case-link:hover {
  color: var(--accent-strong);
}

.case-summary {
  max-width: 78ch;
  margin: 0;
  color: var(--muted);
}

.stage-row {
  display: flex;
  flex-wrap: wrap;
  gap: 0.5rem;
  margin-top: 1rem;
}

.stage {
  border: 1px solid #365348;
  border-radius: 999px;
  padding: 0.25rem 0.6rem;
  color: var(--muted);
  font-size: 0.72rem;
  font-weight: 750;
  letter-spacing: 0.035em;
  text-transform: uppercase;
}

.stage-present,
.status-pass,
.status-noninferior,
.status-promote,
.status-approve,
.status-investigating,
.status-closed,
.status-low,
.status-normal {
  border-color: #3b8469;
  color: var(--accent);
}

.status-warning,
.status-inconclusive,
.status-continue,
.status-conditional_pass,
.status-needs_evidence,
.status-exception,
.status-queued,
.status-high {
  border-color: #8a6c36;
  color: var(--warning);
}

.status-fail,
.status-regressed,
.status-rollback,
.status-reject,
.status-blocked,
.status-critical {
  border-color: #8b4949;
  color: var(--danger);
}

.case-footer {
  display: flex;
  justify-content: space-between;
  gap: 1rem;
  flex-wrap: wrap;
  border-top: 1px solid #1d352d;
  margin-top: 1rem;
  padding-top: 0.8rem;
  color: var(--muted);
  font-size: 0.75rem;
}

.detail-header h1 {
  max-width: 24ch;
}

.back-link {
  display: inline-flex;
  margin-bottom: 1.2rem;
  color: var(--accent-strong);
  font-weight: 700;
  text-decoration: none;
}

.detail-grid {
  display: grid;
  grid-template-columns: repeat(2, minmax(0, 1fr));
  gap: 1rem;
  margin-top: 1rem;
}

.panel {
  padding: 1.2rem;
}

.panel-wide {
  grid-column: 1 / -1;
}

.panel p:last-child {
  margin-bottom: 0;
}

.data-grid {
  display: grid;
  grid-template-columns: repeat(2, minmax(0, 1fr));
  gap: 0.8rem 1rem;
  margin: 0;
}

.data-grid div {
  min-width: 0;
}

.data-grid dt {
  margin-bottom: 0.2rem;
  color: var(--muted);
  font-size: 0.68rem;
  font-weight: 700;
  letter-spacing: 0.07em;
  text-transform: uppercase;
}

.data-grid dd {
  margin: 0;
  overflow-wrap: anywhere;
}

.table-wrap {
  overflow-x: auto;
}

table {
  width: 100%;
  border-collapse: collapse;
  font-size: 0.82rem;
}

th,
td {
  border-bottom: 1px solid #254038;
  padding: 0.62rem 0.45rem;
  text-align: left;
  vertical-align: top;
}

th {
  color: var(--muted);
  font-size: 0.68rem;
  letter-spacing: 0.06em;
  text-transform: uppercase;
}

.artifact-list {
  display: grid;
  gap: 0.65rem;
  margin: 0;
  padding: 0;
  list-style: none;
}

.artifact-list li {
  min-width: 0;
  border-left: 3px solid #31594c;
  padding-left: 0.75rem;
}

.artifact-role {
  display: block;
  font-weight: 730;
}

.artifact-subject {
  display: block;
  color: var(--muted);
  font-size: 0.75rem;
  overflow-wrap: anywhere;
}

.boundary-note {
  border: 1px solid #67572e;
  border-radius: 12px;
  padding: 0.85rem 1rem;
  background: #261f0d;
  color: #f5dfa8;
  font-size: 0.82rem;
}

.footer {
  border-top: 1px solid var(--line);
  padding-block: 1.5rem 2.5rem;
  color: var(--muted);
  font-size: 0.78rem;
}

@media (max-width: 760px) {
  main {
    padding-top: 2.4rem;
  }

  .metrics,
  .event-meta,
  .detail-grid,
  .data-grid {
    grid-template-columns: 1fr;
  }

  .panel-wide {
    grid-column: auto;
  }

  .section-heading,
  .event-footer {
    align-items: flex-start;
    flex-direction: column;
  }
}

@media print {
  :root {
    color-scheme: light;
  }

  body,
  .metric,
  .event,
  .case-card,
  .panel {
    background: #fff;
    color: #111;
    box-shadow: none;
  }

  .topbar,
  .pagination {
    display: none;
  }

  .metric,
  .event,
  .case-card,
  .panel {
    break-inside: avoid;
    border-color: #bbb;
  }
}
""".strip()
    + b"\n"
)


def _escape(value: object) -> str:
    return html.escape(str(value), quote=True)


def _digest(value: str | None) -> str:
    if value is None:
        return "No events"
    return f"{_escape(value[:16])}\u2026"


def _format_bytes(byte_count: int) -> str:
    if byte_count < 1024:
        return f"{byte_count} B"
    if byte_count < 1024 * 1024:
        return f"{byte_count / 1024:.1f} KiB"
    return f"{byte_count / (1024 * 1024):.1f} MiB"


def _event_html(event: TeamEventSummary) -> str:
    authorization_label = "allowed" if event.authorized else "denied"
    outcome = event.outcome.value
    actor = f"{_escape(event.principal.identity_provider)} / {_escape(event.principal.subject_id)}"
    return f"""
<article class="event">
  <div class="event-topline">
    <span class="sequence">Sequence #{event.sequence}</span>
    <span class="outcome outcome-{_escape(outcome)}">{_escape(outcome)}</span>
  </div>
  <div class="event-title">
    <h3>{_escape(event.action.value)} \u2192 {_escape(event.resource.resource_type.value)}</h3>
    <code class="resource-id">{_escape(event.resource.resource_id)}</code>
  </div>
  <dl class="event-meta">
    <div>
      <dt>Occurred</dt>
      <dd>{_escape(event.occurred_at)}</dd>
    </div>
    <div>
      <dt>Actor</dt>
      <dd class="truncate" title="{actor}">{actor}</dd>
    </div>
    <div>
      <dt>Authorization</dt>
      <dd>{authorization_label} \u00b7 {_escape(event.authorization_reason.value)}</dd>
    </div>
    <div>
      <dt>Retention</dt>
      <dd>{_escape(event.retention.class_id)} through {_escape(event.retention.retain_until)}</dd>
    </div>
  </dl>
  <div class="event-footer">
    <span>
      Record:
      <span class="mono">{_escape(event.event_id)}</span> \u00b7
      <span class="mono">{_escape(event.decision_id)}</span> \u00b7
      policy {_escape(event.policy.policy_id)} r{event.policy.revision}
    </span>
    <span>
      Payload: {_escape(event.payload.media_type)} \u00b7
      {_escape(_format_bytes(event.payload.byte_count))} \u00b7
      <span class="mono" title="{_escape(event.payload.sha256)}">
        sha256:{_digest(event.payload.sha256)}
      </span>
    </span>
    <span class="mono" title="{_escape(event.event_sha256)}">
      event:{_digest(event.event_sha256)}
    </span>
  </div>
</article>""".strip()


def render_team_dashboard(page: TeamEventPage, *, page_size: int) -> bytes:
    """Render one bounded Team event page without payload bodies or active controls."""

    if type(page) is not TeamEventPage:
        raise TypeError("page must be a TeamEventPage")
    if isinstance(page_size, bool) or not isinstance(page_size, int) or not 1 <= page_size <= 100:
        raise ValueError("page_size must be an integer from 1 to 100")

    summary = page.summary
    roles = "".join(
        f'<span class="chip">{_escape(role.value)}</span>' for role in summary.assigned_roles
    )
    if page.events:
        events = "\n".join(_event_html(event) for event in page.events)
    else:
        events = (
            '<div class="empty"><strong>No events in this range.</strong><br>'
            "The ledger has no matching retained activity.</div>"
        )
    pagination = ""
    if page.next_before_sequence is not None:
        pagination = f"""
<nav class="pagination" aria-label="Event pagination">
  <a class="button-link"
     href="?limit={page_size}&amp;before_sequence={page.next_before_sequence}">
    View older events \u2192
  </a>
</nav>""".strip()
    head_title = "" if summary.head.event_sha256 is None else _escape(summary.head.event_sha256)
    document = f"""<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <meta name="robots" content="noindex, nofollow, noarchive">
  <title>{_escape(summary.tenant_id)} \u00b7 Causure</title>
  <link rel="stylesheet" href="/team.css">
</head>
<body>
  <header class="topbar">
    <div class="topbar-inner">
      <div class="brand">
        <span class="brand-mark" aria-hidden="true">PB</span>
        <span>Causure</span>
      </div>
      <div class="top-actions">
        <a class="nav-link" href="/team/investigations">Investigations</a>
        <a class="nav-link" href="/team/cases">Change cases</a>
        <span class="read-only">Read-only evidence</span>
      </div>
    </div>
  </header>
  <main>
    <section aria-labelledby="tenant-title">
      <p class="eyebrow">Tenant evidence console</p>
      <h1 id="tenant-title">{_escape(summary.tenant_id)}</h1>
      <p class="lede">
        Current-policy access to the tamper-evident Team ledger. Payload bodies are never
        rendered; this view exposes bounded audit metadata and content subjects only.
      </p>
      <div class="roles" aria-label="Your current tenant roles">{roles}</div>
    </section>

    <section class="metrics" aria-label="Tenant ledger summary">
      <div class="metric">
        <span class="metric-label">Ledger head</span>
        <span class="metric-value">Sequence {summary.head.sequence}</span>
      </div>
      <div class="metric">
        <span class="metric-label">Head digest</span>
        <code class="metric-value truncate" title="{head_title}">
          {_digest(summary.head.event_sha256)}
        </code>
      </div>
      <div class="metric">
        <span class="metric-label">Active policy</span>
        <span class="metric-value truncate" title="{_escape(summary.policy_id)}">
          {_escape(summary.policy_id)} \u00b7 revision {summary.policy_revision}
        </span>
      </div>
    </section>

    <section aria-labelledby="activity-title">
      <div class="section-heading">
        <h2 id="activity-title">Recent activity</h2>
        <p>Newest first \u00b7 {len(page.events)} event(s) in this page</p>
      </div>
      <div class="event-list">{events}</div>
      {pagination}
    </section>
  </main>
  <footer class="footer">
    Causure {PACKAGE_VERSION} \u00b7 Read-only evidence view \u00b7
    Exact event documents remain available through the authenticated API.
  </footer>
</body>
</html>
"""
    return document.encode("utf-8")


def _roles_html(summary: TeamTenantSummary) -> str:
    return "".join(
        f'<span class="chip">{_escape(role.value)}</span>' for role in summary.assigned_roles
    )


def _case_stage(label: str, value: str, *, present: bool = True) -> str:
    status_class = f"status-{value}" if present else ""
    presence_class = "stage-present" if present and not status_class else ""
    classes = " ".join(item for item in ("stage", presence_class, status_class) if item)
    return f'<span class="{classes}">{_escape(label)}: {_escape(value)}</span>'


def _case_card(view: TeamCaseView) -> str:
    record = view.record
    stages = [
        _case_stage("review", record.review.decision.value),
        _case_stage(
            "delivery",
            "recorded" if record.delivery is not None else "not recorded",
            present=record.delivery is not None,
        ),
        _case_stage(
            "approval",
            record.approval.action.value if record.approval is not None else "not recorded",
            present=record.approval is not None,
        ),
        _case_stage(
            "canary",
            record.canary.decision.value if record.canary is not None else "not recorded",
            present=record.canary is not None,
        ),
    ]
    return f"""
<article class="case-card">
  <p class="eyebrow">{_escape(record.case_id)}</p>
  <h2>
    <a class="case-link" href="/team/cases/{_escape(record.case_id)}">
      {_escape(record.evidence.title)}
    </a>
  </h2>
  <p class="case-summary">{_escape(record.evidence.proposed_summary)}</p>
  <div class="stage-row" aria-label="Recorded case stages">{"".join(stages)}</div>
  <div class="case-footer">
    <span>
      {_escape(record.evidence.proposed_component.value)} ·
      {_escape(record.evidence.severity.value)} severity ·
      {record.evidence.validation_candidate_passed_count}/
      {record.evidence.validation_case_count} candidate checks passed
    </span>
    <span>
      Revision {record.revision} · sequence {view.event.sequence} ·
      {_escape(record.published_at)}
    </span>
  </div>
</article>""".strip()


def render_team_case_dashboard(page: TeamCasePage, *, page_size: int) -> bytes:
    """Render a bounded newest-first dashboard of latest minimized case revisions."""

    if type(page) is not TeamCasePage:
        raise TypeError("page must be a TeamCasePage")
    if isinstance(page_size, bool) or not isinstance(page_size, int) or not 1 <= page_size <= 100:
        raise ValueError("page_size must be an integer from 1 to 100")
    summary = page.summary
    if page.cases:
        cases = "\n".join(_case_card(case) for case in page.cases)
    else:
        cases = (
            '<div class="empty"><strong>No change cases in this range.</strong><br>'
            "Publish a minimized case record through the authenticated API.</div>"
        )
    pagination = ""
    if page.next_before_sequence is not None:
        pagination = f"""
<nav class="pagination" aria-label="Case pagination">
  <a class="button-link"
     href="?limit={page_size}&amp;before_sequence={page.next_before_sequence}">
    View older cases →
  </a>
</nav>""".strip()
    head_title = "" if summary.head.event_sha256 is None else _escape(summary.head.event_sha256)
    document = f"""<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <meta name="robots" content="noindex, nofollow, noarchive">
  <title>Change cases · {_escape(summary.tenant_id)} · Causure</title>
  <link rel="stylesheet" href="/team.css">
</head>
<body>
  <header class="topbar">
    <div class="topbar-inner">
      <div class="brand">
        <span class="brand-mark" aria-hidden="true">PB</span>
        <span>Causure</span>
      </div>
      <div class="top-actions">
        <a class="nav-link" href="/team/investigations">Investigations</a>
        <a class="nav-link" href="/team">Audit ledger</a>
        <span class="read-only">Read-only evidence</span>
      </div>
    </div>
  </header>
  <main>
    <section aria-labelledby="cases-title">
      <p class="eyebrow">{_escape(summary.tenant_id)} · change control</p>
      <h1 id="cases-title">Change-case evidence</h1>
      <p class="lede">
        Latest minimized records joining causal evidence, gate review, recorded approval
        receipts, and post-deployment canary outcomes. Raw source artifacts are not rendered.
      </p>
      <div class="roles" aria-label="Your current tenant roles">{_roles_html(summary)}</div>
    </section>

    <section class="metrics" aria-label="Tenant case summary">
      <div class="metric">
        <span class="metric-label">Cases in page</span>
        <span class="metric-value">{len(page.cases)}</span>
      </div>
      <div class="metric">
        <span class="metric-label">Ledger head</span>
        <span class="metric-value">Sequence {summary.head.sequence}</span>
      </div>
      <div class="metric">
        <span class="metric-label">Head digest</span>
        <code class="metric-value truncate" title="{head_title}">
          {_digest(summary.head.event_sha256)}
        </code>
      </div>
    </section>

    <section aria-labelledby="latest-cases-title">
      <div class="section-heading">
        <h2 id="latest-cases-title">Latest case revisions</h2>
        <p>Newest publication first · exact subjects retained</p>
      </div>
      <div class="case-list">{cases}</div>
      {pagination}
    </section>
  </main>
  <footer class="footer">
    Causure {PACKAGE_VERSION} · Minimized read-only case index ·
    Point-in-time receipts are not live authorization.
  </footer>
</body>
</html>
"""
    return document.encode("utf-8")


def _investigation_card(view: TeamInvestigationView) -> str:
    record = view.record
    assigned = (
        "unassigned"
        if record.assigned_to is None
        else f"{record.assigned_to.identity_provider} / {record.assigned_to.subject_id}"
    )
    resolution = "open" if record.resolution is None else record.resolution.value
    span_count = sum(item.span_count for item in record.observations)
    error_count = sum(item.error_span_count for item in record.observations)
    return f"""
<article class="case-card">
  <p class="eyebrow">{_escape(record.investigation_id)}</p>
  <h2>
    <a class="case-link" href="/team/investigations/{_escape(record.investigation_id)}">
      {_escape(record.title)}
    </a>
  </h2>
  <p class="case-summary">
    Candidate trace grouping only · {_escape(assigned)}
  </p>
  <div class="stage-row" aria-label="Investigation queue state">
    <span class="stage status-{_escape(record.status.value)}">
      status: {_escape(record.status.value)}
    </span>
    <span class="stage status-{_escape(record.priority.value)}">
      priority: {_escape(record.priority.value)}
    </span>
    <span class="stage">resolution: {_escape(resolution)}</span>
  </div>
  <div class="case-footer">
    <span>
      {len(record.observations)} cluster(s) · {span_count} spans · {error_count} errors
    </span>
    <span>
      Revision {record.revision} · sequence {view.event.sequence} ·
      {_escape(record.updated_at)}
    </span>
  </div>
</article>""".strip()


def render_team_investigation_dashboard(
    page: TeamInvestigationPage,
    *,
    page_size: int,
    status: TeamInvestigationStatus | None = None,
    priority: TeamInvestigationPriority | None = None,
) -> bytes:
    """Render latest minimized investigation revisions with preserved filters."""

    if type(page) is not TeamInvestigationPage:
        raise TypeError("page must be a TeamInvestigationPage")
    if isinstance(page_size, bool) or not isinstance(page_size, int) or not 1 <= page_size <= 100:
        raise ValueError("page_size must be an integer from 1 to 100")
    if status is not None and not isinstance(status, TeamInvestigationStatus):
        raise TypeError("status must be a TeamInvestigationStatus or None")
    if priority is not None and not isinstance(priority, TeamInvestigationPriority):
        raise TypeError("priority must be a TeamInvestigationPriority or None")
    summary = page.summary
    if page.investigations:
        cards = "\n".join(_investigation_card(item) for item in page.investigations)
    else:
        cards = (
            '<div class="empty"><strong>No investigations match this range.</strong><br>'
            "Open a candidate cluster through the authenticated API or adjust the filters."
            "</div>"
        )
    filters = []
    if status is not None:
        filters.append(f"status={_escape(status.value)}")
    if priority is not None:
        filters.append(f"priority={_escape(priority.value)}")
    filter_label = " · ".join(filters) if filters else "all current queue states"
    pagination = ""
    if page.next_before_sequence is not None:
        query = [f"limit={page_size}"]
        if status is not None:
            query.append(f"status={status.value}")
        if priority is not None:
            query.append(f"priority={priority.value}")
        query.append(f"before_sequence={page.next_before_sequence}")
        pagination = f"""
<nav class="pagination" aria-label="Investigation pagination">
  <a class="button-link" href="?{_escape("&".join(query))}">
    View older investigations →
  </a>
</nav>""".strip()
    head_title = "" if summary.head.event_sha256 is None else _escape(summary.head.event_sha256)
    document = f"""<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <meta name="robots" content="noindex, nofollow, noarchive">
  <title>Investigations · {_escape(summary.tenant_id)} · Causure</title>
  <link rel="stylesheet" href="/team.css">
</head>
<body>
  <header class="topbar">
    <div class="topbar-inner">
      <div class="brand">
        <span class="brand-mark" aria-hidden="true">PB</span>
        <span>Causure</span>
      </div>
      <div class="top-actions">
        <a class="nav-link" href="/team/cases">Change cases</a>
        <a class="nav-link" href="/team">Audit ledger</a>
        <span class="read-only">Read-only evidence</span>
      </div>
    </div>
  </header>
  <main>
    <section aria-labelledby="investigations-title">
      <p class="eyebrow">{_escape(summary.tenant_id)} · incident triage</p>
      <h1 id="investigations-title">Investigation queue</h1>
      <p class="lede">
        Explicit human-authorized groupings of candidate trace clusters. These records do not
        infer a failure, causal attribution, or permission to patch.
      </p>
      <div class="roles" aria-label="Your current tenant roles">{_roles_html(summary)}</div>
    </section>

    <section class="metrics" aria-label="Investigation queue summary">
      <div class="metric">
        <span class="metric-label">Investigations in page</span>
        <span class="metric-value">{len(page.investigations)}</span>
      </div>
      <div class="metric">
        <span class="metric-label">Current filter</span>
        <span class="metric-value">{filter_label}</span>
      </div>
      <div class="metric">
        <span class="metric-label">Ledger head</span>
        <code class="metric-value truncate" title="{head_title}">
          #{summary.head.sequence} · {_digest(summary.head.event_sha256)}
        </code>
      </div>
    </section>

    <p class="boundary-note">
      Queue membership is an investigative lead, not gate evidence. A change case must supply
      independent failure adjudication, causal evidence, proposed intervention, and controls.
    </p>

    <section aria-labelledby="latest-investigations-title">
      <div class="section-heading">
        <h2 id="latest-investigations-title">Latest queue revisions</h2>
        <p>Newest update first · minimized exact subjects</p>
      </div>
      <div class="case-list">{cards}</div>
      {pagination}
    </section>
  </main>
  <footer class="footer">
    Causure {PACKAGE_VERSION} · Candidate-only investigation index ·
    Raw traces and span references remain outside the browser view.
  </footer>
</body>
</html>
"""
    return document.encode("utf-8")


def _investigation_observation_rows(view: TeamInvestigationView) -> str:
    rows: list[str] = []
    for observation in view.record.observations:
        actor = (
            f"{observation.attached_by.identity_provider} / {observation.attached_by.subject_id}"
        )
        model = ", ".join(observation.model_identifiers) or "none retained"
        provider = ", ".join(observation.provider_identifiers) or "none retained"
        rows.append(
            "<tr>"
            f"<td><code>{_escape(observation.fixture_id)}</code><br>"
            f'<span class="mono">{_escape(observation.cluster_id[:22])}…</span></td>'
            f"<td>{observation.span_count} spans<br>"
            f"{observation.root_span_count} roots · {observation.error_span_count} errors</td>"
            f"<td>{_escape(model)}<br>{_escape(provider)}</td>"
            f"<td>{_escape(observation.attached_at)}<br>{_escape(actor)}</td>"
            f"<td>{_escape(_format_bytes(observation.fixture.byte_count))}<br>"
            f'<span class="mono" title="{_escape(observation.fixture.sha256)}">'
            f"{_digest(observation.fixture.sha256)}</span></td>"
            "</tr>"
        )
    return "".join(rows)


def render_team_investigation_detail(detail: TeamInvestigationDetail) -> bytes:
    """Render one minimized candidate-only investigation without raw trace content."""

    if type(detail) is not TeamInvestigationDetail:
        raise TypeError("detail must be a TeamInvestigationDetail")
    summary = detail.summary
    view = detail.investigation
    record = view.record
    opened_by = f"{record.opened_by.identity_provider} / {record.opened_by.subject_id}"
    assigned_to = (
        "unassigned"
        if record.assigned_to is None
        else f"{record.assigned_to.identity_provider} / {record.assigned_to.subject_id}"
    )
    resolution = "open" if record.resolution is None else record.resolution.value
    linkage = "none"
    if record.linked_case_id is not None:
        linkage = (
            f'<a href="/team/cases/{_escape(record.linked_case_id)}">'
            f"case {_escape(record.linked_case_id)}</a>"
        )
    elif record.duplicate_of is not None:
        linkage = (
            f'<a href="/team/investigations/{_escape(record.duplicate_of)}">'
            f"investigation {_escape(record.duplicate_of)}</a>"
        )
    publishing_actor = (
        f"{view.event.principal.identity_provider} / {view.event.principal.subject_id}"
    )
    retention = f"{view.event.retention.class_id} through {view.event.retention.retain_until}"
    document = f"""<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <meta name="robots" content="noindex, nofollow, noarchive">
  <title>{_escape(record.title)} · Causure</title>
  <link rel="stylesheet" href="/team.css">
</head>
<body>
  <header class="topbar">
    <div class="topbar-inner">
      <div class="brand">
        <span class="brand-mark" aria-hidden="true">PB</span>
        <span>Causure</span>
      </div>
      <div class="top-actions">
        <a class="nav-link" href="/team/cases">Change cases</a>
        <a class="nav-link" href="/team">Audit ledger</a>
        <span class="read-only">Read-only evidence</span>
      </div>
    </div>
  </header>
  <main>
    <a class="back-link" href="/team/investigations">← All investigations</a>
    <section class="detail-header" aria-labelledby="investigation-title">
      <p class="eyebrow">
        {_escape(summary.tenant_id)} · {_escape(record.investigation_id)}
      </p>
      <h1 id="investigation-title">{_escape(record.title)}</h1>
      <p class="lede">
        Candidate trace clusters explicitly grouped for investigation. No failure or causal
        claim is inferred by this record.
      </p>
      <div class="roles" aria-label="Your current tenant roles">{_roles_html(summary)}</div>
    </section>

    <section class="metrics" aria-label="Investigation queue state">
      <div class="metric">
        <span class="metric-label">Status</span>
        <span class="metric-value">{_escape(record.status.value)}</span>
      </div>
      <div class="metric">
        <span class="metric-label">Priority</span>
        <span class="metric-value">{_escape(record.priority.value)}</span>
      </div>
      <div class="metric">
        <span class="metric-label">Candidate clusters</span>
        <span class="metric-value">{len(record.observations)}</span>
      </div>
    </section>

    <p class="boundary-note">
      Candidate only · gate eligible: no · causal claims inferred: no. Closing an investigation
      as “change case opened” links workflow records; it does not convert these trace summaries
      into proof.
    </p>

    <div class="detail-grid">
      <section class="panel" aria-labelledby="queue-title">
        <h2 id="queue-title">Queue state</h2>
        <dl class="data-grid">
          <div><dt>Opened</dt><dd>{_escape(record.created_at)}</dd></div>
          <div><dt>Updated</dt><dd>{_escape(record.updated_at)}</dd></div>
          <div><dt>Opened by</dt><dd>{_escape(opened_by)}</dd></div>
          <div><dt>Assigned to</dt><dd>{_escape(assigned_to)}</dd></div>
          <div><dt>Resolution</dt><dd>{_escape(resolution)}</dd></div>
          <div><dt>Linkage</dt><dd>{linkage}</dd></div>
        </dl>
      </section>

      <section class="panel" aria-labelledby="semantics-title">
        <h2 id="semantics-title">Semantic boundary</h2>
        <dl class="data-grid">
          <div><dt>Candidate only</dt><dd>yes</dd></div>
          <div><dt>Gate eligible</dt><dd>no</dd></div>
          <div><dt>Causal claims inferred</dt><dd>no</dd></div>
          <div><dt>Record revision</dt><dd>{record.revision}</dd></div>
        </dl>
      </section>

      <section class="panel panel-wide" aria-labelledby="observations-title">
        <h2 id="observations-title">Attached candidate clusters</h2>
        <div class="table-wrap"><table>
          <thead><tr>
            <th>Fixture / cluster</th><th>Counts</th><th>Safe identifiers</th>
            <th>Attached</th><th>Exact fixture subject</th>
          </tr></thead>
          <tbody>{_investigation_observation_rows(view)}</tbody>
        </table></div>
      </section>

      <section class="panel panel-wide" aria-labelledby="investigation-audit-title">
        <h2 id="investigation-audit-title">Audit binding</h2>
        <dl class="data-grid">
          <div><dt>Ledger sequence</dt><dd>{view.event.sequence}</dd></div>
          <div><dt>Event digest</dt><dd class="mono">{_escape(view.event.event_sha256)}</dd></div>
          <div><dt>Publishing actor</dt><dd>{_escape(publishing_actor)}</dd></div>
          <div><dt>Retention</dt><dd>{_escape(retention)}</dd></div>
          <div>
            <dt>Record subject</dt>
            <dd class="mono">{_escape(view.event.payload.sha256)}</dd>
          </div>
          <div><dt>Record bytes</dt><dd>{_format_bytes(view.event.payload.byte_count)}</dd></div>
        </dl>
      </section>
    </div>
  </main>
  <footer class="footer">
    Causure {PACKAGE_VERSION} · Minimized investigation revision {record.revision} ·
    Raw fixture bodies and span references remain outside the browser view.
  </footer>
</body>
</html>
"""
    return document.encode("utf-8")


def _hypothesis_rows(view: TeamCaseView) -> str:
    rows: list[str] = []
    for hypothesis in view.record.evidence.hypotheses:
        if hypothesis.intervention_present:
            intervention = (
                f"{'isolated' if hypothesis.intervention_isolated else 'not isolated'} · "
                f"{hypothesis.intervention_resolved_count}/"
                f"{hypothesis.intervention_trial_count} resolved"
            )
        else:
            intervention = "not recorded"
        rows.append(
            "<tr>"
            f"<td><code>{_escape(hypothesis.component.value)}</code></td>"
            f"<td>{hypothesis.confidence:.1%}</td>"
            f"<td>{hypothesis.evidence_count}</td>"
            f"<td>{_escape(intervention)}</td>"
            "</tr>"
        )
    return "".join(rows)


def _finding_rows(view: TeamCaseView) -> str:
    if not view.record.review.findings:
        return '<tr><td colspan="3">No findings recorded.</td></tr>'
    return "".join(
        (
            "<tr>"
            f'<td><span class="stage status-{_escape(finding.status.value)}">'
            f"{_escape(finding.status.value)}</span></td>"
            f"<td><code>{_escape(finding.code)}</code></td>"
            f"<td>{_escape(finding.consequence.value)}</td>"
            "</tr>"
        )
        for finding in view.record.review.findings
    )


def _delivery_html(view: TeamCaseView) -> str:
    delivery = view.record.delivery
    if delivery is None:
        return '<p class="case-summary">No Azure delivery receipt has been recorded.</p>'
    if delivery.changeset_id is not None:
        target = f"changeset {delivery.changeset_id}"
    else:
        target = f"shelveset {delivery.shelveset_name};{delivery.shelveset_owner}"
    work_items = ", ".join(str(item) for item in delivery.work_item_ids) or "none"
    return f"""
<dl class="data-grid">
  <div><dt>TFVC target</dt><dd>{_escape(target)}</dd></div>
  <div><dt>Server path</dt><dd><code>{_escape(delivery.server_path)}</code></dd></div>
  <div><dt>Build</dt><dd>{delivery.build_id} · {_escape(delivery.build_number)}</dd></div>
  <div><dt>Work items</dt><dd>{_escape(work_items)}</dd></div>
  <div><dt>Published</dt><dd>{_escape(delivery.published_at)}</dd></div>
  <div><dt>Receipt checked</dt><dd>{_escape(delivery.verified_at)}</dd></div>
</dl>""".strip()


def _approval_html(view: TeamCaseView) -> str:
    approval = view.record.approval
    if approval is None:
        return '<p class="case-summary">No authenticated approval receipt has been recorded.</p>'
    exceptions = ", ".join(approval.exception_finding_codes) or "none"
    actor = f"{approval.identity_provider} / {approval.subject_id}"
    return f"""
<dl class="data-grid">
  <div><dt>Recorded action</dt><dd>{_escape(approval.action.value)}</dd></div>
  <div><dt>Approver</dt><dd class="mono">{_escape(actor)}</dd></div>
  <div>
    <dt>Authority</dt>
    <dd>{_escape(approval.authority_id)} / {_escape(approval.key_id)}</dd>
  </div>
  <div><dt>Authentication</dt><dd>{_escape(approval.authentication_method.value)}</dd></div>
  <div><dt>Issued</dt><dd>{_escape(approval.issued_at)}</dd></div>
  <div><dt>Expires</dt><dd>{_escape(approval.expires_at)}</dd></div>
  <div><dt>Verified at</dt><dd>{_escape(approval.checked_at)}</dd></div>
  <div><dt>Exception scope</dt><dd>{_escape(exceptions)}</dd></div>
</dl>""".strip()


def _canary_html(view: TeamCaseView) -> str:
    canary = view.record.canary
    if canary is None:
        return '<p class="case-summary">No post-deployment canary result has been recorded.</p>'
    rows = "".join(
        (
            "<tr>"
            f"<td><code>{_escape(metric.metric_id)}</code></td>"
            f"<td>{_escape(metric.direction.value)}</td>"
            f"<td>{metric.baseline_rate:.3%}</td>"
            f"<td>{metric.candidate_rate:.3%}</td>"
            f"<td>{metric.confidence_lower:.3%} to {metric.confidence_upper:.3%}</td>"
            f'<td><span class="stage status-{_escape(metric.status.value)}">'
            f"{_escape(metric.status.value)}</span></td>"
            "</tr>"
        )
        for metric in canary.metrics
    )
    return f"""
<p>
  <span class="stage status-{_escape(canary.decision.value)}">
    {_escape(canary.decision.value)}
  </span>
  {_escape(canary.summary)}
</p>
<dl class="data-grid">
  <div><dt>Comparison</dt><dd>{_escape(canary.comparison_id)}</dd></div>
  <div><dt>Sequential look</dt><dd>{canary.look_number} of {canary.maximum_looks}</dd></div>
  <div><dt>Baseline sample</dt><dd>{canary.baseline_sample_count:,}</dd></div>
  <div><dt>Candidate sample</dt><dd>{canary.candidate_sample_count:,}</dd></div>
  <div>
    <dt>Window</dt>
    <dd>{_escape(canary.window_started_at)} to {_escape(canary.window_ended_at)}</dd>
  </div>
  <div><dt>Compared</dt><dd>{_escape(canary.compared_at)}</dd></div>
</dl>
<div class="table-wrap">
  <table>
    <thead><tr><th>Metric</th><th>Better</th><th>Baseline</th><th>Candidate</th><th>CI</th><th>Status</th></tr></thead>
    <tbody>{rows}</tbody>
  </table>
</div>""".strip()


def _artifact_html(view: TeamCaseView) -> str:
    sources = view.record.sources
    artifacts: list[tuple[str, object]] = [
        ("Change case", sources.change_case),
        ("Review result", sources.review_result),
    ]
    for label, subject in (
        ("Review report", sources.review_report),
        ("Azure publication", sources.azure_publication),
        ("Azure verification", sources.azure_verification),
        ("Approval verification", sources.approval_verification),
        ("Canary result", sources.canary_result),
    ):
        if subject is not None:
            artifacts.append((label, subject))
    rows: list[str] = []
    for label, subject in artifacts:
        canonical = ""
        if isinstance(subject, TeamCaseChangeSubject):
            canonical = (
                f'<span class="artifact-subject mono">canonical:'
                f"{_escape(subject.canonical_sha256)}</span>"
            )
        rows.append(
            "<li>"
            f'<span class="artifact-role">{_escape(label)}</span>'
            f'<span class="artifact-subject">{_escape(subject.media_type)} · '
            f"{_escape(_format_bytes(subject.byte_count))}</span>"
            f'<span class="artifact-subject mono">sha256:'
            f"{_escape(subject.sha256)}</span>"
            f"{canonical}</li>"
        )
    return "".join(rows)


def render_team_case_detail(detail: TeamCaseDetail) -> bytes:
    """Render one full minimized case record without loading raw source artifacts."""

    if type(detail) is not TeamCaseDetail:
        raise TypeError("detail must be a TeamCaseDetail")
    summary = detail.summary
    view = detail.case
    record = view.record
    approval_label = record.approval.action.value if record.approval else "not recorded"
    canary_label = record.canary.decision.value if record.canary else "not recorded"
    oracle_label = (
        f"{record.evidence.oracle_kind.value} · "
        f"{'independent' if record.evidence.oracle_independent else 'not independent'}"
    )
    reproduction_label = (
        f"{record.evidence.reproduced_trial_count}/{record.evidence.reproduction_trial_count}"
    )
    validation_label = (
        f"{record.evidence.validation_candidate_passed_count}/"
        f"{record.evidence.validation_case_count}"
    )
    publishing_actor = (
        f"{view.event.principal.identity_provider} / {view.event.principal.subject_id}"
    )
    retention_label = f"{view.event.retention.class_id} through {view.event.retention.retain_until}"
    document = f"""<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <meta name="robots" content="noindex, nofollow, noarchive">
  <title>{_escape(record.evidence.title)} · Causure</title>
  <link rel="stylesheet" href="/team.css">
</head>
<body>
  <header class="topbar">
    <div class="topbar-inner">
      <div class="brand">
        <span class="brand-mark" aria-hidden="true">PB</span>
        <span>Causure</span>
      </div>
      <div class="top-actions">
        <a class="nav-link" href="/team/investigations">Investigations</a>
        <a class="nav-link" href="/team">Audit ledger</a>
        <span class="read-only">Read-only evidence</span>
      </div>
    </div>
  </header>
  <main>
    <a class="back-link" href="/team/cases">← All change cases</a>
    <section class="detail-header" aria-labelledby="case-title">
      <p class="eyebrow">{_escape(summary.tenant_id)} · {_escape(record.case_id)}</p>
      <h1 id="case-title">{_escape(record.evidence.title)}</h1>
      <p class="lede">{_escape(record.evidence.proposed_summary)}</p>
      <div class="roles" aria-label="Your current tenant roles">{_roles_html(summary)}</div>
    </section>

    <section class="metrics" aria-label="Case decision summary">
      <div class="metric">
        <span class="metric-label">Gate review</span>
        <span class="metric-value">{_escape(record.review.decision.value)}</span>
      </div>
      <div class="metric">
        <span class="metric-label">Recorded approval</span>
        <span class="metric-value">{_escape(approval_label)}</span>
      </div>
      <div class="metric">
        <span class="metric-label">Canary outcome</span>
        <span class="metric-value">{_escape(canary_label)}</span>
      </div>
    </section>

    <p class="boundary-note">
      This page is an immutable minimized index derived from exact artifacts. A verification
      receipt is point-in-time evidence, not proof that an approval, key, build, or deployment
      remains current. Revalidate at every decision boundary.
    </p>

    <div class="detail-grid">
      <section class="panel" aria-labelledby="change-title">
        <h2 id="change-title">Proposed change</h2>
        <p>{_escape(record.evidence.prediction)}</p>
        <dl class="data-grid">
          <div><dt>Component</dt><dd>{_escape(record.evidence.proposed_component.value)}</dd></div>
          <div><dt>Changed surfaces</dt><dd>{record.evidence.changed_surface_count}</dd></div>
          <div><dt>Known risks</dt><dd>{record.evidence.known_risk_count}</dd></div>
          <div>
            <dt>Change reference</dt>
            <dd><code>{_escape(record.evidence.change_ref)}</code></dd>
          </div>
        </dl>
      </section>

      <section class="panel" aria-labelledby="verification-title">
        <h2 id="verification-title">Verification snapshot</h2>
        <dl class="data-grid">
          <div><dt>Severity</dt><dd>{_escape(record.evidence.severity.value)}</dd></div>
          <div><dt>Requirement</dt><dd>{_escape(record.evidence.requirement_status.value)}</dd></div>
          <div><dt>Oracle</dt><dd>{_escape(oracle_label)}</dd></div>
          <div><dt>Reproduction</dt><dd>{reproduction_label}</dd></div>
          <div><dt>Candidate checks</dt><dd>{validation_label}</dd></div>
          <div>
            <dt>Critical failures</dt>
            <dd>{record.evidence.validation_critical_failed_count}</dd>
          </div>
        </dl>
      </section>

      <section class="panel panel-wide" aria-labelledby="causal-title">
        <h2 id="causal-title">Causal hypotheses</h2>
        <div class="table-wrap"><table>
          <thead><tr>
            <th>Component</th><th>Confidence</th><th>Evidence subjects</th>
            <th>Intervention</th>
          </tr></thead>
          <tbody>{_hypothesis_rows(view)}</tbody>
        </table></div>
      </section>

      <section class="panel panel-wide" aria-labelledby="review-title">
        <h2 id="review-title">Gate review</h2>
        <p>
          <span class="stage status-{_escape(record.review.decision.value)}">
            {_escape(record.review.decision.value)}
          </span>
          {_escape(record.review.summary)}
        </p>
        <div class="table-wrap"><table>
          <thead><tr><th>Status</th><th>Finding</th><th>Consequence</th></tr></thead>
          <tbody>{_finding_rows(view)}</tbody>
        </table></div>
      </section>

      <section class="panel" aria-labelledby="delivery-title">
        <h2 id="delivery-title">Azure delivery</h2>
        {_delivery_html(view)}
      </section>

      <section class="panel" aria-labelledby="approval-title">
        <h2 id="approval-title">Approval receipt</h2>
        {_approval_html(view)}
      </section>

      <section class="panel panel-wide" aria-labelledby="canary-title">
        <h2 id="canary-title">Post-deployment canary</h2>
        {_canary_html(view)}
      </section>

      <section class="panel panel-wide" aria-labelledby="artifacts-title">
        <h2 id="artifacts-title">Exact artifact subjects</h2>
        <ul class="artifact-list">{_artifact_html(view)}</ul>
      </section>

      <section class="panel panel-wide" aria-labelledby="audit-title">
        <h2 id="audit-title">Audit binding</h2>
        <dl class="data-grid">
          <div><dt>Case revision</dt><dd>{record.revision}</dd></div>
          <div><dt>Published</dt><dd>{_escape(record.published_at)}</dd></div>
          <div><dt>Ledger sequence</dt><dd>{view.event.sequence}</dd></div>
          <div><dt>Event digest</dt><dd class="mono">{_escape(view.event.event_sha256)}</dd></div>
          <div><dt>Publishing actor</dt><dd>{_escape(publishing_actor)}</dd></div>
          <div><dt>Retention</dt><dd>{_escape(retention_label)}</dd></div>
        </dl>
      </section>
    </div>
  </main>
  <footer class="footer">
    Causure {PACKAGE_VERSION} · Minimized case revision {record.revision} ·
    Raw source artifacts remain outside the browser view.
  </footer>
</body>
</html>
"""
    return document.encode("utf-8")
