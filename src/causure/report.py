"""Human-readable and machine-readable review reports."""

from __future__ import annotations

import json
from typing import Any

from causure.constants import CheckStatus, Consequence
from causure.models import ChangeCase, ReviewResult, to_jsonable


def render_json(result: ReviewResult) -> str:
    """Render a stable JSON review result."""

    return (
        json.dumps(
            to_jsonable(result),
            allow_nan=False,
            ensure_ascii=False,
            indent=2,
        )
        + "\n"
    )


def _label(value: str) -> str:
    return value.replace("_", " ").upper()


def _escape_table(value: Any) -> str:
    if value is None:
        return "not measured"
    return str(value).replace("|", "\\|").replace("\n", " ")


def _format_rate(value: int | float | None) -> str:
    if value is None:
        return "not measured"
    return f"{float(value):.1%}"


def _status_label(status: CheckStatus) -> str:
    return {
        CheckStatus.PASS: "PASS",
        CheckStatus.FAIL: "FAIL",
        CheckStatus.WARNING: "WARN",
    }[status]


def render_markdown(case: ChangeCase, result: ReviewResult) -> str:
    """Render an evidence report suitable for a build summary or review record."""

    metrics = result.metrics
    lines = [
        "# Causure evidence report",
        "",
        f"> **{_label(result.decision.value)}** - {result.summary}",
        "",
        "## Decision",
        "",
        "| Field | Value |",
        "| --- | --- |",
        f"| Case | `{_escape_table(result.case_id)}` |",
        f"| Proposed component | `{_escape_table(result.component.value)}` |",
        f"| Recommended action | **{_label(result.recommended_action.value)}** |",
        f"| Policy | `{_escape_table(result.policy_name)}` |",
        "",
        "## Evidence snapshot",
        "",
        "| Measure | Result |",
        "| --- | ---: |",
        f"| Reproduction | {_format_rate(metrics.get('reproduction_rate'))} "
        f"across {metrics.get('reproduction_trials', 0)} trials |",
        f"| Attribution confidence | {_format_rate(metrics.get('attribution_confidence'))} |",
        f"| Intervention success | {_format_rate(metrics.get('intervention_success_rate'))} |",
        f"| Positive controls | {_format_rate(metrics.get('positive_pass_rate'))} "
        f"across {metrics.get('positive_controls', 0)} cases |",
        f"| Negative controls | {_format_rate(metrics.get('negative_pass_rate'))} "
        f"across {metrics.get('negative_controls', 0)} cases |",
        f"| Regression controls | {_format_rate(metrics.get('regression_pass_rate'))} "
        f"across {metrics.get('regression_controls', 0)} cases |",
        f"| Cost change | {_format_rate(metrics.get('cost_change_ratio'))} |",
        f"| p95 latency change | {_format_rate(metrics.get('latency_change_ratio'))} |",
        "",
        "## Gate checks",
        "",
        "| Status | Check | Finding |",
        "| --- | --- | --- |",
    ]
    for finding in result.findings:
        lines.append(
            f"| {_status_label(finding.status)} | `{finding.code}` | "
            f"{_escape_table(finding.message)} |"
        )

    required_findings = [
        finding for finding in result.findings if finding.consequence is not Consequence.NONE
    ]
    if required_findings:
        lines.extend(["", "## Required resolution", ""])
        for finding in required_findings:
            lines.append(
                f"- `{finding.code}` ({_label(finding.consequence.value)}): {finding.message}"
            )

    lines.extend(
        [
            "",
            "## Proposed change",
            "",
            f"**Summary:** {case.proposed_change.summary}",
            "",
            f"**Predicted effect:** {case.proposed_change.prediction}",
            "",
            "**Expected unaffected behavior:**",
            "",
        ]
    )
    lines.extend(f"- {behavior}" for behavior in case.proposed_change.expected_unaffected_behaviors)
    if case.proposed_change.known_risks:
        lines.extend(["", "**Known risks:**", ""])
        lines.extend(f"- {risk}" for risk in case.proposed_change.known_risks)

    lines.extend(
        [
            "",
            "## Audit",
            "",
            f"- Evidence document SHA-256: `{result.input_sha256}`",
            f"- Engine version: `{result.engine_version}`",
            f"- Reviewed at: `{result.reviewed_at}`",
            f"- Change reference: `{case.proposed_change.change_ref}`",
            "",
        ]
    )
    return "\n".join(lines)
