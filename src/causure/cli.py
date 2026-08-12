"""Causure command line interface."""

from __future__ import annotations

import argparse
import json
import os
import sys
from collections.abc import Sequence
from pathlib import Path

from causure.adapters import MAX_CASE_GENERATION_BYTES, CaseGenerationBudget
from causure.approvals import (
    DEFAULT_MAX_APPROVAL_REVOCATION_AGE_SECONDS,
    MAX_APPROVAL_ASSERTION_BYTES,
    MAX_APPROVAL_POLICY_BYTES,
    MAX_APPROVAL_REVOCATION_AGE_SECONDS,
    create_approval_assertion,
    parse_approval_revocation_list,
    parse_approval_trust_store,
    render_approval_assertion,
    render_approval_verification,
    verify_approval_assertion,
)
from causure.attestations import (
    DEFAULT_MAX_REVOCATION_AGE_SECONDS,
    MAX_ATTESTED_ARTIFACT_BYTES,
    MAX_KEY_DOCUMENT_BYTES,
    MAX_REVOCATION_AGE_SECONDS,
    create_artifact_attestation,
    parse_artifact_attestation,
    parse_attestation_revocation_list,
    parse_attestation_trust_store,
    public_key_base64url_from_pem,
    render_artifact_attestation,
    render_attestation_verification,
    utc_timestamp,
    verify_artifact_attestation,
)
from causure.azure_devops import (
    DEFAULT_MAX_PUBLICATION_AGE_SECONDS,
    MAX_AZURE_PUBLICATION_BYTES,
    MAX_AZURE_VERIFICATION_BYTES,
    MAX_PUBLICATION_AGE_SECONDS,
    MAX_REVIEW_REPORT_BYTES,
    MAX_REVIEW_RESULT_BYTES,
    azure_context_from_environment,
    create_azure_review_publication,
    render_azure_build_summary,
    render_azure_review_publication,
    render_azure_review_verification,
    verify_azure_review_publication,
)
from causure.canary import (
    MAX_CANARY_CHANGE_CASE_BYTES,
    MAX_CANARY_OBSERVATION_BYTES,
    MAX_CANARY_POLICY_BYTES,
    MAX_CANARY_REVIEW_RESULT_BYTES,
    compare_canary_outcomes,
    render_canary_markdown,
    render_canary_result,
)
from causure.case_creation import (
    collect_guided_case,
    create_case_workspace,
    default_case_output,
    load_case_policy,
    render_case_creation_summary,
    render_case_preview,
)
from causure.collector import (
    DEFAULT_MAX_SPANS,
    collect_otlp_trace_manifest,
    render_trace_manifest,
)
from causure.constants import (
    PACKAGE_VERSION,
    ApprovalAction,
    ApprovalAuthenticationMethod,
    CanaryDecision,
    Component,
    Decision,
    TeamAction,
    TeamAuditOutcome,
    TeamResourceType,
    TraceSourceFormat,
)
from causure.engine import review_case
from causure.errors import DocumentValidationError
from causure.fixtures import (
    DEFAULT_MAX_CLUSTERS,
    MAX_MANIFEST_DOCUMENT_BYTES,
    generate_investigation_fixture,
    render_investigation_fixture,
)
from causure.github_checks import (
    DEFAULT_GITHUB_CHECK_RUN_TIMEOUT_SECONDS,
    MAX_GITHUB_CHECK_RUN_TIMEOUT_SECONDS,
    create_github_check_run_request,
    publish_github_check_run,
    render_github_check_run_receipt,
    render_github_check_run_request,
    render_github_check_run_summary,
)
from causure.github_review import (
    DEFAULT_MAX_GITHUB_PUBLICATION_AGE_SECONDS,
    MAX_GITHUB_CHANGE_CASE_BYTES,
    MAX_GITHUB_PUBLICATION_AGE_SECONDS,
    MAX_GITHUB_PUBLICATION_BYTES,
    MAX_GITHUB_REVIEW_REPORT_BYTES,
    MAX_GITHUB_REVIEW_RESULT_BYTES,
    MAX_GITHUB_VERIFICATION_BYTES,
    create_github_review_publication,
    github_context_from_environment,
    render_github_review_publication,
    render_github_review_verification,
    verify_github_review_publication,
)
from causure.investigation_workspace import (
    default_investigation_output,
    load_verified_investigation_workspace,
    prepare_investigation,
    render_investigation_preview,
    render_workspace_summary,
    select_cluster_ids,
    write_investigation_workspace,
)
from causure.io import (
    MAX_TRACE_DOCUMENT_BYTES,
    InputDocumentError,
    atomic_write_bytes,
    atomic_write_text,
    load_change_case,
    load_policy,
    read_json,
    read_json_with_bytes,
)
from causure.onboarding import (
    configure_github_component,
    configure_trusted_adapter,
    initialize_project,
    inspect_environment,
    render_demo_summary,
    render_doctor_json,
    render_doctor_text,
    render_github_configuration_summary,
    render_initialization_summary,
    render_trusted_adapter_configuration_summary,
    run_demo,
)
from causure.openai_quota_host import (
    load_openai_quota_host_configuration,
    serve_openai_quota_host,
)
from causure.openai_quota_pilot import prepare_openai_quota_pilot_state
from causure.report import render_json, render_markdown
from causure.runner import AdapterRunError
from causure.schema import get_schema
from causure.team_entra_refresh import (
    DEFAULT_ENTRA_REFRESH_TIMEOUT_SECONDS,
    load_entra_refresh_configuration,
    refresh_entra_trust_file,
)
from causure.team_host import load_team_host_configuration, serve_team_host
from causure.team_service import (
    MAX_TEAM_ACCESS_POLICY_BYTES,
    MAX_TEAM_AUDIT_EVENT_BYTES,
    MAX_TEAM_AUDIT_EXPORT_BYTES,
    MAX_TEAM_AUDIT_PAYLOAD_BYTES,
    MAX_TEAM_AUTHORIZATION_BYTES,
    create_team_audit_event,
    create_team_audit_export,
    create_team_authorization,
    render_team_audit_event,
    render_team_audit_export,
    render_team_audit_verification,
    render_team_authorization,
    verify_team_audit_export,
)
from causure.team_store import SQLiteTeamStore, render_team_ledger_head
from causure.trusted_case_generation import (
    generate_configured_github_case,
    render_trusted_case_generation_summary,
)


def _read_bounded_bytes(path: str, *, maximum: int, description: str) -> bytes:
    if path == "-":
        raise ValueError(f"{description} requires a file path")
    source = Path(path)
    try:
        size = source.stat().st_size
        if not 1 <= size <= maximum:
            raise ValueError(f"{description} must contain from 1 to {maximum} bytes")
        content = source.read_bytes()
    except OSError as exc:
        raise ValueError(f"could not read {description} {source}: {exc}") from exc
    if len(content) != size:
        raise ValueError(f"{description} changed while it was being read")
    return content


def _password_from_environment(variable_name: str | None) -> bytes | None:
    if variable_name is None:
        return None
    value = os.environ.get(variable_name)
    if not value:
        raise ValueError(
            f"private-key password environment variable is unset or empty: {variable_name}"
        )
    return value.encode("utf-8")


def _secret_from_environment(variable_name: str, *, description: str) -> str:
    value = os.environ.get(variable_name)
    if not value:
        raise ValueError(f"{description} environment variable is unset or empty: {variable_name}")
    return value


def _reject_output_collision(output: str | None, *inputs: str) -> None:
    if output is None:
        return
    output_path = Path(output).resolve()
    if any(output_path == Path(input_path).resolve() for input_path in inputs):
        raise ValueError("output path must differ from every input path")


def _primary_help() -> str:
    """Render the short first-run workflow instead of the enterprise command catalog."""

    return "\n".join(
        [
            f"Causure {PACKAGE_VERSION}",
            "Evidence-gated change control for production AI agents.",
            "",
            "Start with a synthetic decision:",
            "  causure demo",
            "",
            "Use Causure on your own trace export in three commands:",
            "  causure init my-agent-project",
            "  causure investigate <path-to-agent-traces.json>",
            "  causure case create <path-to-investigation>",
            "",
            "Connect a reviewed case to pull requests:",
            "  causure github-configure --help",
            "",
            "Diagnose local setup:",
            "  causure doctor my-agent-project",
            "",
            "Run 'causure COMMAND --help' for command options.",
            "Run 'causure --help-all' for automation and enterprise commands.",
        ]
    )


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="causure",
        description="Evidence-gated change control for production AI agents.",
    )
    parser.add_argument(
        "--version",
        action="version",
        version=f"%(prog)s {PACKAGE_VERSION}",
    )
    subparsers = parser.add_subparsers(dest="command", required=True, metavar="COMMAND")

    demo_parser = subparsers.add_parser(
        "demo",
        help="run a deterministic two-story synthetic demonstration",
    )
    demo_parser.add_argument(
        "--output",
        default="causure-demo",
        help="create the demo in this new directory (default: causure-demo)",
    )

    init_parser = subparsers.add_parser(
        "init",
        help="create a safe local Causure project configuration",
    )
    init_parser.add_argument(
        "directory",
        nargs="?",
        default=".",
        help="project directory to initialize (default: current directory)",
    )
    init_parser.add_argument(
        "--project-id",
        help="stable lowercase project ID (default: derived from the directory name)",
    )

    github_configure_parser = subparsers.add_parser(
        "github-configure",
        help="register one GitHub component without editing configuration JSON",
    )
    github_configure_parser.add_argument(
        "--project",
        default=".",
        help="initialized project directory (default: current directory)",
    )
    github_configure_parser.add_argument(
        "--component-id",
        required=True,
        help="stable lowercase ID for this configured harness component",
    )
    github_configure_parser.add_argument(
        "--component",
        choices=tuple(component.value for component in Component),
        required=True,
        help="Causure component type represented by the case",
    )
    github_configure_parser.add_argument(
        "--path",
        action="append",
        required=True,
        help="repository-relative path pattern; repeat for additional * or ** patterns",
    )
    github_configure_parser.add_argument(
        "--case",
        required=True,
        help="repository-relative canonical change-case JSON path",
    )
    github_configure_parser.add_argument(
        "--retention-days",
        type=int,
        help="evidence artifact retention from 1 to 90 days (default: keep configured value)",
    )

    adapter_configure_parser = subparsers.add_parser(
        "adapter-configure",
        help="register a reviewed adapter entry point without executing it",
    )
    adapter_configure_parser.add_argument(
        "--project",
        default=".",
        help="initialized project directory (default: current directory)",
    )
    adapter_configure_parser.add_argument(
        "--adapter-id",
        required=True,
        help="stable lowercase ID for the trusted adapter",
    )
    adapter_configure_parser.add_argument(
        "--kind",
        choices=("replay", "evaluator", "case_generator"),
        required=True,
        help="adapter protocol implemented by the entry point",
    )
    adapter_configure_parser.add_argument(
        "--entry-point",
        required=True,
        help="reviewed Python entry point in module.path:callable format",
    )
    adapter_configure_parser.add_argument(
        "--component-id",
        help="optionally bind a case_generator to an existing GitHub component",
    )

    doctor_parser = subparsers.add_parser(
        "doctor",
        help="inspect local readiness without writing files or contacting services",
    )
    doctor_parser.add_argument(
        "directory",
        nargs="?",
        default=".",
        help="project directory to inspect (default: current directory)",
    )
    doctor_parser.add_argument(
        "--format",
        choices=("text", "json"),
        default="text",
        help="diagnostic output format (default: text)",
    )

    investigate_parser = subparsers.add_parser(
        "investigate",
        help="preview and create a redacted investigation from an OTLP JSON export",
    )
    investigate_parser.add_argument("traces", help="path to an OTLP JSON trace export")
    investigate_parser.add_argument(
        "--source-id",
        help="stable non-sensitive source ID (default: derived from the source digest)",
    )
    investigate_parser.add_argument(
        "--investigation-id",
        help="stable investigation ID (default: derived from the source ID)",
    )
    investigate_parser.add_argument(
        "--output",
        help=(
            "create the workspace in this new directory (default: configured artifacts "
            "directory or causure-investigation)"
        ),
    )
    investigate_parser.add_argument(
        "--select",
        metavar="LIST",
        help="candidate numbers or IDs separated by commas; use all for every candidate",
    )
    investigate_parser.add_argument(
        "--yes",
        action="store_true",
        help="save without confirmation; selects all candidates when --select is omitted",
    )
    investigate_parser.add_argument(
        "--preview-only",
        action="store_true",
        help="show the redaction and candidate preview without writing files",
    )
    investigate_parser.add_argument(
        "--max-spans",
        type=int,
        default=DEFAULT_MAX_SPANS,
        help=f"maximum spans to accept (default: {DEFAULT_MAX_SPANS})",
    )
    investigate_parser.add_argument(
        "--max-clusters",
        type=int,
        default=DEFAULT_MAX_CLUSTERS,
        help=f"maximum candidate traces to accept (default: {DEFAULT_MAX_CLUSTERS})",
    )

    case_parser = subparsers.add_parser(
        "case",
        help="create and manage canonical evidence-gate cases",
    )
    case_commands = case_parser.add_subparsers(dest="case_command", required=True)
    case_create_parser = case_commands.add_parser(
        "create",
        help="create and immediately review a case through plain-language questions",
    )
    case_create_parser.add_argument(
        "investigation",
        help="path to a generated investigation workspace",
    )
    case_create_parser.add_argument(
        "--policy",
        help="policy override JSON (default: associated project preset or built-in defaults)",
    )
    case_create_parser.add_argument(
        "--output",
        help="create the case in this new directory (default: project artifacts/cases/case-id)",
    )
    case_create_parser.add_argument(
        "--yes",
        action="store_true",
        help="write the completed case without a final confirmation prompt",
    )
    case_generate_parser = case_commands.add_parser(
        "generate",
        help="run a configured case generator from a separate trusted checkout",
    )
    case_generate_parser.add_argument(
        "--trusted-project",
        default=".",
        help="protected base checkout containing config and adapter code",
    )
    case_generate_parser.add_argument(
        "--candidate-root",
        required=True,
        help="separate untrusted candidate checkout treated only as data",
    )
    case_generate_parser.add_argument("--component-id", required=True)
    case_generate_parser.add_argument("--component-path", required=True)
    case_generate_parser.add_argument("--repository", required=True)
    case_generate_parser.add_argument("--pull-request", required=True, type=int)
    case_generate_parser.add_argument("--base-sha", required=True)
    case_generate_parser.add_argument("--head-sha", required=True)
    case_generate_parser.add_argument("--output-directory", required=True)
    case_generate_parser.add_argument(
        "--timeout-seconds",
        type=float,
        default=60.0,
        help="kill the generator after this wall-clock limit (default: 60)",
    )
    case_generate_parser.add_argument(
        "--maximum-case-bytes",
        type=int,
        default=MAX_CASE_GENERATION_BYTES,
        help=f"maximum canonical case size (default: {MAX_CASE_GENERATION_BYTES})",
    )

    validate_parser = subparsers.add_parser(
        "validate",
        help="validate an evidence bundle without reviewing it",
    )
    validate_parser.add_argument("case", help="path to a change-case JSON file, or - for stdin")

    review_parser = subparsers.add_parser(
        "review",
        help="review an evidence bundle and produce a gate decision",
    )
    review_parser.add_argument("case", help="path to a change-case JSON file, or - for stdin")
    review_parser.add_argument(
        "--policy",
        help="path to a sparse policy override JSON file",
    )
    review_parser.add_argument(
        "--format",
        choices=("markdown", "json"),
        default="markdown",
        help="report format (default: markdown)",
    )
    review_parser.add_argument(
        "--output",
        help="write the report atomically to this path instead of stdout",
    )
    review_parser.add_argument(
        "--result-output",
        help="also write the machine-readable JSON result to this path",
    )
    review_parser.add_argument(
        "--allow-conditional",
        action="store_true",
        help="return exit code 0 for a conditional pass",
    )
    review_parser.add_argument(
        "--quiet",
        action="store_true",
        help="suppress the one-line status when --output is used",
    )

    collect_parser = subparsers.add_parser(
        "collect",
        help="collect a redacted manifest from an OTLP JSON trace export",
    )
    collect_parser.add_argument(
        "traces",
        help="path to an OTLP JSON trace export",
    )
    collect_parser.add_argument(
        "--source-id",
        required=True,
        help="stable, non-sensitive ID for the source artifact",
    )
    collect_parser.add_argument(
        "--format",
        choices=tuple(member.value for member in TraceSourceFormat),
        default=TraceSourceFormat.OTLP_JSON.value,
        help="trace input format (default: otlp-json)",
    )
    collect_parser.add_argument(
        "--max-spans",
        type=int,
        default=DEFAULT_MAX_SPANS,
        help=f"maximum spans to accept (default: {DEFAULT_MAX_SPANS})",
    )
    collect_parser.add_argument(
        "--output",
        help="write the manifest atomically to this path instead of stdout",
    )
    collect_parser.add_argument(
        "--quiet",
        action="store_true",
        help="suppress the one-line status when --output is used",
    )

    fixture_parser = subparsers.add_parser(
        "fixture",
        help="generate a draft investigation fixture from a trace manifest",
    )
    fixture_parser.add_argument(
        "manifest",
        help="path to a redacted trace-manifest JSON file",
    )
    fixture_parser.add_argument(
        "--fixture-id",
        required=True,
        help="stable, non-sensitive ID for the investigation draft",
    )
    fixture_parser.add_argument(
        "--max-clusters",
        type=int,
        default=DEFAULT_MAX_CLUSTERS,
        help=f"maximum candidate traces to accept (default: {DEFAULT_MAX_CLUSTERS})",
    )
    fixture_parser.add_argument(
        "--output",
        help="write the fixture atomically to this path instead of stdout",
    )
    fixture_parser.add_argument(
        "--quiet",
        action="store_true",
        help="suppress the one-line status when --output is used",
    )

    canary_parser = subparsers.add_parser(
        "canary-compare",
        help="compare exact baseline/candidate outcome rates after deployment",
    )
    canary_parser.add_argument(
        "observation",
        help="path to a canary-observation JSON file",
    )
    canary_parser.add_argument(
        "--policy",
        required=True,
        help="path to the exact predeclared canary-policy JSON file",
    )
    canary_parser.add_argument(
        "--case",
        required=True,
        help="path to the exact reviewed change-case JSON file",
    )
    canary_parser.add_argument(
        "--review-result",
        required=True,
        help="path to the exact review-result JSON file",
    )
    canary_parser.add_argument(
        "--format",
        choices=("markdown", "json"),
        default="markdown",
        help="report format (default: markdown)",
    )
    canary_parser.add_argument(
        "--output",
        help="write the report atomically to this path instead of stdout",
    )
    canary_parser.add_argument(
        "--result-output",
        help="also write the machine-readable comparison result to this path",
    )
    canary_parser.add_argument(
        "--allow-continue",
        action="store_true",
        help="return exit code 0 when valid minimum evidence remains inconclusive",
    )
    canary_parser.add_argument(
        "--quiet",
        action="store_true",
        help="suppress the one-line status when --output is used",
    )

    attest_parser = subparsers.add_parser(
        "attest",
        help="create a detached Ed25519 producer attestation for exact artifact bytes",
    )
    attest_parser.add_argument("artifact", help="path to the artifact to attest")
    attest_parser.add_argument(
        "--artifact-id",
        required=True,
        help="stable, non-sensitive ID for the artifact",
    )
    attest_parser.add_argument(
        "--media-type",
        required=True,
        help="lowercase artifact media type, such as application/json",
    )
    attest_parser.add_argument(
        "--producer-id",
        required=True,
        help="producer identity bound to the trusted signing key",
    )
    attest_parser.add_argument(
        "--key-id",
        required=True,
        help="signing-key ID present in the verifier trust store",
    )
    attest_parser.add_argument(
        "--private-key",
        required=True,
        help="path to an Ed25519 private key in PEM form",
    )
    attest_parser.add_argument(
        "--private-key-password-env",
        help="name of an environment variable containing the PEM password",
    )
    attest_parser.add_argument(
        "--issued-at",
        help="explicit UTC issue time (default: current time)",
    )
    attest_parser.add_argument(
        "--expires-at",
        required=True,
        help="exclusive UTC validity deadline",
    )
    attest_parser.add_argument(
        "--retention-class",
        required=True,
        help="organization-defined retention class ID",
    )
    attest_parser.add_argument(
        "--retain-until",
        required=True,
        help="UTC time through which the artifact must be retained",
    )
    attest_parser.add_argument(
        "--revocation-list-id",
        required=True,
        help="revocation-list ID required by the verifier trust store",
    )
    attest_parser.add_argument(
        "--output",
        help="write the detached attestation atomically to this path",
    )
    attest_parser.add_argument(
        "--quiet",
        action="store_true",
        help="suppress the one-line status when --output is used",
    )

    public_key_parser = subparsers.add_parser(
        "public-key",
        help="export an Ed25519 PEM key as raw unpadded base64url",
    )
    public_key_parser.add_argument(
        "key",
        help="path to an Ed25519 public or private PEM key",
    )
    public_key_parser.add_argument(
        "--private-key-password-env",
        help="environment variable containing a private PEM password, when needed",
    )
    public_key_parser.add_argument(
        "--output",
        help="write the public-key value atomically to this path",
    )
    public_key_parser.add_argument(
        "--quiet",
        action="store_true",
        help="suppress the one-line status when --output is used",
    )

    verify_attestation_parser = subparsers.add_parser(
        "verify-attestation",
        help="verify artifact bytes against producer trust and current revocations",
    )
    verify_attestation_parser.add_argument(
        "artifact",
        help="path to the exact artifact named by the attestation",
    )
    verify_attestation_parser.add_argument(
        "attestation",
        help="path to the detached artifact-attestation JSON",
    )
    verify_attestation_parser.add_argument(
        "--trust-store",
        required=True,
        help="path to the protected producer-key trust store",
    )
    verify_attestation_parser.add_argument(
        "--revocations",
        required=True,
        help="path to the current protected revocation list",
    )
    verify_attestation_parser.add_argument(
        "--max-revocation-age-seconds",
        type=int,
        default=DEFAULT_MAX_REVOCATION_AGE_SECONDS,
        help=(
            "maximum accepted revocation-list age "
            f"(default: {DEFAULT_MAX_REVOCATION_AGE_SECONDS}, "
            f"maximum: {MAX_REVOCATION_AGE_SECONDS})"
        ),
    )
    verify_attestation_parser.add_argument(
        "--output",
        help="write a successful verification receipt atomically to this path",
    )
    verify_attestation_parser.add_argument(
        "--quiet",
        action="store_true",
        help="suppress the one-line status when --output is used",
    )

    issue_approval_parser = subparsers.add_parser(
        "issue-approval",
        help="sign an authenticated approver action for exact Azure review artifacts",
    )
    issue_approval_parser.add_argument(
        "publication",
        help="path to the exact Azure review-publication JSON",
    )
    issue_approval_parser.add_argument(
        "verification",
        help="path to the exact pre-approval verification JSON",
    )
    issue_approval_parser.add_argument(
        "result",
        help="path to the exact machine-readable review-result JSON",
    )
    issue_approval_parser.add_argument(
        "--assertion-id",
        required=True,
        help="unique, non-sensitive organizational approval-event ID",
    )
    issue_approval_parser.add_argument(
        "--authority-id",
        required=True,
        help="approval authority bound to the trusted signing key",
    )
    issue_approval_parser.add_argument(
        "--key-id",
        required=True,
        help="signing-key ID present in the approval trust store",
    )
    issue_approval_parser.add_argument(
        "--approver-id",
        required=True,
        help="stable subject ID authenticated by the approval authority",
    )
    issue_approval_parser.add_argument(
        "--identity-provider",
        required=True,
        help="stable identity-provider or organization ID",
    )
    issue_approval_parser.add_argument(
        "--authentication-method",
        choices=tuple(method.value for method in ApprovalAuthenticationMethod),
        required=True,
        help="organizational mechanism that authenticated the approver action",
    )
    issue_approval_parser.add_argument(
        "--authentication-event-id",
        required=True,
        help="stable source approval or authentication-event ID",
    )
    issue_approval_parser.add_argument(
        "--authenticated-at",
        required=True,
        help="UTC time the approver action was authenticated",
    )
    issue_approval_parser.add_argument(
        "--action",
        choices=tuple(action.value for action in ApprovalAction),
        required=True,
        help="approve an approve decision, or record an explicit policy exception",
    )
    issue_approval_parser.add_argument(
        "--finding-code",
        action="append",
        default=[],
        help=(
            "decision-affecting finding covered by an exception; repeat until every "
            "such finding is named"
        ),
    )
    issue_approval_parser.add_argument(
        "--justification",
        help="required bounded justification for an exception action",
    )
    issue_approval_parser.add_argument(
        "--issued-at",
        help="explicit UTC issue time (default: current time)",
    )
    issue_approval_parser.add_argument(
        "--expires-at",
        required=True,
        help=("exclusive UTC deadline, within 24 hours of issue and pre-approval verification"),
    )
    issue_approval_parser.add_argument(
        "--revocation-list-id",
        required=True,
        help="approval-authority revocation-list ID required by the trust store",
    )
    issue_approval_parser.add_argument(
        "--private-key",
        required=True,
        help="path to the authority Ed25519 private key in PEM form",
    )
    issue_approval_parser.add_argument(
        "--private-key-password-env",
        help="name of an environment variable containing the PEM password",
    )
    issue_approval_parser.add_argument(
        "--output",
        help="write the signed approval assertion atomically to this path",
    )
    issue_approval_parser.add_argument(
        "--quiet",
        action="store_true",
        help="suppress the one-line status when --output is used",
    )

    verify_approval_parser = subparsers.add_parser(
        "verify-approval",
        help="verify a signed approver action against the current Azure TFVC build",
    )
    verify_approval_parser.add_argument(
        "assertion",
        help="path to the exact signed approval-assertion JSON",
    )
    verify_approval_parser.add_argument(
        "publication",
        help="path to the exact Azure review-publication JSON",
    )
    verify_approval_parser.add_argument(
        "verification",
        help="path to the exact pre-approval verification JSON",
    )
    verify_approval_parser.add_argument(
        "result",
        help="path to the exact machine-readable review-result JSON",
    )
    verify_approval_parser.add_argument(
        "report",
        help="path to the exact Markdown review report",
    )
    verify_approval_parser.add_argument(
        "--trust-store",
        required=True,
        help="path to the protected approval-authority/action trust store",
    )
    verify_approval_parser.add_argument(
        "--revocations",
        required=True,
        help="path to the current protected approval-key revocation list",
    )
    verify_approval_parser.add_argument(
        "--tfvc-server-path",
        required=True,
        help="protected TFVC root associated with this pipeline, such as $/Project",
    )
    verify_approval_parser.add_argument(
        "--max-revocation-age-seconds",
        type=int,
        default=DEFAULT_MAX_APPROVAL_REVOCATION_AGE_SECONDS,
        help=(
            "maximum accepted approval revocation-list age "
            f"(default: {DEFAULT_MAX_APPROVAL_REVOCATION_AGE_SECONDS}, "
            f"maximum: {MAX_APPROVAL_REVOCATION_AGE_SECONDS})"
        ),
    )
    verify_approval_parser.add_argument(
        "--output",
        help="write a successful approval-verification receipt atomically to this path",
    )
    verify_approval_parser.add_argument(
        "--quiet",
        action="store_true",
        help="suppress the one-line status when --output is used",
    )

    azure_publish_parser = subparsers.add_parser(
        "azure-publish",
        help="bind exact gate artifacts to the current Azure TFVC build",
    )
    azure_publish_parser.add_argument(
        "result",
        help="path to the machine-readable review-result JSON",
    )
    azure_publish_parser.add_argument(
        "report",
        help="path to the corresponding Markdown review report",
    )
    azure_publish_parser.add_argument(
        "--tfvc-server-path",
        required=True,
        help="protected TFVC root associated with this pipeline, such as $/Project",
    )
    azure_publish_parser.add_argument(
        "--work-item-id",
        action="append",
        default=[],
        type=int,
        help="associated Azure Boards work-item ID; repeat for multiple items",
    )
    azure_publish_parser.add_argument(
        "--output",
        help="write the publication manifest atomically to this path",
    )
    azure_publish_parser.add_argument(
        "--quiet",
        action="store_true",
        help="suppress the one-line status when --output is used",
    )

    azure_verify_parser = subparsers.add_parser(
        "azure-verify",
        help="recheck publication artifacts and current Azure TFVC build identity",
    )
    azure_verify_parser.add_argument(
        "publication",
        help="path to the Azure review-publication JSON",
    )
    azure_verify_parser.add_argument(
        "result",
        help="path to the exact machine-readable review-result JSON",
    )
    azure_verify_parser.add_argument(
        "report",
        help="path to the exact Markdown review report",
    )
    azure_verify_parser.add_argument(
        "--tfvc-server-path",
        required=True,
        help="protected TFVC root associated with this pipeline, such as $/Project",
    )
    azure_verify_parser.add_argument(
        "--maximum-age-seconds",
        type=int,
        default=DEFAULT_MAX_PUBLICATION_AGE_SECONDS,
        help=(
            "maximum publication age before approval "
            f"(default: {DEFAULT_MAX_PUBLICATION_AGE_SECONDS}, "
            f"maximum: {MAX_PUBLICATION_AGE_SECONDS})"
        ),
    )
    azure_verify_parser.add_argument(
        "--output",
        help="write the successful verification receipt atomically to this path",
    )
    azure_verify_parser.add_argument(
        "--summary-output",
        help="also write the verified Azure build-summary Markdown to this path",
    )
    azure_verify_parser.add_argument(
        "--quiet",
        action="store_true",
        help="suppress the one-line status when --output is used",
    )

    github_publish_parser = subparsers.add_parser(
        "github-publish",
        help="bind exact gate artifacts to the current GitHub pull-request head",
    )
    github_publish_parser.add_argument(
        "case",
        help="path to the exact change-case JSON",
    )
    github_publish_parser.add_argument(
        "result",
        help="path to the exact machine-readable review-result JSON",
    )
    github_publish_parser.add_argument(
        "report",
        help="path to the exact Markdown review report",
    )
    github_publish_parser.add_argument(
        "--output",
        help="write the publication manifest atomically to this path",
    )
    github_publish_parser.add_argument(
        "--quiet",
        action="store_true",
        help="suppress the one-line status when --output is used",
    )

    github_verify_parser = subparsers.add_parser(
        "github-verify",
        help="recheck gate artifacts and the current GitHub pull-request run identity",
    )
    github_verify_parser.add_argument(
        "publication",
        help="path to the GitHub review-publication JSON",
    )
    github_verify_parser.add_argument(
        "case",
        help="path to the exact change-case JSON",
    )
    github_verify_parser.add_argument(
        "result",
        help="path to the exact machine-readable review-result JSON",
    )
    github_verify_parser.add_argument(
        "report",
        help="path to the exact Markdown review report",
    )
    github_verify_parser.add_argument(
        "--maximum-age-seconds",
        type=int,
        default=DEFAULT_MAX_GITHUB_PUBLICATION_AGE_SECONDS,
        help=(
            "maximum publication age before completion "
            f"(default: {DEFAULT_MAX_GITHUB_PUBLICATION_AGE_SECONDS}, "
            f"maximum: {MAX_GITHUB_PUBLICATION_AGE_SECONDS})"
        ),
    )
    github_verify_parser.add_argument(
        "--output",
        help="write the successful verification receipt atomically to this path",
    )
    github_verify_parser.add_argument(
        "--quiet",
        action="store_true",
        help="suppress the one-line status when --output is used",
    )

    github_check_run_parser = subparsers.add_parser(
        "github-check-run",
        help="publish a verified same-repository decision as one GitHub Check Run",
    )
    github_check_run_parser.add_argument(
        "publication",
        help="path to the exact GitHub review-publication JSON",
    )
    github_check_run_parser.add_argument(
        "verification",
        help="path to the exact GitHub review-verification JSON",
    )
    github_check_run_parser.add_argument("case", help="path to the exact change-case JSON")
    github_check_run_parser.add_argument(
        "result",
        help="path to the exact machine-readable review-result JSON",
    )
    github_check_run_parser.add_argument(
        "report",
        help="path to the exact Markdown review report",
    )
    github_check_run_parser.add_argument(
        "--component-path",
        required=True,
        help="repository-relative changed component path used for decision annotations",
    )
    github_check_run_parser.add_argument(
        "--token-environment",
        default="CAUSURE_GITHUB_TOKEN",
        help=(
            "environment variable containing the short-lived GitHub App token "
            "(default: CAUSURE_GITHUB_TOKEN)"
        ),
    )
    github_check_run_parser.add_argument(
        "--allow-conditional",
        action="store_true",
        help="treat conditional_pass as a successful Check Run conclusion and process exit",
    )
    github_check_run_parser.add_argument(
        "--timeout-seconds",
        type=float,
        default=DEFAULT_GITHUB_CHECK_RUN_TIMEOUT_SECONDS,
        help=(
            "bounded GitHub API timeout "
            f"(default: {DEFAULT_GITHUB_CHECK_RUN_TIMEOUT_SECONDS:g}, "
            f"maximum: {MAX_GITHUB_CHECK_RUN_TIMEOUT_SECONDS:g})"
        ),
    )
    github_check_run_parser.add_argument(
        "--request-output",
        help="write the exact token-free Check Run request plan atomically",
    )
    github_check_run_parser.add_argument(
        "--summary-output",
        help="write the exact Markdown Check Run summary atomically",
    )
    github_check_run_parser.add_argument(
        "--output",
        help="write the successful Check Run receipt atomically",
    )
    github_check_run_parser.add_argument(
        "--quiet",
        action="store_true",
        help="suppress the one-line status when --output is used",
    )

    team_authorize_parser = subparsers.add_parser(
        "team-authorize",
        help="make a tenant-scoped role authorization decision",
    )
    team_authorize_parser.add_argument(
        "policy",
        help="path to the protected Team access-policy JSON",
    )
    team_authorize_parser.add_argument("--decision-id", required=True)
    team_authorize_parser.add_argument("--identity-provider", required=True)
    team_authorize_parser.add_argument("--subject-id", required=True)
    team_authorize_parser.add_argument(
        "--action",
        required=True,
        choices=tuple(action.value for action in TeamAction),
    )
    team_authorize_parser.add_argument(
        "--resource-type",
        required=True,
        choices=tuple(resource.value for resource in TeamResourceType),
    )
    team_authorize_parser.add_argument("--resource-id", required=True)
    team_authorize_parser.add_argument(
        "--decided-at",
        help="whole-second UTC decision time (default: now)",
    )
    team_authorize_parser.add_argument(
        "--output",
        help="write the decision atomically to this path instead of stdout",
    )
    team_authorize_parser.add_argument(
        "--quiet",
        action="store_true",
        help="suppress the one-line status when --output is used",
    )

    team_audit_append_parser = subparsers.add_parser(
        "team-audit-append",
        help="create the next retention-bound tenant audit event",
    )
    team_audit_append_parser.add_argument("policy")
    team_audit_append_parser.add_argument("authorization")
    team_audit_append_parser.add_argument("payload")
    team_audit_append_parser.add_argument("--payload-media-type", required=True)
    team_audit_append_parser.add_argument("--event-id", required=True)
    team_audit_append_parser.add_argument(
        "--outcome",
        required=True,
        choices=tuple(outcome.value for outcome in TeamAuditOutcome),
    )
    team_audit_append_parser.add_argument("--occurred-at")
    team_audit_append_parser.add_argument("--retention-class")
    team_audit_append_parser.add_argument("--retain-until")
    team_audit_append_parser.add_argument(
        "--previous-event",
        help="path to the current tenant audit head; omit only for sequence 1",
    )
    team_audit_append_parser.add_argument("--output")
    team_audit_append_parser.add_argument(
        "--quiet",
        action="store_true",
        help="suppress the one-line status when --output is used",
    )

    team_audit_export_parser = subparsers.add_parser(
        "team-audit-export",
        help="create a complete, policy-authorized tenant audit export",
    )
    team_audit_export_parser.add_argument("policy")
    team_audit_export_parser.add_argument("authorization")
    team_audit_export_parser.add_argument(
        "events",
        nargs="+",
        help="ordered audit-event paths beginning at sequence 1",
    )
    team_audit_export_parser.add_argument("--export-id", required=True)
    team_audit_export_parser.add_argument(
        "--authoritative-head-sha256",
        required=True,
        help="SHA-256 from the protected current tenant-ledger head",
    )
    team_audit_export_parser.add_argument("--created-at")
    team_audit_export_parser.add_argument("--output")
    team_audit_export_parser.add_argument(
        "--quiet",
        action="store_true",
        help="suppress the one-line status when --output is used",
    )

    team_audit_verify_parser = subparsers.add_parser(
        "team-audit-verify",
        help="verify exact Team audit-export bytes and export authorization",
    )
    team_audit_verify_parser.add_argument("policy")
    team_audit_verify_parser.add_argument("export")
    team_audit_verify_parser.add_argument("--output")
    team_audit_verify_parser.add_argument(
        "--quiet",
        action="store_true",
        help="suppress the one-line status when --output is used",
    )

    team_store_init_parser = subparsers.add_parser(
        "team-store-init",
        help="initialize or validate a transactional SQLite Team store",
    )
    team_store_init_parser.add_argument("database")

    team_store_policy_put_parser = subparsers.add_parser(
        "team-store-policy-put",
        help="append and activate an exact tenant policy snapshot",
    )
    team_store_policy_put_parser.add_argument("database")
    team_store_policy_put_parser.add_argument("policy")

    team_store_policy_get_parser = subparsers.add_parser(
        "team-store-policy-get",
        help="retrieve exact historical tenant policy bytes",
    )
    team_store_policy_get_parser.add_argument("database")
    team_store_policy_get_parser.add_argument("--tenant-id", required=True)
    team_store_policy_get_parser.add_argument("--policy-id", required=True)
    team_store_policy_get_parser.add_argument("--revision", required=True, type=int)
    team_store_policy_get_parser.add_argument("--sha256")
    team_store_policy_get_parser.add_argument("--byte-count", type=int)
    team_store_policy_get_parser.add_argument("--output")
    team_store_policy_get_parser.add_argument(
        "--quiet",
        action="store_true",
        help="suppress the one-line status when --output is used",
    )

    team_store_head_parser = subparsers.add_parser(
        "team-store-head",
        help="read the authoritative tenant ledger head",
    )
    team_store_head_parser.add_argument("database")
    team_store_head_parser.add_argument("--tenant-id", required=True)
    team_store_head_parser.add_argument("--output")
    team_store_head_parser.add_argument(
        "--quiet",
        action="store_true",
        help="suppress the one-line status when --output is used",
    )

    team_store_append_parser = subparsers.add_parser(
        "team-store-append",
        help="atomically append a verified event with tenant-head compare-and-swap",
    )
    team_store_append_parser.add_argument("database")
    team_store_append_parser.add_argument("event")
    expected_head = team_store_append_parser.add_mutually_exclusive_group(required=True)
    expected_head.add_argument("--expected-head-sha256")
    expected_head.add_argument(
        "--expect-empty",
        action="store_true",
        help="require the tenant ledger to have no existing events",
    )
    team_store_append_parser.add_argument("--output")
    team_store_append_parser.add_argument(
        "--quiet",
        action="store_true",
        help="suppress the one-line status when --output is used",
    )

    team_store_event_get_parser = subparsers.add_parser(
        "team-store-event-get",
        help="retrieve exact tenant audit-event bytes by sequence",
    )
    team_store_event_get_parser.add_argument("database")
    team_store_event_get_parser.add_argument("--tenant-id", required=True)
    team_store_event_get_parser.add_argument("--sequence", required=True, type=int)
    team_store_event_get_parser.add_argument("--output")
    team_store_event_get_parser.add_argument(
        "--quiet",
        action="store_true",
        help="suppress the one-line status when --output is used",
    )

    team_store_export_parser = subparsers.add_parser(
        "team-store-export",
        help="create and persist a complete export at the protected tenant head",
    )
    team_store_export_parser.add_argument("database")
    team_store_export_parser.add_argument("authorization")
    team_store_export_parser.add_argument("--export-id", required=True)
    team_store_export_parser.add_argument("--created-at")
    team_store_export_parser.add_argument("--output")
    team_store_export_parser.add_argument(
        "--quiet",
        action="store_true",
        help="suppress the one-line status when --output is used",
    )

    team_store_backup_parser = subparsers.add_parser(
        "team-store-backup",
        help="create a consistent online SQLite Team-store backup",
    )
    team_store_backup_parser.add_argument("database")
    team_store_backup_parser.add_argument("destination")

    entra_refresh_parser = subparsers.add_parser(
        "entra-trust-refresh",
        help="refresh a protected Entra trust snapshot from exact tenant endpoints",
    )
    entra_refresh_parser.add_argument("configuration")
    entra_refresh_parser.add_argument("output")
    entra_refresh_parser.add_argument(
        "--timeout-seconds",
        type=float,
        default=DEFAULT_ENTRA_REFRESH_TIMEOUT_SECONDS,
    )
    entra_refresh_parser.add_argument(
        "--quiet",
        action="store_true",
        help="suppress the one-line refresh status",
    )

    team_serve_parser = subparsers.add_parser(
        "team-serve",
        help="run the loopback-only Team service behind a trusted HTTPS edge",
    )
    team_serve_parser.add_argument("configuration")

    openai_quota_serve_parser = subparsers.add_parser(
        "openai-quota-serve",
        help="run the protected quota core behind the split trusted TLS edges",
    )
    openai_quota_serve_parser.add_argument("configuration")

    openai_quota_pilot_prepare_parser = subparsers.add_parser(
        "openai-quota-pilot-prepare",
        help="prepare new protected state for the split-edge quota pilot",
    )
    openai_quota_pilot_prepare_parser.add_argument("quota_configuration")
    openai_quota_pilot_prepare_parser.add_argument("provider_api_key_file")
    openai_quota_pilot_prepare_parser.add_argument("output_directory")
    openai_quota_pilot_prepare_parser.add_argument(
        "--certificate-days",
        type=int,
        default=30,
    )

    schema_parser = subparsers.add_parser(
        "schema",
        help="print a bundled JSON Schema",
    )
    schema_parser.add_argument(
        "name",
        choices=(
            "approval-assertion",
            "approval-revocations",
            "approval-trust-store",
            "approval-verification",
            "artifact-attestation",
            "attestation-revocations",
            "attestation-trust-store",
            "attestation-verification",
            "azure-review-publication",
            "azure-review-verification",
            "canary-observation",
            "canary-policy",
            "canary-result",
            "change-case",
            "entra-refresh-config",
            "entra-trust-store",
            "github-review-publication",
            "github-review-verification",
            "github-check-run-request",
            "github-check-run-receipt",
            "trusted-case-generation",
            "investigation-fixture",
            "investigation-selection",
            "openai-quota-config",
            "openai-quota-host-config",
            "policy",
            "review-result",
            "sandbox-policy",
            "sandbox-worker-request",
            "sandbox-worker-response",
            "team-access-policy",
            "team-audit-event",
            "team-audit-export",
            "team-audit-verification",
            "team-authorization",
            "team-http-action-request",
            "team-http-case-detail",
            "team-http-case-page",
            "team-http-case-publication-request",
            "team-http-event-page",
            "team-http-investigation-attach-request",
            "team-http-investigation-detail",
            "team-http-investigation-open-request",
            "team-http-investigation-page",
            "team-http-investigation-transition-request",
            "team-case-record",
            "team-host-config",
            "team-investigation-record",
            "trace-manifest",
        ),
    )
    schema_parser.add_argument("--output", help="write the schema atomically to this path")
    return parser


def _review_exit_code(decision: Decision, *, allow_conditional: bool) -> int:
    if decision is Decision.APPROVE:
        return 0
    if decision is Decision.CONDITIONAL_PASS and allow_conditional:
        return 0
    return 1


def main(argv: Sequence[str] | None = None) -> int:
    """Run the CLI and return a process exit code."""

    arguments = list(sys.argv[1:] if argv is None else argv)
    if not arguments or arguments in (["-h"], ["--help"]):
        print(_primary_help())
        return 0
    if arguments == ["--help-all"]:
        print(_parser().format_help(), end="")
        return 0

    args = _parser().parse_args(arguments)
    try:
        if args.command == "demo":
            run = run_demo(args.output)
            print(render_demo_summary(run))
            return 0

        if args.command == "init":
            initialization = initialize_project(
                args.directory,
                project_id=args.project_id,
            )
            print(render_initialization_summary(initialization))
            return 0

        if args.command == "github-configure":
            update = configure_github_component(
                args.project,
                component_id=args.component_id,
                component=args.component,
                paths=tuple(args.path),
                case_file=args.case,
                artifact_retention_days=args.retention_days,
            )
            print(render_github_configuration_summary(update))
            return 0

        if args.command == "adapter-configure":
            update = configure_trusted_adapter(
                args.project,
                adapter_id=args.adapter_id,
                kind=args.kind,
                entry_point=args.entry_point,
                component_id=args.component_id,
            )
            print(render_trusted_adapter_configuration_summary(update))
            return 0

        if args.command == "doctor":
            report = inspect_environment(args.directory)
            content = (
                render_doctor_json(report)
                if args.format == "json"
                else render_doctor_text(report) + "\n"
            )
            sys.stdout.write(content)
            return 2 if report.status == "failed" else 0

        if args.command == "investigate":
            prepared = prepare_investigation(
                args.traces,
                source_id=args.source_id,
                investigation_id=args.investigation_id,
                max_spans=args.max_spans,
                max_clusters=args.max_clusters,
            )
            print(render_investigation_preview(prepared))
            if args.preview_only:
                return 0

            selection = args.select
            if selection is None:
                if args.yes:
                    selection = "all"
                elif not sys.stdin.isatty():
                    raise ValueError(
                        "interactive selection requires a terminal; for automation pass "
                        "--select all --yes"
                    )
                else:
                    try:
                        selection = input(
                            "Select candidate numbers separated by commas "
                            "(Enter for all, q to cancel): "
                        )
                    except EOFError as exc:
                        raise ValueError(
                            "candidate selection ended before input was received"
                        ) from exc
                    if selection.strip().lower() in {"q", "quit", "cancel"}:
                        print("Cancelled; no files were written.")
                        return 0
            selected_cluster_ids = select_cluster_ids(prepared, selection)
            print(f"Selected {len(selected_cluster_ids)} candidate trace cluster(s).")
            output = args.output or default_investigation_output(prepared)

            if not args.yes:
                if not sys.stdin.isatty():
                    raise ValueError(
                        "saving without a terminal requires explicit confirmation with --yes"
                    )
                try:
                    confirmation = input(f"Create new workspace at {output}? [y/N]: ")
                except EOFError as exc:
                    raise ValueError("confirmation ended before input was received") from exc
                if confirmation.strip().lower() not in {"y", "yes"}:
                    print("Cancelled; no files were written.")
                    return 0

            workspace = write_investigation_workspace(
                prepared,
                selected_cluster_ids,
                output,
            )
            print(render_workspace_summary(workspace))
            return 0

        if args.command == "case" and args.case_command == "create":
            if not sys.stdin.isatty():
                raise ValueError(
                    "guided case creation requires an interactive terminal; canonical JSON "
                    "remains available as the automation interchange format"
                )
            investigation = load_verified_investigation_workspace(args.investigation)
            case = collect_guided_case(investigation)
            print(render_case_preview(case))
            output = args.output or default_case_output(investigation, case.case_id)
            if not args.yes:
                try:
                    confirmation = input(f"Create and review this case at {output}? [y/N]: ")
                except EOFError as exc:
                    raise ValueError("confirmation ended before input was received") from exc
                if confirmation.strip().lower() not in {"y", "yes"}:
                    print("Cancelled; no case files were written.")
                    return 0
            policy = load_case_policy(investigation, args.policy)
            created = create_case_workspace(
                investigation,
                case,
                policy=policy,
                output_directory=output,
            )
            print(render_case_creation_summary(created))
            return 0

        if args.command == "case" and args.case_command == "generate":
            generated = generate_configured_github_case(
                args.trusted_project,
                args.candidate_root,
                component_id=args.component_id,
                component_path=args.component_path,
                repository=args.repository,
                pull_request_number=args.pull_request,
                base_sha=args.base_sha,
                head_sha=args.head_sha,
                output_directory=args.output_directory,
                budget=CaseGenerationBudget(
                    timeout_seconds=args.timeout_seconds,
                    maximum_case_bytes=args.maximum_case_bytes,
                ),
            )
            print(render_trusted_case_generation_summary(generated))
            return 0

        if args.command == "validate":
            case = load_change_case(args.case, stdin=sys.stdin)
            print(f"Valid Causure change case: {case.case_id}")
            return 0

        if args.command == "schema":
            content = json.dumps(get_schema(args.name), ensure_ascii=False, indent=2) + "\n"
            if args.output:
                atomic_write_text(args.output, content)
                print(f"Wrote {args.name} schema to {args.output}")
            else:
                sys.stdout.write(content)
            return 0

        if args.command == "entra-trust-refresh":
            _reject_output_collision(args.output, args.configuration)
            configuration = load_entra_refresh_configuration(args.configuration)
            store = refresh_entra_trust_file(
                configuration,
                args.output,
                timeout_seconds=args.timeout_seconds,
            )
            if not args.quiet:
                print(
                    f"Refreshed {len(store.tenants)} Entra tenant(s) "
                    f"for {store.store_id} at {args.output}"
                )
            return 0

        if args.command == "team-serve":
            configuration = load_team_host_configuration(args.configuration)
            print(
                "Starting Causure Team service on "
                f"{configuration.server.listen_host}:{configuration.server.listen_port} "
                "behind the required trusted HTTPS edge",
                flush=True,
            )
            serve_team_host(configuration)
            return 0

        if args.command == "openai-quota-serve":
            configuration = load_openai_quota_host_configuration(args.configuration)
            print(
                "Starting Causure OpenAI-compatible quota core on "
                f"{configuration.server.listen_host}:{configuration.server.listen_port} "
                "behind the required split trusted TLS edges",
                flush=True,
            )
            serve_openai_quota_host(configuration)
            return 0

        if args.command == "openai-quota-pilot-prepare":
            state = prepare_openai_quota_pilot_state(
                args.quota_configuration,
                args.provider_api_key_file,
                args.output_directory,
                valid_days=args.certificate_days,
            )
            print(
                f"Prepared protected OpenAI quota pilot state at {state.state_directory}; "
                f"install trust from {state.ca_certificate_path}; "
                f"certificate expires {state.certificate_not_after}"
            )
            return 0

        if args.command == "collect":
            if args.traces == "-":
                raise ValueError(
                    "collect requires a file path so the manifest hashes exact source bytes"
                )
            if args.output and Path(args.traces).resolve() == Path(args.output).resolve():
                raise ValueError("trace input and --output must use different paths")
            document, raw_bytes = read_json_with_bytes(
                args.traces,
                max_bytes=MAX_TRACE_DOCUMENT_BYTES,
            )
            manifest = collect_otlp_trace_manifest(
                document,
                raw_bytes=raw_bytes,
                source_id=args.source_id,
                max_spans=args.max_spans,
            )
            content = render_trace_manifest(manifest)
            if args.output:
                atomic_write_text(args.output, content)
                if not args.quiet:
                    print(
                        f"Collected {manifest.source.span_count} span(s) from "
                        f"{manifest.source.trace_count} trace(s) to {args.output}"
                    )
            else:
                sys.stdout.write(content)
            return 0

        if args.command == "fixture":
            if args.manifest == "-":
                raise ValueError(
                    "fixture requires a file path so the draft hashes exact manifest bytes"
                )
            if args.output and Path(args.manifest).resolve() == Path(args.output).resolve():
                raise ValueError("trace manifest input and --output must use different paths")
            document, raw_bytes = read_json_with_bytes(
                args.manifest,
                max_bytes=MAX_MANIFEST_DOCUMENT_BYTES,
            )
            fixture = generate_investigation_fixture(
                document,
                raw_bytes=raw_bytes,
                fixture_id=args.fixture_id,
                max_clusters=args.max_clusters,
            )
            content = render_investigation_fixture(fixture)
            if args.output:
                atomic_write_text(args.output, content)
                if not args.quiet:
                    print(
                        f"Generated {len(fixture.candidate_clusters)} draft "
                        f"trace cluster(s) to {args.output}"
                    )
            else:
                sys.stdout.write(content)
            return 0

        if args.command == "canary-compare":
            _reject_output_collision(
                args.output,
                args.observation,
                args.policy,
                args.case,
                args.review_result,
            )
            _reject_output_collision(
                args.result_output,
                args.observation,
                args.policy,
                args.case,
                args.review_result,
                *((args.output,) if args.output else ()),
            )
            observation_bytes = _read_bounded_bytes(
                args.observation,
                maximum=MAX_CANARY_OBSERVATION_BYTES,
                description="canary observation",
            )
            policy_bytes = _read_bounded_bytes(
                args.policy,
                maximum=MAX_CANARY_POLICY_BYTES,
                description="canary policy",
            )
            change_case_bytes = _read_bounded_bytes(
                args.case,
                maximum=MAX_CANARY_CHANGE_CASE_BYTES,
                description="change case",
            )
            review_result_bytes = _read_bounded_bytes(
                args.review_result,
                maximum=MAX_CANARY_REVIEW_RESULT_BYTES,
                description="review result",
            )
            result = compare_canary_outcomes(
                observation_bytes,
                policy_bytes,
                change_case_bytes,
                review_result_bytes,
            )
            machine_content = render_canary_result(result)
            content = machine_content if args.format == "json" else render_canary_markdown(result)
            if args.output:
                atomic_write_text(args.output, content)
                if not args.quiet:
                    print(
                        f"Causure canary: {result.decision.value.upper()} "
                        f"({result.comparison_id}) - {args.output}"
                    )
            else:
                sys.stdout.write(content)
            if args.result_output:
                atomic_write_text(args.result_output, machine_content)
            if result.decision is CanaryDecision.PROMOTE:
                return 0
            if result.decision is CanaryDecision.CONTINUE and args.allow_continue:
                return 0
            return 1

        if args.command == "team-authorize":
            _reject_output_collision(args.output, args.policy)
            policy_bytes = _read_bounded_bytes(
                args.policy,
                maximum=MAX_TEAM_ACCESS_POLICY_BYTES,
                description="Team access policy",
            )
            decision = create_team_authorization(
                policy_bytes,
                decision_id=args.decision_id,
                identity_provider=args.identity_provider,
                subject_id=args.subject_id,
                action=args.action,
                resource_type=args.resource_type,
                resource_id=args.resource_id,
                decided_at=args.decided_at or utc_timestamp(),
            )
            content = render_team_authorization(decision)
            if args.output:
                atomic_write_text(args.output, content)
                if not args.quiet:
                    status = "authorized" if decision.authorized else "denied"
                    print(
                        f"Team action {status} for {decision.principal.subject_id} at {args.output}"
                    )
            else:
                sys.stdout.write(content)
            return 0 if decision.authorized else 1

        if args.command == "team-audit-append":
            input_paths = [args.policy, args.authorization, args.payload]
            if args.previous_event:
                input_paths.append(args.previous_event)
            _reject_output_collision(args.output, *input_paths)
            policy_bytes = _read_bounded_bytes(
                args.policy,
                maximum=MAX_TEAM_ACCESS_POLICY_BYTES,
                description="Team access policy",
            )
            authorization_bytes = _read_bounded_bytes(
                args.authorization,
                maximum=MAX_TEAM_AUTHORIZATION_BYTES,
                description="Team authorization decision",
            )
            payload_bytes = _read_bounded_bytes(
                args.payload,
                maximum=MAX_TEAM_AUDIT_PAYLOAD_BYTES,
                description="Team audit payload",
            )
            previous_event_bytes = (
                _read_bounded_bytes(
                    args.previous_event,
                    maximum=MAX_TEAM_AUDIT_EVENT_BYTES,
                    description="previous Team audit event",
                )
                if args.previous_event
                else None
            )
            event = create_team_audit_event(
                policy_bytes,
                authorization_bytes,
                payload_bytes,
                payload_media_type=args.payload_media_type,
                event_id=args.event_id,
                outcome=args.outcome,
                occurred_at=args.occurred_at or utc_timestamp(),
                retention_class_id=args.retention_class,
                retain_until=args.retain_until,
                previous_event_bytes=previous_event_bytes,
            )
            content = render_team_audit_event(event)
            if args.output:
                atomic_write_text(args.output, content)
                if not args.quiet:
                    print(
                        f"Created Team audit event {event.entry.sequence} "
                        f"for {event.entry.tenant_id} at {args.output}"
                    )
            else:
                sys.stdout.write(content)
            return 0

        if args.command == "team-audit-export":
            _reject_output_collision(
                args.output,
                args.policy,
                args.authorization,
                *args.events,
            )
            policy_bytes = _read_bounded_bytes(
                args.policy,
                maximum=MAX_TEAM_ACCESS_POLICY_BYTES,
                description="Team access policy",
            )
            authorization_bytes = _read_bounded_bytes(
                args.authorization,
                maximum=MAX_TEAM_AUTHORIZATION_BYTES,
                description="Team authorization decision",
            )
            event_bytes = [
                _read_bounded_bytes(
                    event_path,
                    maximum=MAX_TEAM_AUDIT_EVENT_BYTES,
                    description="Team audit event",
                )
                for event_path in args.events
            ]
            export = create_team_audit_export(
                policy_bytes,
                authorization_bytes,
                event_bytes,
                export_id=args.export_id,
                authoritative_head_sha256=args.authoritative_head_sha256,
                created_at=args.created_at or utc_timestamp(),
            )
            content = render_team_audit_export(export)
            if len(content.encode("utf-8")) > MAX_TEAM_AUDIT_EXPORT_BYTES:
                raise ValueError(f"Team audit export exceeds {MAX_TEAM_AUDIT_EXPORT_BYTES} bytes")
            if args.output:
                atomic_write_text(args.output, content)
                if not args.quiet:
                    print(
                        f"Exported {export.audit_range.event_count} Team audit event(s) "
                        f"for {export.tenant_id} at {args.output}"
                    )
            else:
                sys.stdout.write(content)
            return 0

        if args.command == "team-audit-verify":
            _reject_output_collision(args.output, args.policy, args.export)
            policy_bytes = _read_bounded_bytes(
                args.policy,
                maximum=MAX_TEAM_ACCESS_POLICY_BYTES,
                description="Team access policy",
            )
            export_bytes = _read_bounded_bytes(
                args.export,
                maximum=MAX_TEAM_AUDIT_EXPORT_BYTES,
                description="Team audit export",
            )
            verification = verify_team_audit_export(
                export_bytes,
                policy_bytes,
                checked_at=utc_timestamp(),
            )
            content = render_team_audit_verification(verification)
            if args.output:
                atomic_write_text(args.output, content)
                if not args.quiet:
                    print(
                        f"Verified {verification.audit_range.event_count} Team audit "
                        f"event(s) for {verification.tenant_id} at {args.output}"
                    )
            else:
                sys.stdout.write(content)
            return 0

        if args.command == "team-store-init":
            store = SQLiteTeamStore(args.database)
            store.initialize()
            print(f"Initialized Team store at {store.database_path}")
            return 0

        if args.command == "team-store-policy-put":
            policy_bytes = _read_bounded_bytes(
                args.policy,
                maximum=MAX_TEAM_ACCESS_POLICY_BYTES,
                description="Team access policy",
            )
            store = SQLiteTeamStore(args.database)
            policy = store.put_policy(policy_bytes)
            print(
                f"Stored Team policy {policy.policy_id} revision {policy.revision} "
                f"for {policy.tenant_id}"
            )
            return 0

        if args.command == "team-store-policy-get":
            _reject_output_collision(args.output, args.database)
            store = SQLiteTeamStore(args.database)
            policy_bytes = store.get_policy_bytes(
                args.tenant_id,
                args.policy_id,
                args.revision,
                sha256=args.sha256,
                byte_count=args.byte_count,
            )
            if args.output:
                atomic_write_bytes(args.output, policy_bytes)
                if not args.quiet:
                    print(f"Wrote exact historical Team policy bytes to {args.output}")
            else:
                stdout_buffer = getattr(sys.stdout, "buffer", None)
                if stdout_buffer is None:
                    sys.stdout.write(policy_bytes.decode("utf-8"))
                else:
                    stdout_buffer.write(policy_bytes)
            return 0

        if args.command == "team-store-head":
            _reject_output_collision(args.output, args.database)
            store = SQLiteTeamStore(args.database)
            head = store.get_head(args.tenant_id)
            content = render_team_ledger_head(head)
            if args.output:
                atomic_write_text(args.output, content)
                if not args.quiet:
                    print(f"Wrote Team ledger head for {head.tenant_id} to {args.output}")
            else:
                sys.stdout.write(content)
            return 0

        if args.command == "team-store-append":
            _reject_output_collision(args.output, args.database, args.event)
            event_bytes = _read_bounded_bytes(
                args.event,
                maximum=MAX_TEAM_AUDIT_EVENT_BYTES,
                description="Team audit event",
            )
            store = SQLiteTeamStore(args.database)
            head = store.append_event(
                event_bytes,
                expected_head_sha256=(None if args.expect_empty else args.expected_head_sha256),
            )
            content = render_team_ledger_head(head)
            if args.output:
                atomic_write_text(args.output, content)
                if not args.quiet:
                    print(
                        f"Appended Team event {head.sequence} for {head.tenant_id} at {args.output}"
                    )
            else:
                sys.stdout.write(content)
            return 0

        if args.command == "team-store-event-get":
            _reject_output_collision(args.output, args.database)
            store = SQLiteTeamStore(args.database)
            event_bytes = store.get_event_bytes(args.tenant_id, args.sequence)
            if args.output:
                atomic_write_bytes(args.output, event_bytes)
                if not args.quiet:
                    print(
                        f"Wrote exact Team event {args.sequence} "
                        f"for {args.tenant_id} to {args.output}"
                    )
            else:
                stdout_buffer = getattr(sys.stdout, "buffer", None)
                if stdout_buffer is None:
                    sys.stdout.write(event_bytes.decode("utf-8"))
                else:
                    stdout_buffer.write(event_bytes)
            return 0

        if args.command == "team-store-export":
            _reject_output_collision(args.output, args.database, args.authorization)
            authorization_bytes = _read_bounded_bytes(
                args.authorization,
                maximum=MAX_TEAM_AUTHORIZATION_BYTES,
                description="Team authorization decision",
            )
            store = SQLiteTeamStore(args.database)
            export = store.create_export(
                authorization_bytes,
                export_id=args.export_id,
                created_at=args.created_at or utc_timestamp(),
            )
            export_bytes = store.get_export_bytes(export.tenant_id, export.export_id)
            if args.output:
                atomic_write_bytes(args.output, export_bytes)
                if not args.quiet:
                    print(
                        f"Exported {export.audit_range.event_count} stored Team event(s) "
                        f"for {export.tenant_id} at {args.output}"
                    )
            else:
                stdout_buffer = getattr(sys.stdout, "buffer", None)
                if stdout_buffer is None:
                    sys.stdout.write(export_bytes.decode("utf-8"))
                else:
                    stdout_buffer.write(export_bytes)
            return 0

        if args.command == "team-store-backup":
            store = SQLiteTeamStore(args.database)
            destination = store.backup(args.destination)
            print(f"Backed up Team store to {destination}")
            return 0

        if args.command == "public-key":
            _reject_output_collision(args.output, args.key)
            key_pem = _read_bounded_bytes(
                args.key,
                maximum=MAX_KEY_DOCUMENT_BYTES,
                description="key document",
            )
            password = _password_from_environment(args.private_key_password_env)
            content = (
                public_key_base64url_from_pem(
                    key_pem,
                    password=password,
                )
                + "\n"
            )
            if args.output:
                atomic_write_text(args.output, content)
                if not args.quiet:
                    print(f"Exported Ed25519 public key to {args.output}")
            else:
                sys.stdout.write(content)
            return 0

        if args.command == "attest":
            _reject_output_collision(args.output, args.artifact, args.private_key)
            raw_bytes = _read_bounded_bytes(
                args.artifact,
                maximum=MAX_ATTESTED_ARTIFACT_BYTES,
                description="artifact",
            )
            private_key_pem = _read_bounded_bytes(
                args.private_key,
                maximum=MAX_KEY_DOCUMENT_BYTES,
                description="private key",
            )
            attestation = create_artifact_attestation(
                raw_bytes,
                artifact_id=args.artifact_id,
                media_type=args.media_type,
                producer_id=args.producer_id,
                key_id=args.key_id,
                private_key_pem=private_key_pem,
                private_key_password=_password_from_environment(args.private_key_password_env),
                issued_at=args.issued_at or utc_timestamp(),
                expires_at=args.expires_at,
                retention_class=args.retention_class,
                retain_until=args.retain_until,
                revocation_list_id=args.revocation_list_id,
            )
            content = render_artifact_attestation(attestation)
            if args.output:
                atomic_write_text(args.output, content)
                if not args.quiet:
                    print(
                        f"Attested {attestation.artifact.artifact_id} as "
                        f"{attestation.producer.producer_id} to {args.output}"
                    )
            else:
                sys.stdout.write(content)
            return 0

        if args.command == "verify-attestation":
            _reject_output_collision(
                args.output,
                args.artifact,
                args.attestation,
                args.trust_store,
                args.revocations,
            )
            raw_bytes = _read_bounded_bytes(
                args.artifact,
                maximum=MAX_ATTESTED_ARTIFACT_BYTES,
                description="artifact",
            )
            attestation = parse_artifact_attestation(read_json(args.attestation))
            trust_store = parse_attestation_trust_store(read_json(args.trust_store))
            revocations = parse_attestation_revocation_list(read_json(args.revocations))
            verification = verify_artifact_attestation(
                raw_bytes,
                attestation,
                trust_store,
                revocations,
                checked_at=utc_timestamp(),
                max_revocation_age_seconds=args.max_revocation_age_seconds,
            )
            content = render_attestation_verification(verification)
            if args.output:
                atomic_write_text(args.output, content)
                if not args.quiet:
                    print(
                        f"Verified {verification.artifact.artifact_id} from "
                        f"{verification.producer.producer_id} to {args.output}"
                    )
            else:
                sys.stdout.write(content)
            return 0

        if args.command == "issue-approval":
            _reject_output_collision(
                args.output,
                args.publication,
                args.verification,
                args.result,
                args.private_key,
            )
            publication_bytes = _read_bounded_bytes(
                args.publication,
                maximum=MAX_AZURE_PUBLICATION_BYTES,
                description="Azure review publication",
            )
            verification_bytes = _read_bounded_bytes(
                args.verification,
                maximum=MAX_AZURE_VERIFICATION_BYTES,
                description="Azure review verification",
            )
            result_bytes = _read_bounded_bytes(
                args.result,
                maximum=MAX_REVIEW_RESULT_BYTES,
                description="review result",
            )
            private_key_pem = _read_bounded_bytes(
                args.private_key,
                maximum=MAX_KEY_DOCUMENT_BYTES,
                description="private key",
            )
            assertion = create_approval_assertion(
                publication_bytes,
                verification_bytes,
                result_bytes,
                assertion_id=args.assertion_id,
                authority_id=args.authority_id,
                key_id=args.key_id,
                approver_id=args.approver_id,
                identity_provider=args.identity_provider,
                authentication_method=args.authentication_method,
                authentication_event_id=args.authentication_event_id,
                authenticated_at=args.authenticated_at,
                action=args.action,
                finding_codes=args.finding_code,
                justification=args.justification,
                issued_at=args.issued_at or utc_timestamp(),
                expires_at=args.expires_at,
                revocation_list_id=args.revocation_list_id,
                private_key_pem=private_key_pem,
                private_key_password=_password_from_environment(args.private_key_password_env),
            )
            content = render_approval_assertion(assertion)
            if args.output:
                atomic_write_text(args.output, content)
                if not args.quiet:
                    print(
                        f"Issued {assertion.action.value} assertion "
                        f"{assertion.assertion_id} to {args.output}"
                    )
            else:
                sys.stdout.write(content)
            return 0

        if args.command == "verify-approval":
            _reject_output_collision(
                args.output,
                args.assertion,
                args.publication,
                args.verification,
                args.result,
                args.report,
                args.trust_store,
                args.revocations,
            )
            assertion_bytes = _read_bounded_bytes(
                args.assertion,
                maximum=MAX_APPROVAL_ASSERTION_BYTES,
                description="approval assertion",
            )
            publication_bytes = _read_bounded_bytes(
                args.publication,
                maximum=MAX_AZURE_PUBLICATION_BYTES,
                description="Azure review publication",
            )
            verification_bytes = _read_bounded_bytes(
                args.verification,
                maximum=MAX_AZURE_VERIFICATION_BYTES,
                description="Azure review verification",
            )
            result_bytes = _read_bounded_bytes(
                args.result,
                maximum=MAX_REVIEW_RESULT_BYTES,
                description="review result",
            )
            report_bytes = _read_bounded_bytes(
                args.report,
                maximum=MAX_REVIEW_REPORT_BYTES,
                description="review report",
            )
            trust_document, _ = read_json_with_bytes(
                args.trust_store,
                max_bytes=MAX_APPROVAL_POLICY_BYTES,
            )
            revocation_document, _ = read_json_with_bytes(
                args.revocations,
                max_bytes=MAX_APPROVAL_POLICY_BYTES,
            )
            trust_store = parse_approval_trust_store(trust_document)
            revocations = parse_approval_revocation_list(revocation_document)
            tfvc, build = azure_context_from_environment(
                os.environ,
                tfvc_server_path=args.tfvc_server_path,
            )
            approval_verification = verify_approval_assertion(
                assertion_bytes,
                publication_bytes,
                verification_bytes,
                result_bytes,
                report_bytes,
                trust_store,
                revocations,
                expected_tfvc=tfvc,
                expected_build=build,
                checked_at=utc_timestamp(),
                max_revocation_age_seconds=args.max_revocation_age_seconds,
            )
            content = render_approval_verification(approval_verification)
            if args.output:
                atomic_write_text(args.output, content)
                if not args.quiet:
                    print(
                        f"Verified {approval_verification.action.value} by "
                        f"{approval_verification.approver.subject_id} to {args.output}"
                    )
            else:
                sys.stdout.write(content)
            return _review_exit_code(
                approval_verification.review.decision,
                allow_conditional=False,
            )

        if args.command == "azure-publish":
            _reject_output_collision(args.output, args.result, args.report)
            result_bytes = _read_bounded_bytes(
                args.result,
                maximum=MAX_REVIEW_RESULT_BYTES,
                description="review result",
            )
            report_bytes = _read_bounded_bytes(
                args.report,
                maximum=MAX_REVIEW_REPORT_BYTES,
                description="review report",
            )
            tfvc, build = azure_context_from_environment(
                os.environ,
                tfvc_server_path=args.tfvc_server_path,
            )
            publication = create_azure_review_publication(
                result_bytes,
                report_bytes,
                tfvc=tfvc,
                build=build,
                work_item_ids=args.work_item_id,
                created_at=utc_timestamp(),
            )
            content = render_azure_review_publication(publication)
            if args.output:
                atomic_write_text(args.output, content)
                if not args.quiet:
                    print(
                        f"Bound {publication.review.case_id} to Azure build "
                        f"{publication.build.build_id} at {args.output}"
                    )
            else:
                sys.stdout.write(content)
            return 0

        if args.command == "azure-verify":
            _reject_output_collision(
                args.output,
                args.publication,
                args.result,
                args.report,
            )
            _reject_output_collision(
                args.summary_output,
                args.publication,
                args.result,
                args.report,
                *((args.output,) if args.output else ()),
            )
            publication_bytes = _read_bounded_bytes(
                args.publication,
                maximum=MAX_AZURE_PUBLICATION_BYTES,
                description="Azure review publication",
            )
            result_bytes = _read_bounded_bytes(
                args.result,
                maximum=MAX_REVIEW_RESULT_BYTES,
                description="review result",
            )
            report_bytes = _read_bounded_bytes(
                args.report,
                maximum=MAX_REVIEW_REPORT_BYTES,
                description="review report",
            )
            tfvc, build = azure_context_from_environment(
                os.environ,
                tfvc_server_path=args.tfvc_server_path,
            )
            verification = verify_azure_review_publication(
                publication_bytes,
                result_bytes,
                report_bytes,
                expected_tfvc=tfvc,
                expected_build=build,
                verified_at=utc_timestamp(),
                maximum_age_seconds=args.maximum_age_seconds,
            )
            content = render_azure_review_verification(verification)
            if args.summary_output:
                atomic_write_text(
                    args.summary_output,
                    render_azure_build_summary(publication_bytes, verification),
                )
            if args.output:
                atomic_write_text(args.output, content)
                if not args.quiet:
                    print(
                        f"Verified {verification.review.case_id} for Azure build "
                        f"{verification.build_id} at {args.output}"
                    )
            else:
                sys.stdout.write(content)
            return 0

        if args.command == "github-publish":
            _reject_output_collision(args.output, args.case, args.result, args.report)
            change_case_bytes = _read_bounded_bytes(
                args.case,
                maximum=MAX_GITHUB_CHANGE_CASE_BYTES,
                description="change case",
            )
            result_bytes = _read_bounded_bytes(
                args.result,
                maximum=MAX_GITHUB_REVIEW_RESULT_BYTES,
                description="review result",
            )
            report_bytes = _read_bounded_bytes(
                args.report,
                maximum=MAX_GITHUB_REVIEW_REPORT_BYTES,
                description="review report",
            )
            pull_request, workflow = github_context_from_environment(os.environ)
            publication = create_github_review_publication(
                change_case_bytes,
                result_bytes,
                report_bytes,
                pull_request=pull_request,
                workflow=workflow,
                created_at=utc_timestamp(),
            )
            content = render_github_review_publication(publication)
            if args.output:
                atomic_write_text(args.output, content)
                if not args.quiet:
                    print(
                        f"Bound {publication.review.case_id} to GitHub PR "
                        f"#{publication.pull_request.number} head "
                        f"{publication.pull_request.head_sha} at {args.output}"
                    )
            else:
                sys.stdout.write(content)
            return 0

        if args.command == "github-verify":
            _reject_output_collision(
                args.output,
                args.publication,
                args.case,
                args.result,
                args.report,
            )
            publication_bytes = _read_bounded_bytes(
                args.publication,
                maximum=MAX_GITHUB_PUBLICATION_BYTES,
                description="GitHub review publication",
            )
            change_case_bytes = _read_bounded_bytes(
                args.case,
                maximum=MAX_GITHUB_CHANGE_CASE_BYTES,
                description="change case",
            )
            result_bytes = _read_bounded_bytes(
                args.result,
                maximum=MAX_GITHUB_REVIEW_RESULT_BYTES,
                description="review result",
            )
            report_bytes = _read_bounded_bytes(
                args.report,
                maximum=MAX_GITHUB_REVIEW_REPORT_BYTES,
                description="review report",
            )
            pull_request, workflow = github_context_from_environment(os.environ)
            verification = verify_github_review_publication(
                publication_bytes,
                change_case_bytes,
                result_bytes,
                report_bytes,
                expected_pull_request=pull_request,
                expected_workflow=workflow,
                verified_at=utc_timestamp(),
                maximum_age_seconds=args.maximum_age_seconds,
            )
            content = render_github_review_verification(verification)
            if args.output:
                atomic_write_text(args.output, content)
                if not args.quiet:
                    print(
                        f"Verified {verification.review.case_id} for GitHub PR "
                        f"#{verification.pull_request.number} head "
                        f"{verification.pull_request.head_sha} at {args.output}"
                    )
            else:
                sys.stdout.write(content)
            return 0

        if args.command == "github-check-run":
            input_paths = (
                args.publication,
                args.verification,
                args.case,
                args.result,
                args.report,
            )
            _reject_output_collision(args.request_output, *input_paths)
            _reject_output_collision(
                args.summary_output,
                *input_paths,
                *((args.request_output,) if args.request_output else ()),
            )
            _reject_output_collision(
                args.output,
                *input_paths,
                *((args.request_output,) if args.request_output else ()),
                *((args.summary_output,) if args.summary_output else ()),
            )
            publication_bytes = _read_bounded_bytes(
                args.publication,
                maximum=MAX_GITHUB_PUBLICATION_BYTES,
                description="GitHub review publication",
            )
            verification_bytes = _read_bounded_bytes(
                args.verification,
                maximum=MAX_GITHUB_VERIFICATION_BYTES,
                description="GitHub review verification",
            )
            change_case_bytes = _read_bounded_bytes(
                args.case,
                maximum=MAX_GITHUB_CHANGE_CASE_BYTES,
                description="change case",
            )
            result_bytes = _read_bounded_bytes(
                args.result,
                maximum=MAX_GITHUB_REVIEW_RESULT_BYTES,
                description="review result",
            )
            report_bytes = _read_bounded_bytes(
                args.report,
                maximum=MAX_GITHUB_REVIEW_REPORT_BYTES,
                description="review report",
            )
            pull_request, workflow = github_context_from_environment(os.environ)
            check_request = create_github_check_run_request(
                publication_bytes,
                verification_bytes,
                change_case_bytes,
                result_bytes,
                report_bytes,
                expected_pull_request=pull_request,
                expected_workflow=workflow,
                component_path=args.component_path,
                created_at=utc_timestamp(),
                allow_conditional=args.allow_conditional,
            )
            request_content = render_github_check_run_request(check_request)
            if args.request_output:
                atomic_write_text(args.request_output, request_content)
            if args.summary_output:
                atomic_write_text(
                    args.summary_output,
                    render_github_check_run_summary(check_request),
                )
            token = _secret_from_environment(
                args.token_environment,
                description="GitHub token",
            )
            try:
                receipt = publish_github_check_run(
                    request_content.encode("utf-8"),
                    token=token,
                    published_at=utc_timestamp(),
                    timeout_seconds=args.timeout_seconds,
                )
            finally:
                token = ""
            content = render_github_check_run_receipt(receipt)
            if args.output:
                atomic_write_text(args.output, content)
                if not args.quiet:
                    print(
                        f"Published {receipt.name} for GitHub PR "
                        f"#{receipt.pull_request_number} as check run "
                        f"{receipt.check_run_id} at {args.output}"
                    )
            else:
                sys.stdout.write(content)
            return _review_exit_code(
                check_request.review.decision,
                allow_conditional=args.allow_conditional,
            )

        case = load_change_case(args.case, stdin=sys.stdin)
        policy = load_policy(args.policy)
        result = review_case(case, policy)
        content = render_json(result) if args.format == "json" else render_markdown(case, result)
        if args.output:
            if (
                args.result_output
                and Path(args.output).resolve() == Path(args.result_output).resolve()
            ):
                raise ValueError("--output and --result-output must use different paths")
            atomic_write_text(args.output, content)
            if not args.quiet:
                print(
                    f"Causure: {result.decision.value.upper()} "
                    f"({result.recommended_action.value}) - {args.output}"
                )
        else:
            sys.stdout.write(content)
        if args.result_output:
            atomic_write_text(args.result_output, render_json(result))
        return _review_exit_code(
            result.decision,
            allow_conditional=args.allow_conditional,
        )
    except BrokenPipeError:
        return 0
    except (
        AdapterRunError,
        DocumentValidationError,
        InputDocumentError,
        OSError,
        ValueError,
    ) as exc:
        print(str(exc), file=sys.stderr)
        return 2
