"""Trusted-identity application operations over the transactional Team store."""

from __future__ import annotations

import hashlib
import json
import re
import uuid
from collections.abc import Callable
from dataclasses import dataclass
from datetime import datetime

from causure.attestations import utc_timestamp
from causure.constants import (
    TeamAction,
    TeamAuditOutcome,
    TeamAuthorizationReason,
    TeamInvestigationPriority,
    TeamInvestigationResolution,
    TeamInvestigationStatus,
    TeamResourceType,
    TeamRole,
)
from causure.team_cases import (
    TEAM_CASE_RECORD_MEDIA_TYPE,
    TeamCaseRecord,
    TeamCaseValidationError,
    create_team_case_record,
    parse_team_case_record_bytes,
    render_team_case_record,
    validate_team_case_successor,
)
from causure.team_investigations import (
    TEAM_INVESTIGATION_RECORD_MEDIA_TYPE,
    TeamInvestigationRecord,
    TeamInvestigationValidationError,
    attach_team_investigation_observation,
    create_team_investigation_record,
    parse_team_investigation_record_bytes,
    render_team_investigation_record,
    transition_team_investigation_record,
)
from causure.team_service import (
    TeamAccessPolicy,
    TeamAuditEvent,
    TeamAuditExport,
    TeamAuthorizationDecision,
    TeamDocumentSubject,
    TeamPolicySubject,
    TeamPrincipal,
    TeamResource,
    TeamRetentionRequirement,
    create_team_audit_event,
    create_team_authorization,
    parse_team_access_policy_bytes,
    parse_team_audit_event_bytes,
    render_team_audit_event,
    render_team_authorization,
)
from causure.team_store import (
    SQLiteTeamStore,
    TeamLedgerHead,
    TeamStoreConflictError,
    TeamStoreError,
)

_SAFE_ID_PATTERN = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:+/@-]{0,127}$")
_CASE_ID_PATTERN = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{2,127}$")
_SHA256_PATTERN = re.compile(r"^[a-f0-9]{64}$")
_UTC_TIMESTAMP_FORMAT = "%Y-%m-%dT%H:%M:%SZ"
_CASE_PUBLICATION_SUBJECT_MEDIA_TYPE = "application/vnd.causure.team-case-publication-subject+json"
_INVESTIGATION_MUTATION_SUBJECT_MEDIA_TYPE = (
    "application/vnd.causure.team-investigation-mutation-subject+json"
)
_IdentifierFactory = Callable[[str], str]
_Clock = Callable[[], str]


class TeamApplicationError(ValueError):
    """Raised when a trusted Team application operation cannot be completed."""

    def __init__(self, code: str, message: str) -> None:
        self.code = code
        self.message = message
        super().__init__(f"Team application failed [{code}]: {message}")


class TeamIdentityError(TeamApplicationError):
    """Raised when the hosting layer did not supply a valid trusted identity."""


class TeamAccessDeniedError(TeamApplicationError):
    """Raised when an authenticated principal lacks a required policy grant."""

    def __init__(
        self,
        code: str,
        message: str,
        *,
        decision: TeamAuthorizationDecision | None = None,
    ) -> None:
        self.decision = decision
        super().__init__(code, message)


@dataclass(frozen=True, slots=True)
class AuthenticatedTeamIdentity:
    """Stable identity and tenant selected by trusted hosting middleware."""

    tenant_id: str
    identity_provider: str
    subject_id: str


@dataclass(frozen=True, slots=True)
class TeamTenantSummary:
    tenant_id: str
    policy_id: str
    policy_revision: int
    policy_effective_at: str
    policy_sha256: str
    policy_byte_count: int
    assigned_roles: tuple[TeamRole, ...]
    head: TeamLedgerHead


@dataclass(frozen=True, slots=True)
class TeamRecordedAction:
    authorization: TeamAuthorizationDecision
    event: TeamAuditEvent
    head: TeamLedgerHead


@dataclass(frozen=True, slots=True)
class TeamEventSummary:
    sequence: int
    event_id: str
    event_sha256: str
    decision_id: str
    occurred_at: str
    principal: TeamPrincipal
    action: TeamAction
    resource: TeamResource
    authorized: bool
    authorization_reason: TeamAuthorizationReason
    outcome: TeamAuditOutcome
    payload: TeamDocumentSubject
    retention: TeamRetentionRequirement
    policy: TeamPolicySubject


@dataclass(frozen=True, slots=True)
class TeamEventPage:
    summary: TeamTenantSummary
    events: tuple[TeamEventSummary, ...]
    next_before_sequence: int | None


@dataclass(frozen=True, slots=True)
class TeamCaseView:
    record: TeamCaseRecord
    event: TeamEventSummary


@dataclass(frozen=True, slots=True)
class TeamCasePage:
    summary: TeamTenantSummary
    cases: tuple[TeamCaseView, ...]
    next_before_sequence: int | None


@dataclass(frozen=True, slots=True)
class TeamCaseDetail:
    summary: TeamTenantSummary
    case: TeamCaseView


@dataclass(frozen=True, slots=True)
class TeamCasePublication:
    authorization: TeamAuthorizationDecision
    event: TeamAuditEvent
    head: TeamLedgerHead
    record: TeamCaseRecord | None


@dataclass(frozen=True, slots=True)
class TeamInvestigationView:
    record: TeamInvestigationRecord
    event: TeamEventSummary


@dataclass(frozen=True, slots=True)
class TeamInvestigationPage:
    summary: TeamTenantSummary
    investigations: tuple[TeamInvestigationView, ...]
    next_before_sequence: int | None


@dataclass(frozen=True, slots=True)
class TeamInvestigationDetail:
    summary: TeamTenantSummary
    investigation: TeamInvestigationView


@dataclass(frozen=True, slots=True)
class TeamInvestigationMutation:
    authorization: TeamAuthorizationDecision
    event: TeamAuditEvent
    head: TeamLedgerHead
    record: TeamInvestigationRecord | None


def _default_identifier(prefix: str) -> str:
    return f"{prefix}-{uuid.uuid4()}"


def _validate_identity(identity: AuthenticatedTeamIdentity) -> AuthenticatedTeamIdentity:
    if type(identity) is not AuthenticatedTeamIdentity:
        raise TeamIdentityError(
            "identity_context_invalid",
            "the host must inject an AuthenticatedTeamIdentity",
        )
    for name, value in (
        ("tenant_id", identity.tenant_id),
        ("identity_provider", identity.identity_provider),
        ("subject_id", identity.subject_id),
    ):
        if not isinstance(value, str) or _SAFE_ID_PATTERN.fullmatch(value) is None:
            raise TeamIdentityError(
                "identity_context_invalid",
                f"the trusted {name} is not a valid Team identifier",
            )
    return identity


def _validate_expected_head(value: str | None) -> str | None:
    if value is not None and (
        not isinstance(value, str) or _SHA256_PATTERN.fullmatch(value) is None
    ):
        raise TeamApplicationError(
            "expected_head_invalid",
            "expected_head_sha256 must be null or a lowercase SHA-256 digest",
        )
    return value


def _case_publication_subject_bytes(
    case_id: str,
    *,
    change_case_bytes: bytes,
    review_result_bytes: bytes,
    azure_publication_bytes: bytes | None,
    azure_verification_bytes: bytes | None,
    approval_verification_bytes: bytes | None,
    canary_result_bytes: bytes | None,
) -> bytes:
    sources: dict[str, dict[str, int | str]] = {}
    for role, raw_bytes in (
        ("change_case", change_case_bytes),
        ("review_result", review_result_bytes),
        ("azure_publication", azure_publication_bytes),
        ("azure_verification", azure_verification_bytes),
        ("approval_verification", approval_verification_bytes),
        ("canary_result", canary_result_bytes),
    ):
        if raw_bytes is None:
            continue
        if not isinstance(raw_bytes, bytes) or not raw_bytes:
            raise TeamApplicationError(
                "case_source_invalid",
                f"{role} must be nonempty exact bytes when supplied",
            )
        sources[role] = {
            "sha256": hashlib.sha256(raw_bytes).hexdigest(),
            "byte_count": len(raw_bytes),
        }
    return (
        json.dumps(
            {"case_id": case_id, "sources": sources},
            allow_nan=False,
            ensure_ascii=False,
            separators=(",", ":"),
            sort_keys=True,
        )
        + "\n"
    ).encode("utf-8")


def _validate_expected_revision(value: int) -> int:
    if isinstance(value, bool) or not isinstance(value, int) or not 0 <= value < 10_000:
        raise TeamApplicationError(
            "expected_revision_invalid",
            "expected_revision must be an integer from 0 through 9999",
        )
    return value


def _investigation_mutation_subject_bytes(
    operation: str,
    investigation_id: str,
    expected_revision: int,
    *,
    intent: dict[str, object],
    fixture_bytes: bytes | None = None,
) -> bytes:
    if operation not in {"open", "attach", "transition"}:
        raise TeamApplicationError(
            "investigation_operation_invalid",
            "investigation mutation operation is unsupported",
        )
    intent_bytes = json.dumps(
        intent,
        allow_nan=False,
        ensure_ascii=False,
        separators=(",", ":"),
        sort_keys=True,
    ).encode("utf-8")
    document: dict[str, object] = {
        "operation": operation,
        "investigation_id": investigation_id,
        "expected_revision": expected_revision,
        "intent": {
            "media_type": "application/json",
            "sha256": hashlib.sha256(intent_bytes).hexdigest(),
            "byte_count": len(intent_bytes),
        },
    }
    if fixture_bytes is not None:
        if not isinstance(fixture_bytes, bytes) or not fixture_bytes:
            raise TeamApplicationError(
                "investigation_fixture_invalid",
                "fixture_bytes must be nonempty exact bytes when supplied",
            )
        document["fixture"] = {
            "sha256": hashlib.sha256(fixture_bytes).hexdigest(),
            "byte_count": len(fixture_bytes),
        }
    return (
        json.dumps(
            document,
            allow_nan=False,
            ensure_ascii=False,
            separators=(",", ":"),
            sort_keys=True,
        )
        + "\n"
    ).encode("utf-8")


def _event_summary(event: TeamAuditEvent) -> TeamEventSummary:
    entry = event.entry
    authorization = entry.authorization
    return TeamEventSummary(
        sequence=entry.sequence,
        event_id=entry.event_id,
        event_sha256=event.event_sha256,
        decision_id=authorization.decision_id,
        occurred_at=entry.occurred_at,
        principal=authorization.principal,
        action=authorization.action,
        resource=authorization.resource,
        authorized=authorization.authorized,
        authorization_reason=authorization.reason,
        outcome=entry.outcome,
        payload=entry.payload,
        retention=entry.retention,
        policy=authorization.policy,
    )


class TeamApplicationService:
    """Compose trusted identity, Team policy, and SQLite state transitions."""

    def __init__(
        self,
        store: SQLiteTeamStore,
        *,
        clock: _Clock = utc_timestamp,
        identifier_factory: _IdentifierFactory = _default_identifier,
    ) -> None:
        if not isinstance(store, SQLiteTeamStore):
            raise TypeError("store must be a SQLiteTeamStore")
        if not callable(clock):
            raise TypeError("clock must be callable")
        if not callable(identifier_factory):
            raise TypeError("identifier_factory must be callable")
        self._store = store
        self._clock = clock
        self._identifier_factory = identifier_factory

    @property
    def store(self) -> SQLiteTeamStore:
        return self._store

    def _active_policy(
        self,
        identity: AuthenticatedTeamIdentity,
    ) -> tuple[bytes, TeamAccessPolicy]:
        trusted = _validate_identity(identity)
        policy_bytes = self._store.get_active_policy_bytes(trusted.tenant_id)
        policy = parse_team_access_policy_bytes(policy_bytes)
        if policy.tenant_id != trusted.tenant_id:
            raise TeamIdentityError(
                "tenant_context_mismatch",
                "the trusted tenant does not match its active policy",
            )
        return policy_bytes, policy

    @staticmethod
    def _roles(
        policy: TeamAccessPolicy,
        identity: AuthenticatedTeamIdentity,
    ) -> tuple[TeamRole, ...]:
        principal = TeamPrincipal(
            identity_provider=identity.identity_provider,
            subject_id=identity.subject_id,
        )
        for membership in policy.memberships:
            if membership.principal == principal:
                return membership.roles
        return ()

    @staticmethod
    def _require_investigator_assignee(
        policy: TeamAccessPolicy,
        principal: TeamPrincipal | None,
    ) -> None:
        if principal is None:
            return
        for membership in policy.memberships:
            if membership.principal == principal and TeamRole.INVESTIGATOR in membership.roles:
                return
        raise TeamApplicationError(
            "investigation_assignee_invalid",
            "assigned_to must identify a current tenant investigator",
        )

    @staticmethod
    def _policy_for_identity(
        policy_bytes: bytes,
        identity: AuthenticatedTeamIdentity,
    ) -> TeamAccessPolicy:
        policy = parse_team_access_policy_bytes(policy_bytes)
        if policy.tenant_id != identity.tenant_id:
            raise TeamIdentityError(
                "tenant_context_mismatch",
                "the trusted tenant does not match its active policy",
            )
        return policy

    @staticmethod
    def _summary(
        policy_bytes: bytes,
        policy: TeamAccessPolicy,
        roles: tuple[TeamRole, ...],
        head: TeamLedgerHead,
    ) -> TeamTenantSummary:
        return TeamTenantSummary(
            tenant_id=policy.tenant_id,
            policy_id=policy.policy_id,
            policy_revision=policy.revision,
            policy_effective_at=policy.effective_at,
            policy_sha256=hashlib.sha256(policy_bytes).hexdigest(),
            policy_byte_count=len(policy_bytes),
            assigned_roles=roles,
            head=head,
        )

    def _new_identifier(self, prefix: str) -> str:
        value = self._identifier_factory(prefix)
        if not isinstance(value, str) or _SAFE_ID_PATTERN.fullmatch(value) is None:
            raise TeamApplicationError(
                "generated_identifier_invalid",
                f"the server-generated {prefix} identifier is invalid",
            )
        return value

    def _timestamp(self) -> str:
        value = self._clock()
        if not isinstance(value, str):
            raise TeamApplicationError(
                "generated_timestamp_invalid",
                "the server clock did not return a whole-second UTC timestamp",
            )
        try:
            parsed = datetime.strptime(value, _UTC_TIMESTAMP_FORMAT)
        except ValueError as exc:
            raise TeamApplicationError(
                "generated_timestamp_invalid",
                "the server clock did not return a whole-second UTC timestamp",
            ) from exc
        if parsed.strftime(_UTC_TIMESTAMP_FORMAT) != value:
            raise TeamApplicationError(
                "generated_timestamp_invalid",
                "the server clock did not return a whole-second UTC timestamp",
            )
        return value

    def _commit_investigation_mutation(
        self,
        *,
        policy_bytes: bytes,
        decision: TeamAuthorizationDecision,
        instant: str,
        expected_head_sha256: str | None,
        previous_event_bytes: bytes | None,
        request_subject_bytes: bytes,
        record: TeamInvestigationRecord | None,
        retention_class_id: str | None,
    ) -> TeamInvestigationMutation:
        payload_bytes = request_subject_bytes
        payload_media_type = _INVESTIGATION_MUTATION_SUBJECT_MEDIA_TYPE
        outcome = TeamAuditOutcome.DENIED
        if record is not None:
            payload_bytes = render_team_investigation_record(record).encode("utf-8")
            payload_media_type = TEAM_INVESTIGATION_RECORD_MEDIA_TYPE
            outcome = TeamAuditOutcome.SUCCEEDED
        event = create_team_audit_event(
            policy_bytes,
            render_team_authorization(decision).encode("utf-8"),
            payload_bytes,
            payload_media_type=payload_media_type,
            event_id=self._new_identifier("event"),
            outcome=outcome,
            occurred_at=instant,
            retention_class_id=retention_class_id,
            previous_event_bytes=previous_event_bytes,
        )
        event_bytes = render_team_audit_event(event).encode("utf-8")
        if record is None:
            head = self._store.append_event(
                event_bytes,
                expected_head_sha256=expected_head_sha256,
                require_active_policy=True,
            )
        else:
            head = self._store.append_investigation_record(
                event_bytes,
                payload_bytes,
                expected_head_sha256=expected_head_sha256,
                require_active_policy=True,
            )
        return TeamInvestigationMutation(
            authorization=decision,
            event=event,
            head=head,
            record=record,
        )

    def get_tenant_summary(
        self,
        identity: AuthenticatedTeamIdentity,
    ) -> TeamTenantSummary:
        """Return non-membership policy metadata and the protected tenant head."""

        trusted = _validate_identity(identity)
        snapshot = self._store.get_tenant_snapshot(trusted.tenant_id)
        policy_bytes = snapshot.policy_bytes
        policy = self._policy_for_identity(policy_bytes, trusted)
        roles = self._roles(policy, trusted)
        if not roles:
            raise TeamAccessDeniedError(
                "principal_not_member",
                "the authenticated principal is not a current tenant member",
            )
        return self._summary(policy_bytes, policy, roles, snapshot.head)

    def get_event_bytes(
        self,
        identity: AuthenticatedTeamIdentity,
        sequence: int,
    ) -> bytes:
        """Return exact event bytes after current tenant-membership verification."""

        trusted = _validate_identity(identity)
        snapshot = self._store.get_tenant_snapshot(
            trusted.tenant_id,
            event_sequence=sequence,
        )
        policy = self._policy_for_identity(snapshot.policy_bytes, trusted)
        if not self._roles(policy, trusted):
            raise TeamAccessDeniedError(
                "principal_not_member",
                "the authenticated principal is not a current tenant member",
            )
        if snapshot.event_bytes is None:
            raise TeamStoreError(
                "event_not_found",
                "the requested Team audit event does not exist",
            )
        return snapshot.event_bytes

    def list_recent_events(
        self,
        identity: AuthenticatedTeamIdentity,
        *,
        limit: int = 50,
        before_sequence: int | None = None,
    ) -> TeamEventPage:
        """Return a bounded newest-first event summary page for a current member."""

        trusted = _validate_identity(identity)
        snapshot = self._store.get_event_page_snapshot(
            trusted.tenant_id,
            limit=limit,
            before_sequence=before_sequence,
        )
        policy = self._policy_for_identity(snapshot.policy_bytes, trusted)
        roles = self._roles(policy, trusted)
        if not roles:
            raise TeamAccessDeniedError(
                "principal_not_member",
                "the authenticated principal is not a current tenant member",
            )

        events: list[TeamEventSummary] = []
        expected_sequence = min(
            snapshot.head.sequence,
            (snapshot.head.sequence if before_sequence is None else before_sequence - 1),
        )
        for event_bytes in snapshot.event_bytes:
            event = parse_team_audit_event_bytes(event_bytes)
            entry = event.entry
            if entry.tenant_id != trusted.tenant_id or entry.sequence != expected_sequence:
                raise TeamApplicationError(
                    "event_snapshot_invalid",
                    "the stored event page is not a contiguous tenant snapshot",
                )
            events.append(_event_summary(event))
            expected_sequence -= 1
        if expected_sequence > 0 and not events:
            raise TeamApplicationError(
                "event_snapshot_invalid",
                "the stored event page unexpectedly omitted existing events",
            )
        if snapshot.next_before_sequence is not None and (
            not events
            or snapshot.next_before_sequence != events[-1].sequence
            or expected_sequence < 1
        ):
            raise TeamApplicationError(
                "event_snapshot_invalid",
                "the stored event page cursor is inconsistent",
            )
        if snapshot.next_before_sequence is None and expected_sequence > 0:
            raise TeamApplicationError(
                "event_snapshot_invalid",
                "the stored event page omitted its required continuation cursor",
            )
        return TeamEventPage(
            summary=self._summary(
                snapshot.policy_bytes,
                policy,
                roles,
                snapshot.head,
            ),
            events=tuple(events),
            next_before_sequence=snapshot.next_before_sequence,
        )

    def list_cases(
        self,
        identity: AuthenticatedTeamIdentity,
        *,
        limit: int = 50,
        before_sequence: int | None = None,
    ) -> TeamCasePage:
        """Return bounded latest case revisions for a current tenant member."""

        trusted = _validate_identity(identity)
        snapshot = self._store.get_case_page_snapshot(
            trusted.tenant_id,
            limit=limit,
            before_sequence=before_sequence,
        )
        policy = self._policy_for_identity(snapshot.policy_bytes, trusted)
        roles = self._roles(policy, trusted)
        if not roles:
            raise TeamAccessDeniedError(
                "principal_not_member",
                "the authenticated principal is not a current tenant member",
            )
        cases: list[TeamCaseView] = []
        previous_sequence = (
            snapshot.head.sequence + 1 if before_sequence is None else before_sequence
        )
        for item in snapshot.items:
            record = parse_team_case_record_bytes(item.record_bytes)
            event = parse_team_audit_event_bytes(item.event_bytes)
            if (
                record.tenant_id != trusted.tenant_id
                or event.entry.tenant_id != trusted.tenant_id
                or event.entry.sequence >= previous_sequence
            ):
                raise TeamApplicationError(
                    "case_snapshot_invalid",
                    "the stored case page is not a newest-first tenant snapshot",
                )
            cases.append(TeamCaseView(record=record, event=_event_summary(event)))
            previous_sequence = event.entry.sequence
        if snapshot.next_before_sequence is not None and (
            not cases or snapshot.next_before_sequence != cases[-1].event.sequence
        ):
            raise TeamApplicationError(
                "case_snapshot_invalid",
                "the stored case page continuation cursor is inconsistent",
            )
        return TeamCasePage(
            summary=self._summary(snapshot.policy_bytes, policy, roles, snapshot.head),
            cases=tuple(cases),
            next_before_sequence=snapshot.next_before_sequence,
        )

    def get_case(
        self,
        identity: AuthenticatedTeamIdentity,
        case_id: str,
    ) -> TeamCaseDetail:
        """Return one latest minimized case record after current membership checks."""

        trusted = _validate_identity(identity)
        if not isinstance(case_id, str) or _CASE_ID_PATTERN.fullmatch(case_id) is None:
            raise TeamApplicationError(
                "case_id_invalid",
                "case_id must use the closed 3-128 character case identifier format",
            )
        snapshot = self._store.get_case_record_snapshot(trusted.tenant_id, case_id)
        policy = self._policy_for_identity(snapshot.policy_bytes, trusted)
        roles = self._roles(policy, trusted)
        if not roles:
            raise TeamAccessDeniedError(
                "principal_not_member",
                "the authenticated principal is not a current tenant member",
            )
        if snapshot.item is None:
            raise TeamStoreError(
                "case_not_found",
                "the requested Team case does not exist",
            )
        record = parse_team_case_record_bytes(snapshot.item.record_bytes)
        event = parse_team_audit_event_bytes(snapshot.item.event_bytes)
        if record.case_id != case_id:
            raise TeamApplicationError(
                "case_snapshot_invalid",
                "the stored case bytes do not match the requested case",
            )
        return TeamCaseDetail(
            summary=self._summary(snapshot.policy_bytes, policy, roles, snapshot.head),
            case=TeamCaseView(record=record, event=_event_summary(event)),
        )

    def list_investigations(
        self,
        identity: AuthenticatedTeamIdentity,
        *,
        limit: int = 50,
        before_sequence: int | None = None,
        status: TeamInvestigationStatus | str | None = None,
        priority: TeamInvestigationPriority | str | None = None,
    ) -> TeamInvestigationPage:
        """Return bounded latest investigation revisions for a current member."""

        trusted = _validate_identity(identity)
        snapshot = self._store.get_investigation_page_snapshot(
            trusted.tenant_id,
            limit=limit,
            before_sequence=before_sequence,
            status=status,
            priority=priority,
        )
        policy = self._policy_for_identity(snapshot.policy_bytes, trusted)
        roles = self._roles(policy, trusted)
        if not roles:
            raise TeamAccessDeniedError(
                "principal_not_member",
                "the authenticated principal is not a current tenant member",
            )
        investigations: list[TeamInvestigationView] = []
        previous_sequence = (
            snapshot.head.sequence + 1 if before_sequence is None else before_sequence
        )
        for item in snapshot.items:
            record = parse_team_investigation_record_bytes(item.record_bytes)
            event = parse_team_audit_event_bytes(item.event_bytes)
            if (
                record.tenant_id != trusted.tenant_id
                or event.entry.tenant_id != trusted.tenant_id
                or event.entry.sequence >= previous_sequence
            ):
                raise TeamApplicationError(
                    "investigation_snapshot_invalid",
                    "the stored investigation page is not a newest-first tenant snapshot",
                )
            investigations.append(TeamInvestigationView(record=record, event=_event_summary(event)))
            previous_sequence = event.entry.sequence
        if snapshot.next_before_sequence is not None and (
            not investigations or snapshot.next_before_sequence != investigations[-1].event.sequence
        ):
            raise TeamApplicationError(
                "investigation_snapshot_invalid",
                "the investigation page continuation cursor is inconsistent",
            )
        return TeamInvestigationPage(
            summary=self._summary(snapshot.policy_bytes, policy, roles, snapshot.head),
            investigations=tuple(investigations),
            next_before_sequence=snapshot.next_before_sequence,
        )

    def get_investigation(
        self,
        identity: AuthenticatedTeamIdentity,
        investigation_id: str,
    ) -> TeamInvestigationDetail:
        """Return one latest minimized investigation after membership checks."""

        trusted = _validate_identity(identity)
        if (
            not isinstance(investigation_id, str)
            or _CASE_ID_PATTERN.fullmatch(investigation_id) is None
        ):
            raise TeamApplicationError(
                "investigation_id_invalid",
                "investigation_id must use the closed 3-128 character identifier format",
            )
        snapshot = self._store.get_investigation_record_snapshot(
            trusted.tenant_id,
            investigation_id,
        )
        policy = self._policy_for_identity(snapshot.policy_bytes, trusted)
        roles = self._roles(policy, trusted)
        if not roles:
            raise TeamAccessDeniedError(
                "principal_not_member",
                "the authenticated principal is not a current tenant member",
            )
        if snapshot.item is None:
            raise TeamStoreError(
                "investigation_not_found",
                "the requested Team investigation does not exist",
            )
        record = parse_team_investigation_record_bytes(snapshot.item.record_bytes)
        event = parse_team_audit_event_bytes(snapshot.item.event_bytes)
        if record.investigation_id != investigation_id:
            raise TeamApplicationError(
                "investigation_snapshot_invalid",
                "stored investigation bytes do not match the requested id",
            )
        return TeamInvestigationDetail(
            summary=self._summary(snapshot.policy_bytes, policy, roles, snapshot.head),
            investigation=TeamInvestigationView(
                record=record,
                event=_event_summary(event),
            ),
        )

    def publish_case(
        self,
        identity: AuthenticatedTeamIdentity,
        *,
        case_id: str,
        change_case_bytes: bytes,
        review_result_bytes: bytes,
        expected_head_sha256: str | None,
        azure_publication_bytes: bytes | None = None,
        azure_verification_bytes: bytes | None = None,
        approval_verification_bytes: bytes | None = None,
        canary_result_bytes: bytes | None = None,
        retention_class_id: str | None = None,
    ) -> TeamCasePublication:
        """Authorize and atomically publish one minimized, exact-bound case revision."""

        trusted = _validate_identity(identity)
        if not isinstance(case_id, str) or _CASE_ID_PATTERN.fullmatch(case_id) is None:
            raise TeamApplicationError(
                "case_id_invalid",
                "case_id must use the closed 3-128 character case identifier format",
            )
        expected_head = _validate_expected_head(expected_head_sha256)
        request_subject_bytes = _case_publication_subject_bytes(
            case_id,
            change_case_bytes=change_case_bytes,
            review_result_bytes=review_result_bytes,
            azure_publication_bytes=azure_publication_bytes,
            azure_verification_bytes=azure_verification_bytes,
            approval_verification_bytes=approval_verification_bytes,
            canary_result_bytes=canary_result_bytes,
        )
        snapshot = self._store.get_case_record_snapshot(trusted.tenant_id, case_id)
        policy_bytes = snapshot.policy_bytes
        self._policy_for_identity(policy_bytes, trusted)
        current_head = snapshot.head
        if current_head.event_sha256 != expected_head:
            raise TeamStoreConflictError(
                "head_conflict",
                "the expected tenant head is stale; reload it before publishing the case",
            )
        previous_event_bytes = (
            None
            if current_head.sequence == 0
            else self._store.get_event_bytes(trusted.tenant_id, current_head.sequence)
        )
        instant = self._timestamp()
        decision = create_team_authorization(
            policy_bytes,
            decision_id=self._new_identifier("decision"),
            identity_provider=trusted.identity_provider,
            subject_id=trusted.subject_id,
            action=TeamAction.INVESTIGATION_WRITE,
            resource_type=TeamResourceType.INVESTIGATION,
            resource_id=case_id,
            decided_at=instant,
        )

        record: TeamCaseRecord | None = None
        payload_bytes = request_subject_bytes
        payload_media_type = _CASE_PUBLICATION_SUBJECT_MEDIA_TYPE
        requested_outcome = TeamAuditOutcome.DENIED
        if decision.authorized:
            previous_record = (
                None
                if snapshot.item is None
                else parse_team_case_record_bytes(snapshot.item.record_bytes)
            )
            try:
                record = create_team_case_record(
                    change_case_bytes,
                    review_result_bytes,
                    tenant_id=trusted.tenant_id,
                    revision=(1 if previous_record is None else previous_record.revision + 1),
                    published_at=instant,
                    azure_publication_bytes=azure_publication_bytes,
                    azure_verification_bytes=azure_verification_bytes,
                    approval_verification_bytes=approval_verification_bytes,
                    canary_result_bytes=canary_result_bytes,
                )
                if record.case_id != case_id:
                    raise TeamCaseValidationError(
                        "Team case source chain",
                        "$.change_case.case_id",
                        "does not match the authorized case_id",
                    )
                validate_team_case_successor(previous_record, record)
            except TeamCaseValidationError as exc:
                raise TeamApplicationError("case_source_invalid", str(exc)) from exc
            payload_bytes = render_team_case_record(record).encode("utf-8")
            payload_media_type = TEAM_CASE_RECORD_MEDIA_TYPE
            requested_outcome = TeamAuditOutcome.SUCCEEDED

        authorization_bytes = render_team_authorization(decision).encode("utf-8")
        event = create_team_audit_event(
            policy_bytes,
            authorization_bytes,
            payload_bytes,
            payload_media_type=payload_media_type,
            event_id=self._new_identifier("event"),
            outcome=requested_outcome,
            occurred_at=instant,
            retention_class_id=retention_class_id,
            previous_event_bytes=previous_event_bytes,
        )
        event_bytes = render_team_audit_event(event).encode("utf-8")
        if record is None:
            head = self._store.append_event(
                event_bytes,
                expected_head_sha256=expected_head,
                require_active_policy=True,
            )
        else:
            head = self._store.append_case_record(
                event_bytes,
                payload_bytes,
                expected_head_sha256=expected_head,
                require_active_policy=True,
            )
        return TeamCasePublication(
            authorization=decision,
            event=event,
            head=head,
            record=record,
        )

    def open_investigation(
        self,
        identity: AuthenticatedTeamIdentity,
        *,
        investigation_id: str,
        fixture_bytes: bytes,
        cluster_id: str,
        title: str,
        priority: TeamInvestigationPriority | str,
        expected_revision: int,
        expected_head_sha256: str | None,
        retention_class_id: str | None = None,
    ) -> TeamInvestigationMutation:
        """Authorize and atomically open one candidate-only investigation."""

        trusted = _validate_identity(identity)
        if (
            not isinstance(investigation_id, str)
            or _CASE_ID_PATTERN.fullmatch(investigation_id) is None
        ):
            raise TeamApplicationError(
                "investigation_id_invalid",
                "investigation_id must use the closed 3-128 character identifier format",
            )
        expected_revision = _validate_expected_revision(expected_revision)
        expected_head = _validate_expected_head(expected_head_sha256)
        request_subject = _investigation_mutation_subject_bytes(
            "open",
            investigation_id,
            expected_revision,
            intent={
                "cluster_id": cluster_id,
                "title": title,
                "priority": str(priority),
            },
            fixture_bytes=fixture_bytes,
        )
        snapshot = self._store.get_investigation_record_snapshot(
            trusted.tenant_id,
            investigation_id,
        )
        policy_bytes = snapshot.policy_bytes
        self._policy_for_identity(policy_bytes, trusted)
        if snapshot.head.event_sha256 != expected_head:
            raise TeamStoreConflictError(
                "head_conflict",
                "the expected tenant head is stale; reload before opening the investigation",
            )
        previous_event_bytes = (
            None
            if snapshot.head.sequence == 0
            else self._store.get_event_bytes(trusted.tenant_id, snapshot.head.sequence)
        )
        instant = self._timestamp()
        decision = create_team_authorization(
            policy_bytes,
            decision_id=self._new_identifier("decision"),
            identity_provider=trusted.identity_provider,
            subject_id=trusted.subject_id,
            action=TeamAction.INVESTIGATION_WRITE,
            resource_type=TeamResourceType.INVESTIGATION,
            resource_id=investigation_id,
            decided_at=instant,
        )
        record: TeamInvestigationRecord | None = None
        if decision.authorized:
            current_revision = (
                0
                if snapshot.item is None
                else parse_team_investigation_record_bytes(snapshot.item.record_bytes).revision
            )
            if expected_revision != current_revision:
                raise TeamStoreConflictError(
                    "investigation_revision_conflict",
                    "the expected investigation revision is stale",
                )
            if current_revision != 0:
                raise TeamStoreConflictError(
                    "investigation_already_exists",
                    "the investigation already exists; attach evidence or transition it",
                )
            try:
                record = create_team_investigation_record(
                    fixture_bytes,
                    tenant_id=trusted.tenant_id,
                    investigation_id=investigation_id,
                    cluster_id=cluster_id,
                    title=title,
                    priority=priority,
                    opened_at=instant,
                    opened_by=TeamPrincipal(
                        identity_provider=trusted.identity_provider,
                        subject_id=trusted.subject_id,
                    ),
                )
            except TeamInvestigationValidationError as exc:
                raise TeamApplicationError(
                    "investigation_source_invalid",
                    str(exc),
                ) from exc
        return self._commit_investigation_mutation(
            policy_bytes=policy_bytes,
            decision=decision,
            instant=instant,
            expected_head_sha256=expected_head,
            previous_event_bytes=previous_event_bytes,
            request_subject_bytes=request_subject,
            record=record,
            retention_class_id=retention_class_id,
        )

    def attach_investigation_observation(
        self,
        identity: AuthenticatedTeamIdentity,
        *,
        investigation_id: str,
        fixture_bytes: bytes,
        cluster_id: str,
        expected_revision: int,
        expected_head_sha256: str | None,
        retention_class_id: str | None = None,
    ) -> TeamInvestigationMutation:
        """Authorize and atomically attach one exact fixture cluster."""

        trusted = _validate_identity(identity)
        if (
            not isinstance(investigation_id, str)
            or _CASE_ID_PATTERN.fullmatch(investigation_id) is None
        ):
            raise TeamApplicationError(
                "investigation_id_invalid",
                "investigation_id must use the closed 3-128 character identifier format",
            )
        expected_revision = _validate_expected_revision(expected_revision)
        expected_head = _validate_expected_head(expected_head_sha256)
        request_subject = _investigation_mutation_subject_bytes(
            "attach",
            investigation_id,
            expected_revision,
            intent={"cluster_id": cluster_id},
            fixture_bytes=fixture_bytes,
        )
        snapshot = self._store.get_investigation_record_snapshot(
            trusted.tenant_id,
            investigation_id,
        )
        policy_bytes = snapshot.policy_bytes
        self._policy_for_identity(policy_bytes, trusted)
        if snapshot.head.event_sha256 != expected_head:
            raise TeamStoreConflictError(
                "head_conflict",
                "the expected tenant head is stale; reload before attaching evidence",
            )
        previous_event_bytes = (
            None
            if snapshot.head.sequence == 0
            else self._store.get_event_bytes(trusted.tenant_id, snapshot.head.sequence)
        )
        instant = self._timestamp()
        decision = create_team_authorization(
            policy_bytes,
            decision_id=self._new_identifier("decision"),
            identity_provider=trusted.identity_provider,
            subject_id=trusted.subject_id,
            action=TeamAction.INVESTIGATION_WRITE,
            resource_type=TeamResourceType.INVESTIGATION,
            resource_id=investigation_id,
            decided_at=instant,
        )
        record: TeamInvestigationRecord | None = None
        if decision.authorized:
            if snapshot.item is None:
                raise TeamStoreError(
                    "investigation_not_found",
                    "the requested Team investigation does not exist",
                )
            previous = parse_team_investigation_record_bytes(snapshot.item.record_bytes)
            if expected_revision != previous.revision:
                raise TeamStoreConflictError(
                    "investigation_revision_conflict",
                    "the expected investigation revision is stale",
                )
            try:
                record = attach_team_investigation_observation(
                    previous,
                    fixture_bytes,
                    cluster_id=cluster_id,
                    attached_at=instant,
                    attached_by=TeamPrincipal(
                        identity_provider=trusted.identity_provider,
                        subject_id=trusted.subject_id,
                    ),
                )
            except TeamInvestigationValidationError as exc:
                raise TeamApplicationError(
                    "investigation_source_invalid",
                    str(exc),
                ) from exc
        return self._commit_investigation_mutation(
            policy_bytes=policy_bytes,
            decision=decision,
            instant=instant,
            expected_head_sha256=expected_head,
            previous_event_bytes=previous_event_bytes,
            request_subject_bytes=request_subject,
            record=record,
            retention_class_id=retention_class_id,
        )

    def transition_investigation(
        self,
        identity: AuthenticatedTeamIdentity,
        *,
        investigation_id: str,
        title: str,
        status: TeamInvestigationStatus | str,
        priority: TeamInvestigationPriority | str,
        assigned_to: TeamPrincipal | None,
        expected_revision: int,
        expected_head_sha256: str | None,
        resolution: TeamInvestigationResolution | str | None = None,
        linked_case_id: str | None = None,
        duplicate_of: str | None = None,
        retention_class_id: str | None = None,
    ) -> TeamInvestigationMutation:
        """Authorize and atomically transition queue state or terminal resolution."""

        trusted = _validate_identity(identity)
        if (
            not isinstance(investigation_id, str)
            or _CASE_ID_PATTERN.fullmatch(investigation_id) is None
        ):
            raise TeamApplicationError(
                "investigation_id_invalid",
                "investigation_id must use the closed 3-128 character identifier format",
            )
        if assigned_to is not None and not isinstance(assigned_to, TeamPrincipal):
            raise TeamApplicationError(
                "investigation_assignee_invalid",
                "assigned_to must be a TeamPrincipal or null",
            )
        expected_revision = _validate_expected_revision(expected_revision)
        expected_head = _validate_expected_head(expected_head_sha256)
        assigned_intent = (
            None
            if assigned_to is None
            else {
                "identity_provider": assigned_to.identity_provider,
                "subject_id": assigned_to.subject_id,
            }
        )
        request_subject = _investigation_mutation_subject_bytes(
            "transition",
            investigation_id,
            expected_revision,
            intent={
                "title": title,
                "status": str(status),
                "priority": str(priority),
                "assigned_to": assigned_intent,
                "resolution": None if resolution is None else str(resolution),
                "linked_case_id": linked_case_id,
                "duplicate_of": duplicate_of,
            },
        )
        snapshot = self._store.get_investigation_record_snapshot(
            trusted.tenant_id,
            investigation_id,
        )
        policy_bytes = snapshot.policy_bytes
        policy = self._policy_for_identity(policy_bytes, trusted)
        if snapshot.head.event_sha256 != expected_head:
            raise TeamStoreConflictError(
                "head_conflict",
                "the expected tenant head is stale; reload before transitioning the queue",
            )
        previous_event_bytes = (
            None
            if snapshot.head.sequence == 0
            else self._store.get_event_bytes(trusted.tenant_id, snapshot.head.sequence)
        )
        instant = self._timestamp()
        decision = create_team_authorization(
            policy_bytes,
            decision_id=self._new_identifier("decision"),
            identity_provider=trusted.identity_provider,
            subject_id=trusted.subject_id,
            action=TeamAction.INVESTIGATION_WRITE,
            resource_type=TeamResourceType.INVESTIGATION,
            resource_id=investigation_id,
            decided_at=instant,
        )
        record: TeamInvestigationRecord | None = None
        if decision.authorized:
            if snapshot.item is None:
                raise TeamStoreError(
                    "investigation_not_found",
                    "the requested Team investigation does not exist",
                )
            previous = parse_team_investigation_record_bytes(snapshot.item.record_bytes)
            if expected_revision != previous.revision:
                raise TeamStoreConflictError(
                    "investigation_revision_conflict",
                    "the expected investigation revision is stale",
                )
            self._require_investigator_assignee(policy, assigned_to)
            try:
                record = transition_team_investigation_record(
                    previous,
                    updated_at=instant,
                    title=title,
                    status=status,
                    priority=priority,
                    assigned_to=assigned_to,
                    resolution=resolution,
                    linked_case_id=linked_case_id,
                    duplicate_of=duplicate_of,
                )
            except TeamInvestigationValidationError as exc:
                raise TeamApplicationError(
                    "investigation_transition_invalid",
                    str(exc),
                ) from exc
            if record.linked_case_id is not None:
                linked_case = self._store.get_case_record_snapshot(
                    trusted.tenant_id,
                    record.linked_case_id,
                )
                if linked_case.item is None:
                    raise TeamApplicationError(
                        "investigation_linked_case_missing",
                        "linked_case_id does not identify a case in this tenant",
                    )
            if record.duplicate_of is not None:
                duplicate_target = self._store.get_investigation_record_snapshot(
                    trusted.tenant_id,
                    record.duplicate_of,
                )
                if duplicate_target.item is None:
                    raise TeamApplicationError(
                        "investigation_duplicate_target_missing",
                        "duplicate_of does not identify an investigation in this tenant",
                    )
                target_record = parse_team_investigation_record_bytes(
                    duplicate_target.item.record_bytes
                )
                if target_record.resolution is TeamInvestigationResolution.DUPLICATE:
                    raise TeamApplicationError(
                        "investigation_duplicate_chain_invalid",
                        "duplicate_of must identify a canonical, non-duplicate investigation",
                    )
        return self._commit_investigation_mutation(
            policy_bytes=policy_bytes,
            decision=decision,
            instant=instant,
            expected_head_sha256=expected_head,
            previous_event_bytes=previous_event_bytes,
            request_subject_bytes=request_subject,
            record=record,
            retention_class_id=retention_class_id,
        )

    def record_action(
        self,
        identity: AuthenticatedTeamIdentity,
        payload_bytes: bytes,
        *,
        payload_media_type: str,
        action: TeamAction | str,
        resource_type: TeamResourceType | str,
        resource_id: str,
        outcome: TeamAuditOutcome | str,
        expected_head_sha256: str | None,
        retention_class_id: str | None = None,
    ) -> TeamRecordedAction:
        """Authorize, create, and CAS-append one claimed action outcome."""

        trusted = _validate_identity(identity)
        expected_head = _validate_expected_head(expected_head_sha256)
        requested_outcome = TeamAuditOutcome(outcome)
        if requested_outcome is TeamAuditOutcome.DENIED:
            raise TeamApplicationError(
                "outcome_invalid",
                "clients report succeeded or failed; the service derives denied",
            )

        policy_bytes, _ = self._active_policy(trusted)
        current_head = self._store.get_head(trusted.tenant_id)
        if current_head.event_sha256 != expected_head:
            raise TeamStoreConflictError(
                "head_conflict",
                "the expected tenant head is stale; reload it before recording the action",
            )
        previous_event_bytes = (
            None
            if current_head.sequence == 0
            else self._store.get_event_bytes(trusted.tenant_id, current_head.sequence)
        )
        instant = self._timestamp()
        decision = create_team_authorization(
            policy_bytes,
            decision_id=self._new_identifier("decision"),
            identity_provider=trusted.identity_provider,
            subject_id=trusted.subject_id,
            action=action,
            resource_type=resource_type,
            resource_id=resource_id,
            decided_at=instant,
        )
        authorization_bytes = render_team_authorization(decision).encode("utf-8")
        event = create_team_audit_event(
            policy_bytes,
            authorization_bytes,
            payload_bytes,
            payload_media_type=payload_media_type,
            event_id=self._new_identifier("event"),
            outcome=(requested_outcome if decision.authorized else TeamAuditOutcome.DENIED),
            occurred_at=instant,
            retention_class_id=retention_class_id,
            previous_event_bytes=previous_event_bytes,
        )
        event_bytes = render_team_audit_event(event).encode("utf-8")
        head = self._store.append_event(
            event_bytes,
            expected_head_sha256=expected_head,
            require_active_policy=True,
        )
        return TeamRecordedAction(
            authorization=decision,
            event=event,
            head=head,
        )

    def create_audit_export(
        self,
        identity: AuthenticatedTeamIdentity,
    ) -> TeamAuditExport:
        """Authorize and persist a complete export using server IDs and time."""

        trusted = _validate_identity(identity)
        policy_bytes, _ = self._active_policy(trusted)
        instant = self._timestamp()
        export_id = self._new_identifier("export")
        decision = create_team_authorization(
            policy_bytes,
            decision_id=self._new_identifier("decision"),
            identity_provider=trusted.identity_provider,
            subject_id=trusted.subject_id,
            action=TeamAction.AUDIT_EXPORT,
            resource_type=TeamResourceType.AUDIT_EXPORT,
            resource_id=export_id,
            decided_at=instant,
        )
        if not decision.authorized:
            raise TeamAccessDeniedError(
                "action_denied",
                "the active tenant policy does not grant audit export",
                decision=decision,
            )
        return self._store.create_export(
            render_team_authorization(decision).encode("utf-8"),
            export_id=export_id,
            created_at=instant,
        )
