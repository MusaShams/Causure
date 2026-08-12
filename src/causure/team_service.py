"""Tenant authorization and tamper-evident audit contracts for the Team service."""

from __future__ import annotations

import hashlib
import json
import re
from dataclasses import dataclass
from datetime import datetime, timedelta
from enum import Enum
from typing import Any, TypeVar

from causure.attestations import utc_timestamp
from causure.constants import (
    PACKAGE_VERSION,
    TEAM_ACCESS_POLICY_SCHEMA_VERSION,
    TEAM_AUDIT_EVENT_SCHEMA_VERSION,
    TEAM_AUDIT_EXPORT_SCHEMA_VERSION,
    TEAM_AUDIT_VERIFICATION_SCHEMA_VERSION,
    TEAM_AUTHORIZATION_SCHEMA_VERSION,
    TeamAction,
    TeamAuditOutcome,
    TeamAuthorizationReason,
    TeamResourceType,
    TeamRole,
)
from causure.io import InputDocumentError, parse_json_text
from causure.models import to_jsonable

MAX_TEAM_ACCESS_POLICY_BYTES = 4 * 1024 * 1024
MAX_TEAM_AUTHORIZATION_BYTES = 512 * 1024
MAX_TEAM_AUDIT_EVENT_BYTES = 1024 * 1024
MAX_TEAM_AUDIT_PAYLOAD_BYTES = 16 * 1024 * 1024
MAX_TEAM_AUDIT_EXPORT_BYTES = 64 * 1024 * 1024
MAX_TEAM_MEMBERSHIPS = 10_000
MAX_TEAM_RETENTION_CLASSES = 32
MAX_TEAM_EXPORT_EVENTS = 10_000
MAX_TEAM_RETENTION_DAYS = 3_650
MAX_TEAM_AUTHORIZATION_AGE_SECONDS = 15 * 60
DEFAULT_TEAM_CLOCK_SKEW_SECONDS = 5 * 60

_ACCESS_POLICY_MEDIA_TYPE = "application/vnd.causure.team-access-policy+json"
_AUDIT_EXPORT_MEDIA_TYPE = "application/vnd.causure.team-audit-export+json"
_SAFE_ID_PATTERN = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:+/@-]{0,127}$")
_MEDIA_TYPE_PATTERN = re.compile(
    r"^[a-z0-9][a-z0-9!#$&^_.+-]{0,126}/[a-z0-9][a-z0-9!#$&^_.+-]{0,126}$"
)
_SHA256_PATTERN = re.compile(r"^[a-f0-9]{64}$")
_UTC_TIMESTAMP_PATTERN = re.compile(
    r"^[0-9]{4}-(0[1-9]|1[0-2])-([0-2][0-9]|3[01])T"
    r"([01][0-9]|2[0-3]):[0-5][0-9]:[0-5][0-9]Z$"
)
_NO_CONTROL_PATTERN = re.compile(r"^[^\x00-\x1f\x7f]+$")
_EnumT = TypeVar("_EnumT", bound=Enum)

_ROLE_GRANTS: dict[TeamRole, frozenset[TeamAction]] = {
    TeamRole.INVESTIGATOR: frozenset(
        {
            TeamAction.EVIDENCE_READ,
            TeamAction.INVESTIGATION_WRITE,
        }
    ),
    TeamRole.POLICY_ADMINISTRATOR: frozenset(
        {
            TeamAction.EVIDENCE_READ,
            TeamAction.POLICY_WRITE,
            TeamAction.AUDIT_EXPORT,
        }
    ),
    TeamRole.APPROVER: frozenset(
        {
            TeamAction.EVIDENCE_READ,
            TeamAction.APPROVAL_ISSUE,
        }
    ),
}

_ACTION_RESOURCES: dict[TeamAction, frozenset[TeamResourceType]] = {
    TeamAction.EVIDENCE_READ: frozenset(
        {
            TeamResourceType.EVIDENCE_CASE,
            TeamResourceType.INVESTIGATION,
        }
    ),
    TeamAction.INVESTIGATION_WRITE: frozenset({TeamResourceType.INVESTIGATION}),
    TeamAction.POLICY_WRITE: frozenset({TeamResourceType.GATE_POLICY}),
    TeamAction.APPROVAL_ISSUE: frozenset({TeamResourceType.APPROVAL}),
    TeamAction.AUDIT_EXPORT: frozenset({TeamResourceType.AUDIT_EXPORT}),
}


class TeamValidationError(ValueError):
    """Raised when a Team-service document violates its closed wire contract."""

    def __init__(self, document_name: str, path: str, message: str) -> None:
        self.document_name = document_name
        self.path = path
        self.message = message
        super().__init__(f"Invalid {document_name} at {path}: {message}")


class TeamAuthorizationError(ValueError):
    """Raised when a recorded authorization cannot be reproduced from its policy."""

    def __init__(self, code: str, message: str) -> None:
        self.code = code
        self.message = message
        super().__init__(f"Team authorization failed [{code}]: {message}")


class TeamAuditVerificationError(ValueError):
    """Raised when a Team audit export cannot be independently verified."""

    def __init__(self, code: str, message: str) -> None:
        self.code = code
        self.message = message
        super().__init__(f"Team audit verification failed [{code}]: {message}")


@dataclass(frozen=True, slots=True)
class TeamPrincipal:
    identity_provider: str
    subject_id: str


@dataclass(frozen=True, slots=True)
class TeamMembership:
    principal: TeamPrincipal
    roles: tuple[TeamRole, ...]


@dataclass(frozen=True, slots=True)
class TeamRetentionClass:
    class_id: str
    minimum_days: int


@dataclass(frozen=True, slots=True)
class TeamAccessPolicy:
    schema_version: str
    tenant_id: str
    policy_id: str
    revision: int
    effective_at: str
    default_retention_class_id: str
    memberships: tuple[TeamMembership, ...]
    retention_classes: tuple[TeamRetentionClass, ...]


@dataclass(frozen=True, slots=True)
class TeamResource:
    resource_type: TeamResourceType
    resource_id: str


@dataclass(frozen=True, slots=True)
class TeamPolicySubject:
    media_type: str
    policy_id: str
    revision: int
    sha256: str
    byte_count: int


@dataclass(frozen=True, slots=True)
class TeamAuthorizationDecision:
    schema_version: str
    decision_id: str
    tenant_id: str
    principal: TeamPrincipal
    action: TeamAction
    resource: TeamResource
    authorized: bool
    assigned_roles: tuple[TeamRole, ...]
    granting_roles: tuple[TeamRole, ...]
    reason: TeamAuthorizationReason
    decided_at: str
    policy: TeamPolicySubject


@dataclass(frozen=True, slots=True)
class TeamDocumentSubject:
    media_type: str
    sha256: str
    byte_count: int


@dataclass(frozen=True, slots=True)
class TeamRetentionRequirement:
    class_id: str
    retain_until: str


@dataclass(frozen=True, slots=True)
class TeamAuditEntry:
    event_id: str
    tenant_id: str
    sequence: int
    occurred_at: str
    authorization: TeamAuthorizationDecision
    outcome: TeamAuditOutcome
    payload: TeamDocumentSubject
    retention: TeamRetentionRequirement
    previous_event_sha256: str | None


@dataclass(frozen=True, slots=True)
class TeamAuditEvent:
    schema_version: str
    entry: TeamAuditEntry
    event_sha256: str


@dataclass(frozen=True, slots=True)
class TeamAuditRange:
    first_sequence: int
    last_sequence: int
    event_count: int


@dataclass(frozen=True, slots=True)
class TeamAuditExport:
    schema_version: str
    export_id: str
    tenant_id: str
    created_at: str
    authorization: TeamAuthorizationDecision
    audit_range: TeamAuditRange
    head_event_sha256: str
    retention: TeamRetentionRequirement
    events: tuple[TeamAuditEvent, ...]


@dataclass(frozen=True, slots=True)
class TeamAuditVerification:
    schema_version: str
    verifier_version: str
    status: str
    checked_at: str
    export: TeamDocumentSubject
    export_id: str
    tenant_id: str
    audit_range: TeamAuditRange
    head_event_sha256: str
    retention: TeamRetentionRequirement
    exporter: TeamPrincipal
    policy: TeamPolicySubject


def _object(
    value: Any,
    path: str,
    document_name: str,
    *,
    required: set[str],
    optional: set[str] | None = None,
) -> dict[str, Any]:
    if not isinstance(value, dict):
        raise TeamValidationError(document_name, path, "expected an object")
    allowed = required | (optional or set())
    unknown = sorted(set(value) - allowed)
    if unknown:
        raise TeamValidationError(document_name, path, f"unknown field: {unknown[0]}")
    missing = sorted(required - set(value))
    if missing:
        raise TeamValidationError(
            document_name,
            path,
            f"missing required field: {missing[0]}",
        )
    return value


def _array(
    value: Any,
    path: str,
    document_name: str,
    *,
    minimum: int,
    maximum: int,
) -> list[Any]:
    if not isinstance(value, list):
        raise TeamValidationError(document_name, path, "expected an array")
    if not minimum <= len(value) <= maximum:
        raise TeamValidationError(
            document_name,
            path,
            f"expected from {minimum} to {maximum} item(s)",
        )
    return value


def _string(
    value: Any,
    path: str,
    document_name: str,
    *,
    maximum: int = 128,
    pattern: re.Pattern[str] | None = None,
) -> str:
    if not isinstance(value, str) or not value or len(value) > maximum:
        raise TeamValidationError(
            document_name,
            path,
            f"expected a non-empty string no longer than {maximum} characters",
        )
    if not _NO_CONTROL_PATTERN.fullmatch(value):
        raise TeamValidationError(document_name, path, "control characters are not allowed")
    if pattern is not None and not pattern.fullmatch(value):
        raise TeamValidationError(document_name, path, "value has an invalid format")
    return value


def _integer(
    value: Any,
    path: str,
    document_name: str,
    *,
    minimum: int,
    maximum: int | None = None,
) -> int:
    if isinstance(value, bool) or not isinstance(value, int):
        raise TeamValidationError(document_name, path, "expected an integer")
    if value < minimum or (maximum is not None and value > maximum):
        upper = "" if maximum is None else f" and at most {maximum}"
        raise TeamValidationError(
            document_name,
            path,
            f"expected an integer of at least {minimum}{upper}",
        )
    return value


def _boolean(value: Any, path: str, document_name: str) -> bool:
    if not isinstance(value, bool):
        raise TeamValidationError(document_name, path, "expected a boolean")
    return value


def _enum(
    value: Any,
    path: str,
    document_name: str,
    enum_type: type[_EnumT],
) -> _EnumT:
    if not isinstance(value, str):
        raise TeamValidationError(document_name, path, "expected a string enum value")
    try:
        return enum_type(value)
    except ValueError as exc:
        allowed = ", ".join(member.value for member in enum_type)
        raise TeamValidationError(
            document_name,
            path,
            f"expected one of: {allowed}",
        ) from exc


def _timestamp(value: Any, path: str, document_name: str) -> str:
    result = _string(value, path, document_name, maximum=20)
    if not _UTC_TIMESTAMP_PATTERN.fullmatch(result):
        raise TeamValidationError(
            document_name,
            path,
            "expected a UTC timestamp in YYYY-MM-DDTHH:MM:SSZ form",
        )
    try:
        parsed = datetime.fromisoformat(result.replace("Z", "+00:00"))
    except ValueError as exc:
        raise TeamValidationError(
            document_name,
            path,
            "expected a real UTC timestamp in YYYY-MM-DDTHH:MM:SSZ form",
        ) from exc
    if parsed.tzinfo is None or parsed.utcoffset() != timedelta(0):
        raise TeamValidationError(document_name, path, "expected a UTC timestamp")
    return result


def _timestamp_value(value: str) -> datetime:
    return datetime.fromisoformat(value.replace("Z", "+00:00"))


def _parse_bytes_document(
    raw_bytes: bytes,
    *,
    maximum: int,
    document_name: str,
) -> Any:
    if not 1 <= len(raw_bytes) <= maximum:
        raise TeamValidationError(
            document_name,
            "$",
            f"expected from 1 to {maximum} bytes",
        )
    try:
        text = raw_bytes.decode("utf-8")
    except UnicodeDecodeError as exc:
        raise TeamValidationError(document_name, "$", "expected UTF-8 JSON") from exc
    try:
        return parse_json_text(
            text,
            source=document_name,
            max_bytes=maximum,
        )
    except InputDocumentError as exc:
        raise TeamValidationError(document_name, "$", str(exc)) from exc


def _sha256(raw_bytes: bytes) -> str:
    return hashlib.sha256(raw_bytes).hexdigest()


def _canonical_bytes(value: Any) -> bytes:
    return json.dumps(
        to_jsonable(value),
        ensure_ascii=False,
        sort_keys=True,
        separators=(",", ":"),
    ).encode("utf-8")


def _render(value: Any) -> str:
    return json.dumps(to_jsonable(value), ensure_ascii=False, indent=2) + "\n"


def _parse_principal(value: Any, path: str, document_name: str) -> TeamPrincipal:
    obj = _object(
        value,
        path,
        document_name,
        required={"identity_provider", "subject_id"},
    )
    return TeamPrincipal(
        identity_provider=_string(
            obj["identity_provider"],
            f"{path}.identity_provider",
            document_name,
            maximum=128,
            pattern=_SAFE_ID_PATTERN,
        ),
        subject_id=_string(
            obj["subject_id"],
            f"{path}.subject_id",
            document_name,
            maximum=128,
            pattern=_SAFE_ID_PATTERN,
        ),
    )


def _parse_roles(
    value: Any,
    path: str,
    document_name: str,
    *,
    minimum: int,
) -> tuple[TeamRole, ...]:
    raw_roles = _array(
        value,
        path,
        document_name,
        minimum=minimum,
        maximum=len(TeamRole),
    )
    roles = tuple(
        _enum(item, f"{path}[{index}]", document_name, TeamRole)
        for index, item in enumerate(raw_roles)
    )
    if len(roles) != len(set(roles)):
        raise TeamValidationError(document_name, path, "roles must be unique")
    return tuple(sorted(roles, key=lambda role: role.value))


def _parse_policy_subject(
    value: Any,
    path: str,
    document_name: str,
) -> TeamPolicySubject:
    obj = _object(
        value,
        path,
        document_name,
        required={"media_type", "policy_id", "revision", "sha256", "byte_count"},
    )
    media_type = _string(
        obj["media_type"],
        f"{path}.media_type",
        document_name,
        maximum=255,
        pattern=_MEDIA_TYPE_PATTERN,
    )
    if media_type != _ACCESS_POLICY_MEDIA_TYPE:
        raise TeamValidationError(
            document_name,
            f"{path}.media_type",
            f"expected {_ACCESS_POLICY_MEDIA_TYPE}",
        )
    return TeamPolicySubject(
        media_type=media_type,
        policy_id=_string(
            obj["policy_id"],
            f"{path}.policy_id",
            document_name,
            pattern=_SAFE_ID_PATTERN,
        ),
        revision=_integer(
            obj["revision"],
            f"{path}.revision",
            document_name,
            minimum=1,
        ),
        sha256=_string(
            obj["sha256"],
            f"{path}.sha256",
            document_name,
            maximum=64,
            pattern=_SHA256_PATTERN,
        ),
        byte_count=_integer(
            obj["byte_count"],
            f"{path}.byte_count",
            document_name,
            minimum=1,
            maximum=MAX_TEAM_ACCESS_POLICY_BYTES,
        ),
    )


def _parse_resource(value: Any, path: str, document_name: str) -> TeamResource:
    obj = _object(
        value,
        path,
        document_name,
        required={"resource_type", "resource_id"},
    )
    resource = TeamResource(
        resource_type=_enum(
            obj["resource_type"],
            f"{path}.resource_type",
            document_name,
            TeamResourceType,
        ),
        resource_id=_string(
            obj["resource_id"],
            f"{path}.resource_id",
            document_name,
            pattern=_SAFE_ID_PATTERN,
        ),
    )
    return resource


def _validate_action_resource(
    action: TeamAction,
    resource: TeamResource,
    *,
    document_name: str,
    path: str,
) -> None:
    if resource.resource_type not in _ACTION_RESOURCES[action]:
        expected = ", ".join(sorted(item.value for item in _ACTION_RESOURCES[action]))
        raise TeamValidationError(
            document_name,
            path,
            f"{action.value} requires resource type: {expected}",
        )


def parse_team_access_policy(document: Any) -> TeamAccessPolicy:
    """Strictly parse a protected tenant access-policy snapshot."""

    name = "Team access policy"
    root = _object(
        document,
        "$",
        name,
        required={
            "schema_version",
            "tenant_id",
            "policy_id",
            "revision",
            "effective_at",
            "default_retention_class_id",
            "memberships",
            "retention_classes",
        },
    )
    if root["schema_version"] != TEAM_ACCESS_POLICY_SCHEMA_VERSION:
        raise TeamValidationError(
            name,
            "$.schema_version",
            f"expected {TEAM_ACCESS_POLICY_SCHEMA_VERSION}",
        )

    memberships_value = _array(
        root["memberships"],
        "$.memberships",
        name,
        minimum=0,
        maximum=MAX_TEAM_MEMBERSHIPS,
    )
    memberships: list[TeamMembership] = []
    membership_keys: set[tuple[str, str]] = set()
    for index, value in enumerate(memberships_value):
        path = f"$.memberships[{index}]"
        obj = _object(value, path, name, required={"principal", "roles"})
        principal = _parse_principal(obj["principal"], f"{path}.principal", name)
        principal_key = (principal.identity_provider, principal.subject_id)
        if principal_key in membership_keys:
            raise TeamValidationError(name, path, "principal membership must be unique")
        membership_keys.add(principal_key)
        memberships.append(
            TeamMembership(
                principal=principal,
                roles=_parse_roles(obj["roles"], f"{path}.roles", name, minimum=1),
            )
        )

    retention_values = _array(
        root["retention_classes"],
        "$.retention_classes",
        name,
        minimum=1,
        maximum=MAX_TEAM_RETENTION_CLASSES,
    )
    retention_classes: list[TeamRetentionClass] = []
    retention_ids: set[str] = set()
    for index, value in enumerate(retention_values):
        path = f"$.retention_classes[{index}]"
        obj = _object(value, path, name, required={"class_id", "minimum_days"})
        class_id = _string(
            obj["class_id"],
            f"{path}.class_id",
            name,
            pattern=_SAFE_ID_PATTERN,
        )
        if class_id in retention_ids:
            raise TeamValidationError(name, path, "retention class id must be unique")
        retention_ids.add(class_id)
        retention_classes.append(
            TeamRetentionClass(
                class_id=class_id,
                minimum_days=_integer(
                    obj["minimum_days"],
                    f"{path}.minimum_days",
                    name,
                    minimum=1,
                    maximum=MAX_TEAM_RETENTION_DAYS,
                ),
            )
        )

    default_retention_class_id = _string(
        root["default_retention_class_id"],
        "$.default_retention_class_id",
        name,
        pattern=_SAFE_ID_PATTERN,
    )
    if default_retention_class_id not in retention_ids:
        raise TeamValidationError(
            name,
            "$.default_retention_class_id",
            "must reference a declared retention class",
        )

    return TeamAccessPolicy(
        schema_version=TEAM_ACCESS_POLICY_SCHEMA_VERSION,
        tenant_id=_string(
            root["tenant_id"],
            "$.tenant_id",
            name,
            pattern=_SAFE_ID_PATTERN,
        ),
        policy_id=_string(
            root["policy_id"],
            "$.policy_id",
            name,
            pattern=_SAFE_ID_PATTERN,
        ),
        revision=_integer(root["revision"], "$.revision", name, minimum=1),
        effective_at=_timestamp(root["effective_at"], "$.effective_at", name),
        default_retention_class_id=default_retention_class_id,
        memberships=tuple(
            sorted(
                memberships,
                key=lambda membership: (
                    membership.principal.identity_provider,
                    membership.principal.subject_id,
                ),
            )
        ),
        retention_classes=tuple(
            sorted(retention_classes, key=lambda retention: retention.class_id)
        ),
    )


def parse_team_access_policy_bytes(raw_bytes: bytes) -> TeamAccessPolicy:
    """Parse exact bounded policy bytes while rejecting duplicate JSON keys."""

    return parse_team_access_policy(
        _parse_bytes_document(
            raw_bytes,
            maximum=MAX_TEAM_ACCESS_POLICY_BYTES,
            document_name="Team access policy",
        )
    )


def parse_team_authorization(document: Any) -> TeamAuthorizationDecision:
    """Strictly parse one tenant-scoped authorization decision."""

    name = "Team authorization decision"
    root = _object(
        document,
        "$",
        name,
        required={
            "schema_version",
            "decision_id",
            "tenant_id",
            "principal",
            "action",
            "resource",
            "authorized",
            "assigned_roles",
            "granting_roles",
            "reason",
            "decided_at",
            "policy",
        },
    )
    if root["schema_version"] != TEAM_AUTHORIZATION_SCHEMA_VERSION:
        raise TeamValidationError(
            name,
            "$.schema_version",
            f"expected {TEAM_AUTHORIZATION_SCHEMA_VERSION}",
        )
    action = _enum(root["action"], "$.action", name, TeamAction)
    resource = _parse_resource(root["resource"], "$.resource", name)
    _validate_action_resource(action, resource, document_name=name, path="$.resource.resource_type")
    authorized = _boolean(root["authorized"], "$.authorized", name)
    assigned_roles = _parse_roles(root["assigned_roles"], "$.assigned_roles", name, minimum=0)
    granting_roles = _parse_roles(root["granting_roles"], "$.granting_roles", name, minimum=0)
    if not set(granting_roles).issubset(assigned_roles):
        raise TeamValidationError(
            name,
            "$.granting_roles",
            "granting roles must be a subset of assigned roles",
        )
    reason = _enum(root["reason"], "$.reason", name, TeamAuthorizationReason)
    if authorized:
        if reason is not TeamAuthorizationReason.ROLE_GRANT or not granting_roles:
            raise TeamValidationError(
                name,
                "$.authorized",
                "an authorized decision requires role_grant and at least one granting role",
            )
    elif reason is TeamAuthorizationReason.ROLE_GRANT or granting_roles:
        raise TeamValidationError(
            name,
            "$.authorized",
            "a denied decision cannot contain a granting role",
        )

    return TeamAuthorizationDecision(
        schema_version=TEAM_AUTHORIZATION_SCHEMA_VERSION,
        decision_id=_string(
            root["decision_id"],
            "$.decision_id",
            name,
            pattern=_SAFE_ID_PATTERN,
        ),
        tenant_id=_string(
            root["tenant_id"],
            "$.tenant_id",
            name,
            pattern=_SAFE_ID_PATTERN,
        ),
        principal=_parse_principal(root["principal"], "$.principal", name),
        action=action,
        resource=resource,
        authorized=authorized,
        assigned_roles=assigned_roles,
        granting_roles=granting_roles,
        reason=reason,
        decided_at=_timestamp(root["decided_at"], "$.decided_at", name),
        policy=_parse_policy_subject(root["policy"], "$.policy", name),
    )


def parse_team_authorization_bytes(raw_bytes: bytes) -> TeamAuthorizationDecision:
    """Parse exact bounded authorization bytes while rejecting duplicate keys."""

    return parse_team_authorization(
        _parse_bytes_document(
            raw_bytes,
            maximum=MAX_TEAM_AUTHORIZATION_BYTES,
            document_name="Team authorization decision",
        )
    )


def _policy_subject(policy_bytes: bytes, policy: TeamAccessPolicy) -> TeamPolicySubject:
    return TeamPolicySubject(
        media_type=_ACCESS_POLICY_MEDIA_TYPE,
        policy_id=policy.policy_id,
        revision=policy.revision,
        sha256=_sha256(policy_bytes),
        byte_count=len(policy_bytes),
    )


def _membership_roles(
    policy: TeamAccessPolicy,
    principal: TeamPrincipal,
) -> tuple[TeamRole, ...]:
    for membership in policy.memberships:
        if membership.principal == principal:
            return membership.roles
    return ()


def _authorization_result(
    policy: TeamAccessPolicy,
    principal: TeamPrincipal,
    action: TeamAction,
) -> tuple[
    bool,
    tuple[TeamRole, ...],
    tuple[TeamRole, ...],
    TeamAuthorizationReason,
]:
    assigned_roles = _membership_roles(policy, principal)
    if not assigned_roles:
        return (
            False,
            (),
            (),
            TeamAuthorizationReason.PRINCIPAL_NOT_MEMBER,
        )
    granting_roles = tuple(role for role in assigned_roles if action in _ROLE_GRANTS[role])
    if granting_roles:
        return (
            True,
            assigned_roles,
            granting_roles,
            TeamAuthorizationReason.ROLE_GRANT,
        )
    return (
        False,
        assigned_roles,
        (),
        TeamAuthorizationReason.ROLE_NOT_GRANTED,
    )


def create_team_authorization(
    policy_bytes: bytes,
    *,
    decision_id: str,
    identity_provider: str,
    subject_id: str,
    action: TeamAction | str,
    resource_type: TeamResourceType | str,
    resource_id: str,
    decided_at: str | None = None,
) -> TeamAuthorizationDecision:
    """Create a reproducible authorization decision from exact protected policy bytes."""

    policy = parse_team_access_policy_bytes(policy_bytes)
    action_value = TeamAction(action)
    resource = TeamResource(
        resource_type=TeamResourceType(resource_type),
        resource_id=resource_id,
    )
    principal = TeamPrincipal(
        identity_provider=identity_provider,
        subject_id=subject_id,
    )
    instant = decided_at or utc_timestamp()
    probe = TeamAuthorizationDecision(
        schema_version=TEAM_AUTHORIZATION_SCHEMA_VERSION,
        decision_id=decision_id,
        tenant_id=policy.tenant_id,
        principal=principal,
        action=action_value,
        resource=resource,
        authorized=False,
        assigned_roles=(),
        granting_roles=(),
        reason=TeamAuthorizationReason.PRINCIPAL_NOT_MEMBER,
        decided_at=instant,
        policy=_policy_subject(policy_bytes, policy),
    )
    parsed_probe = parse_team_authorization(to_jsonable(probe))
    if _timestamp_value(parsed_probe.decided_at) < _timestamp_value(policy.effective_at):
        raise TeamAuthorizationError(
            "policy_not_effective",
            "the decision time precedes the policy effective time",
        )
    authorized, assigned, granting, reason = _authorization_result(
        policy,
        parsed_probe.principal,
        parsed_probe.action,
    )
    return parse_team_authorization(
        to_jsonable(
            TeamAuthorizationDecision(
                schema_version=parsed_probe.schema_version,
                decision_id=parsed_probe.decision_id,
                tenant_id=parsed_probe.tenant_id,
                principal=parsed_probe.principal,
                action=parsed_probe.action,
                resource=parsed_probe.resource,
                authorized=authorized,
                assigned_roles=assigned,
                granting_roles=granting,
                reason=reason,
                decided_at=parsed_probe.decided_at,
                policy=parsed_probe.policy,
            )
        )
    )


def verify_team_authorization(
    policy_bytes: bytes,
    decision: TeamAuthorizationDecision,
) -> TeamAuthorizationDecision:
    """Reproduce an authorization decision against its exact policy snapshot."""

    policy = parse_team_access_policy_bytes(policy_bytes)
    validated = parse_team_authorization(to_jsonable(decision))
    expected_subject = _policy_subject(policy_bytes, policy)
    if validated.policy != expected_subject:
        raise TeamAuthorizationError(
            "policy_subject_mismatch",
            "the decision does not bind the supplied access-policy bytes",
        )
    if validated.tenant_id != policy.tenant_id:
        raise TeamAuthorizationError(
            "tenant_mismatch",
            "the decision tenant does not match the access policy",
        )
    if _timestamp_value(validated.decided_at) < _timestamp_value(policy.effective_at):
        raise TeamAuthorizationError(
            "policy_not_effective",
            "the decision time precedes the policy effective time",
        )
    authorized, assigned, granting, reason = _authorization_result(
        policy,
        validated.principal,
        validated.action,
    )
    if (
        validated.authorized != authorized
        or validated.assigned_roles != assigned
        or validated.granting_roles != granting
        or validated.reason is not reason
    ):
        raise TeamAuthorizationError(
            "decision_mismatch",
            "the recorded decision cannot be reproduced from the bound policy",
        )
    return validated


def _parse_document_subject(
    value: Any,
    path: str,
    document_name: str,
    *,
    maximum_bytes: int = MAX_TEAM_AUDIT_PAYLOAD_BYTES,
) -> TeamDocumentSubject:
    obj = _object(
        value,
        path,
        document_name,
        required={"media_type", "sha256", "byte_count"},
    )
    return TeamDocumentSubject(
        media_type=_string(
            obj["media_type"],
            f"{path}.media_type",
            document_name,
            maximum=255,
            pattern=_MEDIA_TYPE_PATTERN,
        ),
        sha256=_string(
            obj["sha256"],
            f"{path}.sha256",
            document_name,
            maximum=64,
            pattern=_SHA256_PATTERN,
        ),
        byte_count=_integer(
            obj["byte_count"],
            f"{path}.byte_count",
            document_name,
            minimum=1,
            maximum=maximum_bytes,
        ),
    )


def _parse_retention(
    value: Any,
    path: str,
    document_name: str,
) -> TeamRetentionRequirement:
    obj = _object(
        value,
        path,
        document_name,
        required={"class_id", "retain_until"},
    )
    return TeamRetentionRequirement(
        class_id=_string(
            obj["class_id"],
            f"{path}.class_id",
            document_name,
            pattern=_SAFE_ID_PATTERN,
        ),
        retain_until=_timestamp(
            obj["retain_until"],
            f"{path}.retain_until",
            document_name,
        ),
    )


def _event_digest(entry: TeamAuditEntry) -> str:
    return _sha256(_canonical_bytes(entry))


def _parse_audit_event(value: Any, path: str, document_name: str) -> TeamAuditEvent:
    obj = _object(
        value,
        path,
        document_name,
        required={"schema_version", "entry", "event_sha256"},
    )
    if obj["schema_version"] != TEAM_AUDIT_EVENT_SCHEMA_VERSION:
        raise TeamValidationError(
            document_name,
            f"{path}.schema_version",
            f"expected {TEAM_AUDIT_EVENT_SCHEMA_VERSION}",
        )
    entry_path = f"{path}.entry"
    entry_obj = _object(
        obj["entry"],
        entry_path,
        document_name,
        required={
            "event_id",
            "tenant_id",
            "sequence",
            "occurred_at",
            "authorization",
            "outcome",
            "payload",
            "retention",
            "previous_event_sha256",
        },
    )
    sequence = _integer(
        entry_obj["sequence"],
        f"{entry_path}.sequence",
        document_name,
        minimum=1,
    )
    previous_raw = entry_obj["previous_event_sha256"]
    if previous_raw is None:
        previous_event_sha256 = None
    else:
        previous_event_sha256 = _string(
            previous_raw,
            f"{entry_path}.previous_event_sha256",
            document_name,
            maximum=64,
            pattern=_SHA256_PATTERN,
        )
    if sequence == 1 and previous_event_sha256 is not None:
        raise TeamValidationError(
            document_name,
            f"{entry_path}.previous_event_sha256",
            "the first event must use null",
        )
    if sequence > 1 and previous_event_sha256 is None:
        raise TeamValidationError(
            document_name,
            f"{entry_path}.previous_event_sha256",
            "a non-genesis event must reference its predecessor",
        )

    authorization = parse_team_authorization(entry_obj["authorization"])
    tenant_id = _string(
        entry_obj["tenant_id"],
        f"{entry_path}.tenant_id",
        document_name,
        pattern=_SAFE_ID_PATTERN,
    )
    if authorization.tenant_id != tenant_id:
        raise TeamValidationError(
            document_name,
            f"{entry_path}.authorization.tenant_id",
            "must match the event tenant",
        )
    outcome = _enum(
        entry_obj["outcome"],
        f"{entry_path}.outcome",
        document_name,
        TeamAuditOutcome,
    )
    if authorization.authorized and outcome is TeamAuditOutcome.DENIED:
        raise TeamValidationError(
            document_name,
            f"{entry_path}.outcome",
            "an authorized action must use succeeded or failed",
        )
    if not authorization.authorized and outcome is not TeamAuditOutcome.DENIED:
        raise TeamValidationError(
            document_name,
            f"{entry_path}.outcome",
            "an unauthorized action must use denied",
        )
    occurred_at = _timestamp(
        entry_obj["occurred_at"],
        f"{entry_path}.occurred_at",
        document_name,
    )
    authorization_age = _timestamp_value(occurred_at) - _timestamp_value(authorization.decided_at)
    if authorization_age < timedelta(0):
        raise TeamValidationError(
            document_name,
            f"{entry_path}.occurred_at",
            "must not precede the authorization decision",
        )
    if authorization_age > timedelta(seconds=MAX_TEAM_AUTHORIZATION_AGE_SECONDS):
        raise TeamValidationError(
            document_name,
            f"{entry_path}.occurred_at",
            "authorization decision is too old for this event",
        )
    retention = _parse_retention(
        entry_obj["retention"],
        f"{entry_path}.retention",
        document_name,
    )
    if _timestamp_value(retention.retain_until) <= _timestamp_value(occurred_at):
        raise TeamValidationError(
            document_name,
            f"{entry_path}.retention.retain_until",
            "must be later than the event time",
        )

    entry = TeamAuditEntry(
        event_id=_string(
            entry_obj["event_id"],
            f"{entry_path}.event_id",
            document_name,
            pattern=_SAFE_ID_PATTERN,
        ),
        tenant_id=tenant_id,
        sequence=sequence,
        occurred_at=occurred_at,
        authorization=authorization,
        outcome=outcome,
        payload=_parse_document_subject(
            entry_obj["payload"],
            f"{entry_path}.payload",
            document_name,
        ),
        retention=retention,
        previous_event_sha256=previous_event_sha256,
    )
    event_sha256 = _string(
        obj["event_sha256"],
        f"{path}.event_sha256",
        document_name,
        maximum=64,
        pattern=_SHA256_PATTERN,
    )
    if event_sha256 != _event_digest(entry):
        raise TeamValidationError(
            document_name,
            f"{path}.event_sha256",
            "does not match the canonical audit entry",
        )
    return TeamAuditEvent(
        schema_version=TEAM_AUDIT_EVENT_SCHEMA_VERSION,
        entry=entry,
        event_sha256=event_sha256,
    )


def parse_team_audit_event(document: Any) -> TeamAuditEvent:
    """Strictly parse and self-verify one audit event."""

    return _parse_audit_event(document, "$", "Team audit event")


def parse_team_audit_event_bytes(raw_bytes: bytes) -> TeamAuditEvent:
    """Parse exact bounded event bytes while rejecting duplicate JSON keys."""

    return parse_team_audit_event(
        _parse_bytes_document(
            raw_bytes,
            maximum=MAX_TEAM_AUDIT_EVENT_BYTES,
            document_name="Team audit event",
        )
    )


def _retention_class(
    policy: TeamAccessPolicy,
    class_id: str,
) -> TeamRetentionClass:
    for retention_class in policy.retention_classes:
        if retention_class.class_id == class_id:
            return retention_class
    raise TeamValidationError(
        "Team audit event",
        "$.entry.retention.class_id",
        "must reference a retention class in the bound access policy",
    )


def _validate_retention_floor(
    *,
    occurred_at: str,
    retain_until: str,
    retention_class: TeamRetentionClass,
    document_name: str,
    path: str,
) -> None:
    minimum = _timestamp_value(occurred_at) + timedelta(days=retention_class.minimum_days)
    if _timestamp_value(retain_until) < minimum:
        raise TeamValidationError(
            document_name,
            path,
            f"must retain for at least {retention_class.minimum_days} day(s)",
        )


def create_team_audit_event(
    policy_bytes: bytes,
    authorization_bytes: bytes,
    payload_bytes: bytes,
    *,
    payload_media_type: str,
    event_id: str,
    outcome: TeamAuditOutcome | str,
    occurred_at: str | None = None,
    retention_class_id: str | None = None,
    retain_until: str | None = None,
    previous_event_bytes: bytes | None = None,
) -> TeamAuditEvent:
    """Create the next tenant audit event after reproducing authorization."""

    if not 1 <= len(payload_bytes) <= MAX_TEAM_AUDIT_PAYLOAD_BYTES:
        raise TeamValidationError(
            "Team audit event",
            "$.entry.payload.byte_count",
            f"expected from 1 to {MAX_TEAM_AUDIT_PAYLOAD_BYTES} bytes",
        )
    policy = parse_team_access_policy_bytes(policy_bytes)
    authorization = verify_team_authorization(
        policy_bytes,
        parse_team_authorization_bytes(authorization_bytes),
    )
    event_time = occurred_at or utc_timestamp()
    outcome_value = TeamAuditOutcome(outcome)

    previous: TeamAuditEvent | None = None
    if previous_event_bytes is not None:
        previous = parse_team_audit_event_bytes(previous_event_bytes)
        if previous.entry.tenant_id != policy.tenant_id:
            raise TeamValidationError(
                "Team audit event",
                "$.entry.tenant_id",
                "predecessor belongs to a different tenant",
            )
        if _timestamp_value(event_time) < _timestamp_value(previous.entry.occurred_at):
            raise TeamValidationError(
                "Team audit event",
                "$.entry.occurred_at",
                "must not precede the previous event",
            )

    selected_class_id = retention_class_id or policy.default_retention_class_id
    selected_class = _retention_class(policy, selected_class_id)
    minimum_retain_until = utc_timestamp(
        _timestamp_value(event_time) + timedelta(days=selected_class.minimum_days)
    )
    retention_deadline = retain_until or minimum_retain_until
    entry = TeamAuditEntry(
        event_id=event_id,
        tenant_id=policy.tenant_id,
        sequence=1 if previous is None else previous.entry.sequence + 1,
        occurred_at=event_time,
        authorization=authorization,
        outcome=outcome_value,
        payload=TeamDocumentSubject(
            media_type=payload_media_type,
            sha256=_sha256(payload_bytes),
            byte_count=len(payload_bytes),
        ),
        retention=TeamRetentionRequirement(
            class_id=selected_class_id,
            retain_until=retention_deadline,
        ),
        previous_event_sha256=None if previous is None else previous.event_sha256,
    )
    event = parse_team_audit_event(
        to_jsonable(
            TeamAuditEvent(
                schema_version=TEAM_AUDIT_EVENT_SCHEMA_VERSION,
                entry=entry,
                event_sha256=_event_digest(entry),
            )
        )
    )
    _validate_retention_floor(
        occurred_at=event.entry.occurred_at,
        retain_until=event.entry.retention.retain_until,
        retention_class=selected_class,
        document_name="Team audit event",
        path="$.entry.retention.retain_until",
    )
    return event


def verify_team_audit_event(
    policy_bytes: bytes,
    event: TeamAuditEvent,
    *,
    previous_event: TeamAuditEvent | None = None,
) -> TeamAuditEvent:
    """Recheck one event's authorization, retention, tenant, and predecessor."""

    policy = parse_team_access_policy_bytes(policy_bytes)
    validated = parse_team_audit_event(to_jsonable(event))
    verify_team_authorization(policy_bytes, validated.entry.authorization)
    if validated.entry.tenant_id != policy.tenant_id:
        raise TeamAuthorizationError(
            "tenant_mismatch",
            "the event tenant does not match the access policy",
        )
    retention_class = _retention_class(policy, validated.entry.retention.class_id)
    _validate_retention_floor(
        occurred_at=validated.entry.occurred_at,
        retain_until=validated.entry.retention.retain_until,
        retention_class=retention_class,
        document_name="Team audit event",
        path="$.entry.retention.retain_until",
    )
    if previous_event is None:
        if validated.entry.sequence != 1 or validated.entry.previous_event_sha256 is not None:
            raise TeamValidationError(
                "Team audit event",
                "$.entry.sequence",
                "a missing predecessor is valid only for the genesis event",
            )
    else:
        previous = parse_team_audit_event(to_jsonable(previous_event))
        if previous.entry.tenant_id != validated.entry.tenant_id:
            raise TeamValidationError(
                "Team audit event",
                "$.entry.tenant_id",
                "predecessor belongs to a different tenant",
            )
        if validated.entry.sequence != previous.entry.sequence + 1:
            raise TeamValidationError(
                "Team audit event",
                "$.entry.sequence",
                "must immediately follow the predecessor sequence",
            )
        if validated.entry.previous_event_sha256 != previous.event_sha256:
            raise TeamValidationError(
                "Team audit event",
                "$.entry.previous_event_sha256",
                "does not match the predecessor event",
            )
        if _timestamp_value(validated.entry.occurred_at) < _timestamp_value(
            previous.entry.occurred_at
        ):
            raise TeamValidationError(
                "Team audit event",
                "$.entry.occurred_at",
                "must not precede the previous event",
            )
    return validated


def _validate_event_chain(
    events: tuple[TeamAuditEvent, ...],
    *,
    tenant_id: str | None = None,
) -> str:
    if not events:
        raise TeamValidationError("Team audit export", "$.events", "must not be empty")
    event_ids: set[str] = set()
    decision_ids: set[str] = set()
    previous: TeamAuditEvent | None = None
    resolved_tenant = tenant_id or events[0].entry.tenant_id
    for index, event in enumerate(events):
        validated = parse_team_audit_event(to_jsonable(event))
        if validated.entry.tenant_id != resolved_tenant:
            raise TeamValidationError(
                "Team audit export",
                f"$.events[{index}].entry.tenant_id",
                "all events must belong to the export tenant",
            )
        if validated.entry.event_id in event_ids:
            raise TeamValidationError(
                "Team audit export",
                f"$.events[{index}].entry.event_id",
                "event ids must be unique",
            )
        if validated.entry.authorization.decision_id in decision_ids:
            raise TeamValidationError(
                "Team audit export",
                f"$.events[{index}].entry.authorization.decision_id",
                "authorization decision ids must be unique",
            )
        event_ids.add(validated.entry.event_id)
        decision_ids.add(validated.entry.authorization.decision_id)
        if previous is None:
            if validated.entry.sequence != 1:
                raise TeamValidationError(
                    "Team audit export",
                    f"$.events[{index}].entry.sequence",
                    "a full export must begin at sequence 1",
                )
        else:
            if validated.entry.sequence != previous.entry.sequence + 1:
                raise TeamValidationError(
                    "Team audit export",
                    f"$.events[{index}].entry.sequence",
                    "event sequences must be contiguous",
                )
            if validated.entry.previous_event_sha256 != previous.event_sha256:
                raise TeamValidationError(
                    "Team audit export",
                    f"$.events[{index}].entry.previous_event_sha256",
                    "event chain does not match its predecessor",
                )
            if _timestamp_value(validated.entry.occurred_at) < _timestamp_value(
                previous.entry.occurred_at
            ):
                raise TeamValidationError(
                    "Team audit export",
                    f"$.events[{index}].entry.occurred_at",
                    "event times must be nondecreasing",
                )
        previous = validated
    return resolved_tenant


def _parse_audit_range(value: Any, path: str, document_name: str) -> TeamAuditRange:
    obj = _object(
        value,
        path,
        document_name,
        required={"first_sequence", "last_sequence", "event_count"},
    )
    return TeamAuditRange(
        first_sequence=_integer(
            obj["first_sequence"],
            f"{path}.first_sequence",
            document_name,
            minimum=1,
        ),
        last_sequence=_integer(
            obj["last_sequence"],
            f"{path}.last_sequence",
            document_name,
            minimum=1,
        ),
        event_count=_integer(
            obj["event_count"],
            f"{path}.event_count",
            document_name,
            minimum=1,
            maximum=MAX_TEAM_EXPORT_EVENTS,
        ),
    )


def parse_team_audit_export(document: Any) -> TeamAuditExport:
    """Strictly parse and verify a complete tenant audit export."""

    name = "Team audit export"
    root = _object(
        document,
        "$",
        name,
        required={
            "schema_version",
            "export_id",
            "tenant_id",
            "created_at",
            "authorization",
            "audit_range",
            "head_event_sha256",
            "retention",
            "events",
        },
    )
    if root["schema_version"] != TEAM_AUDIT_EXPORT_SCHEMA_VERSION:
        raise TeamValidationError(
            name,
            "$.schema_version",
            f"expected {TEAM_AUDIT_EXPORT_SCHEMA_VERSION}",
        )
    tenant_id = _string(
        root["tenant_id"],
        "$.tenant_id",
        name,
        pattern=_SAFE_ID_PATTERN,
    )
    events_values = _array(
        root["events"],
        "$.events",
        name,
        minimum=1,
        maximum=MAX_TEAM_EXPORT_EVENTS,
    )
    events = tuple(
        _parse_audit_event(value, f"$.events[{index}]", name)
        for index, value in enumerate(events_values)
    )
    _validate_event_chain(events, tenant_id=tenant_id)

    export_id = _string(
        root["export_id"],
        "$.export_id",
        name,
        pattern=_SAFE_ID_PATTERN,
    )
    authorization = parse_team_authorization(root["authorization"])
    if (
        not authorization.authorized
        or authorization.action is not TeamAction.AUDIT_EXPORT
        or authorization.resource.resource_type is not TeamResourceType.AUDIT_EXPORT
        or authorization.resource.resource_id != export_id
    ):
        raise TeamValidationError(
            name,
            "$.authorization",
            "must be an authorized audit_export decision for this export id",
        )
    if authorization.tenant_id != tenant_id:
        raise TeamValidationError(
            name,
            "$.authorization.tenant_id",
            "must match the export tenant",
        )

    created_at = _timestamp(root["created_at"], "$.created_at", name)
    last_event = events[-1]
    if _timestamp_value(authorization.decided_at) < _timestamp_value(last_event.entry.occurred_at):
        raise TeamValidationError(
            name,
            "$.authorization.decided_at",
            "must not precede the final exported event",
        )
    export_age = _timestamp_value(created_at) - _timestamp_value(authorization.decided_at)
    if export_age < timedelta(0):
        raise TeamValidationError(
            name,
            "$.created_at",
            "must not precede the export authorization",
        )
    if export_age > timedelta(seconds=MAX_TEAM_AUTHORIZATION_AGE_SECONDS):
        raise TeamValidationError(
            name,
            "$.created_at",
            "export authorization is too old",
        )

    audit_range = _parse_audit_range(root["audit_range"], "$.audit_range", name)
    expected_range = TeamAuditRange(
        first_sequence=events[0].entry.sequence,
        last_sequence=events[-1].entry.sequence,
        event_count=len(events),
    )
    if audit_range != expected_range:
        raise TeamValidationError(
            name,
            "$.audit_range",
            "does not match the exported event sequence",
        )
    head_event_sha256 = _string(
        root["head_event_sha256"],
        "$.head_event_sha256",
        name,
        maximum=64,
        pattern=_SHA256_PATTERN,
    )
    if head_event_sha256 != events[-1].event_sha256:
        raise TeamValidationError(
            name,
            "$.head_event_sha256",
            "does not match the final exported event",
        )
    retention = _parse_retention(root["retention"], "$.retention", name)
    event_retention_floor = max(
        _timestamp_value(event.entry.retention.retain_until) for event in events
    )
    if _timestamp_value(retention.retain_until) < event_retention_floor:
        raise TeamValidationError(
            name,
            "$.retention.retain_until",
            "must not expire before any contained event",
        )

    return TeamAuditExport(
        schema_version=TEAM_AUDIT_EXPORT_SCHEMA_VERSION,
        export_id=export_id,
        tenant_id=tenant_id,
        created_at=created_at,
        authorization=authorization,
        audit_range=audit_range,
        head_event_sha256=head_event_sha256,
        retention=retention,
        events=events,
    )


def parse_team_audit_export_bytes(raw_bytes: bytes) -> TeamAuditExport:
    """Parse exact bounded export bytes while rejecting duplicate JSON keys."""

    return parse_team_audit_export(
        _parse_bytes_document(
            raw_bytes,
            maximum=MAX_TEAM_AUDIT_EXPORT_BYTES,
            document_name="Team audit export",
        )
    )


def create_team_audit_export(
    policy_bytes: bytes,
    authorization_bytes: bytes,
    event_bytes: list[bytes] | tuple[bytes, ...],
    *,
    export_id: str,
    authoritative_head_sha256: str,
    created_at: str | None = None,
) -> TeamAuditExport:
    """Create a complete, policy-authorized tenant audit export."""

    if not 1 <= len(event_bytes) <= MAX_TEAM_EXPORT_EVENTS:
        raise TeamValidationError(
            "Team audit export",
            "$.events",
            f"expected from 1 to {MAX_TEAM_EXPORT_EVENTS} event(s)",
        )
    policy = parse_team_access_policy_bytes(policy_bytes)
    authorization = verify_team_authorization(
        policy_bytes,
        parse_team_authorization_bytes(authorization_bytes),
    )
    events = tuple(parse_team_audit_event_bytes(raw_bytes) for raw_bytes in event_bytes)
    _validate_event_chain(events, tenant_id=policy.tenant_id)
    expected_head = _string(
        authoritative_head_sha256,
        "$.head_event_sha256",
        "Team audit export",
        maximum=64,
        pattern=_SHA256_PATTERN,
    )
    if events[-1].event_sha256 != expected_head:
        raise TeamValidationError(
            "Team audit export",
            "$.head_event_sha256",
            "event list does not end at the authoritative tenant head",
        )
    creation_time = created_at or utc_timestamp()
    default_retention = _retention_class(policy, policy.default_retention_class_id)
    policy_floor = _timestamp_value(creation_time) + timedelta(days=default_retention.minimum_days)
    event_floor = max(_timestamp_value(event.entry.retention.retain_until) for event in events)
    retention_deadline = utc_timestamp(max(policy_floor, event_floor))
    export = TeamAuditExport(
        schema_version=TEAM_AUDIT_EXPORT_SCHEMA_VERSION,
        export_id=export_id,
        tenant_id=policy.tenant_id,
        created_at=creation_time,
        authorization=authorization,
        audit_range=TeamAuditRange(
            first_sequence=events[0].entry.sequence,
            last_sequence=events[-1].entry.sequence,
            event_count=len(events),
        ),
        head_event_sha256=expected_head,
        retention=TeamRetentionRequirement(
            class_id=default_retention.class_id,
            retain_until=retention_deadline,
        ),
        events=events,
    )
    validated = parse_team_audit_export(to_jsonable(export))
    if len(_render(validated).encode("utf-8")) > MAX_TEAM_AUDIT_EXPORT_BYTES:
        raise TeamValidationError(
            "Team audit export",
            "$",
            f"rendered export exceeds {MAX_TEAM_AUDIT_EXPORT_BYTES} bytes",
        )
    return validated


def verify_team_audit_export(
    export_bytes: bytes,
    policy_bytes: bytes,
    *,
    checked_at: str | None = None,
    clock_skew_seconds: int = DEFAULT_TEAM_CLOCK_SKEW_SECONDS,
) -> TeamAuditVerification:
    """Verify exact export bytes, its full chain, and its export authorization."""

    if (
        isinstance(clock_skew_seconds, bool)
        or not isinstance(clock_skew_seconds, int)
        or not 0 <= clock_skew_seconds <= 3_600
    ):
        raise ValueError("clock_skew_seconds must be an integer from 0 to 3600")
    try:
        export = parse_team_audit_export_bytes(export_bytes)
    except TeamValidationError as exc:
        raise TeamAuditVerificationError("export_invalid", str(exc)) from exc
    try:
        authorization = verify_team_authorization(policy_bytes, export.authorization)
        policy = parse_team_access_policy_bytes(policy_bytes)
    except (TeamAuthorizationError, TeamValidationError) as exc:
        raise TeamAuditVerificationError("authorization_invalid", str(exc)) from exc
    if policy.tenant_id != export.tenant_id:
        raise TeamAuditVerificationError(
            "tenant_mismatch",
            "the export tenant does not match the supplied access policy",
        )
    retention_class = _retention_class(policy, export.retention.class_id)
    try:
        _validate_retention_floor(
            occurred_at=export.created_at,
            retain_until=export.retention.retain_until,
            retention_class=retention_class,
            document_name="Team audit export",
            path="$.retention.retain_until",
        )
    except TeamValidationError as exc:
        raise TeamAuditVerificationError("retention_invalid", str(exc)) from exc

    check_time = checked_at or utc_timestamp()
    try:
        canonical_check_time = _timestamp(
            check_time,
            "$.checked_at",
            "Team audit verification",
        )
    except TeamValidationError as exc:
        raise TeamAuditVerificationError("time_invalid", str(exc)) from exc
    if _timestamp_value(export.created_at) > _timestamp_value(canonical_check_time) + timedelta(
        seconds=clock_skew_seconds
    ):
        raise TeamAuditVerificationError(
            "export_from_future",
            "the export creation time is beyond the allowed clock skew",
        )

    return TeamAuditVerification(
        schema_version=TEAM_AUDIT_VERIFICATION_SCHEMA_VERSION,
        verifier_version=PACKAGE_VERSION,
        status="verified",
        checked_at=canonical_check_time,
        export=TeamDocumentSubject(
            media_type=_AUDIT_EXPORT_MEDIA_TYPE,
            sha256=_sha256(export_bytes),
            byte_count=len(export_bytes),
        ),
        export_id=export.export_id,
        tenant_id=export.tenant_id,
        audit_range=export.audit_range,
        head_event_sha256=export.head_event_sha256,
        retention=export.retention,
        exporter=authorization.principal,
        policy=authorization.policy,
    )


def parse_team_audit_verification(document: Any) -> TeamAuditVerification:
    """Strictly parse a successful audit-verification receipt."""

    name = "Team audit verification"
    root = _object(
        document,
        "$",
        name,
        required={
            "schema_version",
            "verifier_version",
            "status",
            "checked_at",
            "export",
            "export_id",
            "tenant_id",
            "audit_range",
            "head_event_sha256",
            "retention",
            "exporter",
            "policy",
        },
    )
    if root["schema_version"] != TEAM_AUDIT_VERIFICATION_SCHEMA_VERSION:
        raise TeamValidationError(
            name,
            "$.schema_version",
            f"expected {TEAM_AUDIT_VERIFICATION_SCHEMA_VERSION}",
        )
    status = _string(root["status"], "$.status", name, maximum=16)
    if status != "verified":
        raise TeamValidationError(name, "$.status", "expected verified")
    export = _parse_document_subject(
        root["export"],
        "$.export",
        name,
        maximum_bytes=MAX_TEAM_AUDIT_EXPORT_BYTES,
    )
    if export.media_type != _AUDIT_EXPORT_MEDIA_TYPE:
        raise TeamValidationError(
            name,
            "$.export.media_type",
            f"expected {_AUDIT_EXPORT_MEDIA_TYPE}",
        )
    audit_range = _parse_audit_range(root["audit_range"], "$.audit_range", name)
    if audit_range.last_sequence - audit_range.first_sequence + 1 != audit_range.event_count:
        raise TeamValidationError(
            name,
            "$.audit_range",
            "sequence bounds do not match event_count",
        )
    return TeamAuditVerification(
        schema_version=TEAM_AUDIT_VERIFICATION_SCHEMA_VERSION,
        verifier_version=_string(
            root["verifier_version"],
            "$.verifier_version",
            name,
            maximum=64,
            pattern=_SAFE_ID_PATTERN,
        ),
        status=status,
        checked_at=_timestamp(root["checked_at"], "$.checked_at", name),
        export=export,
        export_id=_string(
            root["export_id"],
            "$.export_id",
            name,
            pattern=_SAFE_ID_PATTERN,
        ),
        tenant_id=_string(
            root["tenant_id"],
            "$.tenant_id",
            name,
            pattern=_SAFE_ID_PATTERN,
        ),
        audit_range=audit_range,
        head_event_sha256=_string(
            root["head_event_sha256"],
            "$.head_event_sha256",
            name,
            maximum=64,
            pattern=_SHA256_PATTERN,
        ),
        retention=_parse_retention(root["retention"], "$.retention", name),
        exporter=_parse_principal(root["exporter"], "$.exporter", name),
        policy=_parse_policy_subject(root["policy"], "$.policy", name),
    )


def render_team_access_policy(policy: TeamAccessPolicy) -> str:
    """Render a validated access policy as deterministic UTF-8 JSON text."""

    return _render(parse_team_access_policy(to_jsonable(policy)))


def render_team_authorization(decision: TeamAuthorizationDecision) -> str:
    """Render a validated authorization decision."""

    return _render(parse_team_authorization(to_jsonable(decision)))


def render_team_audit_event(event: TeamAuditEvent) -> str:
    """Render a validated, self-hashed audit event."""

    return _render(parse_team_audit_event(to_jsonable(event)))


def render_team_audit_export(export: TeamAuditExport) -> str:
    """Render a validated complete audit export."""

    return _render(parse_team_audit_export(to_jsonable(export)))


def render_team_audit_verification(verification: TeamAuditVerification) -> str:
    """Render a successful audit-verification receipt."""

    return _render(parse_team_audit_verification(to_jsonable(verification)))
