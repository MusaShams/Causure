"""Signed, expiring human approval and policy-exception records."""

from __future__ import annotations

import base64
import binascii
import hashlib
import json
import re
from dataclasses import dataclass, field, replace
from datetime import datetime, timedelta
from enum import Enum
from typing import Any, TypeVar

from causure.azure_devops import (
    MAX_AZURE_PUBLICATION_BYTES,
    MAX_AZURE_VERIFICATION_BYTES,
    AzureBuildContext,
    AzureReviewPublication,
    AzureReviewValidationError,
    AzureReviewVerification,
    AzureReviewVerificationError,
    PublicationSubject,
    ReviewBinding,
    TfvcAssociation,
    parse_azure_review_publication_bytes,
    parse_azure_review_verification_bytes,
    parse_review_result_bytes,
    parse_review_result_findings_bytes,
    verify_azure_review_publication,
)
from causure.constants import (
    APPROVAL_ASSERTION_SCHEMA_VERSION,
    APPROVAL_REVOCATION_LIST_SCHEMA_VERSION,
    APPROVAL_TRUST_STORE_SCHEMA_VERSION,
    APPROVAL_VERIFICATION_SCHEMA_VERSION,
    PACKAGE_VERSION,
    ApprovalAction,
    ApprovalAuthenticationMethod,
    ApprovalGateEffect,
    Consequence,
    Decision,
    RevocationMode,
    SignatureAlgorithm,
    SignatureCanonicalization,
)
from causure.io import InputDocumentError, parse_json_text
from causure.models import to_jsonable

MAX_APPROVAL_ASSERTION_BYTES = 1024 * 1024
MAX_APPROVAL_POLICY_BYTES = 1024 * 1024
DEFAULT_MAX_APPROVAL_REVOCATION_AGE_SECONDS = 24 * 60 * 60
MAX_APPROVAL_REVOCATION_AGE_SECONDS = 31 * 24 * 60 * 60
MAX_APPROVAL_LIFETIME_SECONDS = 24 * 60 * 60
MAX_VERIFICATION_TO_AUTHENTICATION_SECONDS = 24 * 60 * 60
MAX_AUTHENTICATION_TO_ISSUE_SECONDS = 15 * 60
DEFAULT_APPROVAL_CLOCK_SKEW_SECONDS = 5 * 60

_PUBLICATION_MEDIA_TYPE = "application/vnd.causure.azure-review-publication+json"
_AZURE_VERIFICATION_MEDIA_TYPE = "application/vnd.causure.azure-review-verification+json"
_APPROVAL_ASSERTION_MEDIA_TYPE = "application/vnd.causure.approval-assertion+json"
_SAFE_ID_PATTERN = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:+/-]{2,127}$")
_FINDING_CODE_PATTERN = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{2,127}$")
_SHA256_PATTERN = re.compile(r"^[a-f0-9]{64}$")
_UTC_TIMESTAMP_PATTERN = re.compile(
    r"^[0-9]{4}-(0[1-9]|1[0-2])-([0-2][0-9]|3[01])T"
    r"([01][0-9]|2[0-3]):[0-5][0-9]:[0-5][0-9]Z$"
)
_NO_CONTROL_PATTERN = re.compile(r"^[^\x00-\x1f\x7f]+$")
_EnumT = TypeVar("_EnumT", bound=Enum)


class ApprovalValidationError(ValueError):
    """Raised when an approval-side document violates its closed wire contract."""

    def __init__(self, document_name: str, path: str, message: str) -> None:
        self.document_name = document_name
        self.path = path
        self.message = message
        super().__init__(f"Invalid {document_name} at {path}: {message}")


class ApprovalKeyError(ValueError):
    """Raised when an Ed25519 approval-authority key is unavailable or invalid."""


class ApprovalVerificationError(ValueError):
    """Raised with a stable, non-sensitive approval-verification failure code."""

    def __init__(self, code: str, message: str) -> None:
        self.code = code
        self.message = message
        super().__init__(f"Approval verification failed [{code}]: {message}")


@dataclass(frozen=True, slots=True)
class ApprovalDocumentSubject:
    media_type: str
    sha256: str
    byte_count: int


@dataclass(frozen=True, slots=True)
class ApprovalSubject:
    publication: ApprovalDocumentSubject
    verification: ApprovalDocumentSubject


@dataclass(frozen=True, slots=True)
class ApprovalAuthority:
    authority_id: str
    key_id: str


@dataclass(frozen=True, slots=True)
class ApproverIdentity:
    identity_provider: str
    subject_id: str
    authentication_method: ApprovalAuthenticationMethod
    authentication_event_id: str
    authenticated_at: str


@dataclass(frozen=True, slots=True)
class PolicyException:
    finding_codes: tuple[str, ...]
    justification: str


@dataclass(frozen=True, slots=True)
class ApprovalSignature:
    algorithm: SignatureAlgorithm
    canonicalization: SignatureCanonicalization
    value: str


@dataclass(frozen=True, slots=True)
class ApprovalAssertion:
    schema_version: str
    assertion_id: str
    authority: ApprovalAuthority
    approver: ApproverIdentity
    action: ApprovalAction
    gate_effect: ApprovalGateEffect
    issued_at: str
    expires_at: str
    subject: ApprovalSubject
    revocation_list_id: str
    signature: ApprovalSignature
    exception: PolicyException | None = field(
        default=None,
        metadata={"omit_none": True},
    )


@dataclass(frozen=True, slots=True)
class TrustedApprovalKey:
    key_id: str
    authority_id: str
    algorithm: SignatureAlgorithm
    public_key_base64url: str
    valid_from: str
    valid_until: str
    allowed_actions: tuple[ApprovalAction, ...]


@dataclass(frozen=True, slots=True)
class ApprovalTrustStore:
    schema_version: str
    store_id: str
    revocation_list_id: str
    keys: tuple[TrustedApprovalKey, ...]


@dataclass(frozen=True, slots=True)
class ApprovalKeyRevocation:
    key_id: str
    revoked_at: str
    mode: RevocationMode
    reason: str


@dataclass(frozen=True, slots=True)
class ApprovalRevocationList:
    schema_version: str
    list_id: str
    updated_at: str
    revoked_keys: tuple[ApprovalKeyRevocation, ...]


@dataclass(frozen=True, slots=True)
class ApprovalVerification:
    schema_version: str
    verifier_version: str
    status: str
    checked_at: str
    assertion: ApprovalDocumentSubject
    authority: ApprovalAuthority
    approver: ApproverIdentity
    action: ApprovalAction
    gate_effect: ApprovalGateEffect
    issued_at: str
    expires_at: str
    subject: ApprovalSubject
    review: ReviewBinding
    tfvc: TfvcAssociation
    build_id: int
    trust_store_id: str
    revocation_list_id: str
    revocation_list_updated_at: str
    exception: PolicyException | None = field(
        default=None,
        metadata={"omit_none": True},
    )


def _object(
    value: Any,
    path: str,
    document_name: str,
    *,
    required: set[str],
    optional: set[str] | None = None,
) -> dict[str, Any]:
    if not isinstance(value, dict):
        raise ApprovalValidationError(document_name, path, "expected an object")
    allowed = required | (optional or set())
    unknown = sorted(set(value) - allowed)
    if unknown:
        raise ApprovalValidationError(
            document_name,
            path,
            f"unknown field: {unknown[0]}",
        )
    missing = sorted(required - set(value))
    if missing:
        raise ApprovalValidationError(
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
    minimum: int = 0,
    maximum: int,
) -> list[Any]:
    if not isinstance(value, list):
        raise ApprovalValidationError(document_name, path, "expected an array")
    if not minimum <= len(value) <= maximum:
        raise ApprovalValidationError(
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
    pattern: re.Pattern[str] | None = None,
    maximum: int = 512,
) -> str:
    if not isinstance(value, str) or not value:
        raise ApprovalValidationError(document_name, path, "expected a non-empty string")
    if len(value) > maximum:
        raise ApprovalValidationError(
            document_name,
            path,
            f"must not exceed {maximum} characters",
        )
    try:
        value.encode("utf-8")
    except UnicodeEncodeError as exc:
        raise ApprovalValidationError(
            document_name,
            path,
            "must contain valid Unicode scalar values",
        ) from exc
    if pattern is not None and not pattern.fullmatch(value):
        raise ApprovalValidationError(
            document_name,
            path,
            "value does not match the required format",
        )
    return value


def _enum(
    value: Any,
    path: str,
    document_name: str,
    enum_type: type[_EnumT],
) -> _EnumT:
    try:
        return enum_type(value)
    except (TypeError, ValueError) as exc:
        allowed = ", ".join(member.value for member in enum_type)
        raise ApprovalValidationError(
            document_name,
            path,
            f"expected one of: {allowed}",
        ) from exc


def _integer(
    value: Any,
    path: str,
    document_name: str,
    *,
    minimum: int = 0,
    maximum: int | None = None,
) -> int:
    if isinstance(value, bool) or not isinstance(value, int):
        raise ApprovalValidationError(document_name, path, "expected an integer")
    if value < minimum or (maximum is not None and value > maximum):
        upper = "" if maximum is None else f" and at most {maximum}"
        raise ApprovalValidationError(
            document_name,
            path,
            f"expected an integer of at least {minimum}{upper}",
        )
    return value


def _timestamp(value: Any, path: str, document_name: str) -> str:
    result = _string(
        value,
        path,
        document_name,
        pattern=_UTC_TIMESTAMP_PATTERN,
        maximum=20,
    )
    try:
        parsed = datetime.fromisoformat(result.replace("Z", "+00:00"))
    except ValueError as exc:
        raise ApprovalValidationError(
            document_name,
            path,
            "expected a real UTC timestamp in YYYY-MM-DDTHH:MM:SSZ form",
        ) from exc
    if parsed.tzinfo is None or parsed.utcoffset() != timedelta(0):
        raise ApprovalValidationError(document_name, path, "expected a UTC timestamp")
    return result


def _timestamp_value(value: str) -> datetime:
    return datetime.fromisoformat(value.replace("Z", "+00:00"))


def _base64url_encode(value: bytes) -> str:
    return base64.urlsafe_b64encode(value).decode("ascii").rstrip("=")


def _base64url(
    value: Any,
    path: str,
    document_name: str,
    *,
    expected_bytes: int,
) -> str:
    encoded = _string(value, path, document_name, maximum=512)
    try:
        decoded = base64.b64decode(
            encoded + ("=" * (-len(encoded) % 4)),
            altchars=b"-_",
            validate=True,
        )
    except (binascii.Error, ValueError) as exc:
        raise ApprovalValidationError(
            document_name,
            path,
            "expected canonical unpadded base64url",
        ) from exc
    if len(decoded) != expected_bytes or _base64url_encode(decoded) != encoded:
        raise ApprovalValidationError(
            document_name,
            path,
            f"expected canonical unpadded base64url for {expected_bytes} bytes",
        )
    return encoded


def _parse_document_subject(
    value: Any,
    path: str,
    document_name: str,
    *,
    media_type: str,
    maximum_bytes: int,
) -> ApprovalDocumentSubject:
    obj = _object(
        value,
        path,
        document_name,
        required={"media_type", "sha256", "byte_count"},
    )
    parsed_media_type = _string(
        obj["media_type"],
        f"{path}.media_type",
        document_name,
        maximum=255,
    )
    if parsed_media_type != media_type:
        raise ApprovalValidationError(
            document_name,
            f"{path}.media_type",
            f"expected {media_type!r}",
        )
    return ApprovalDocumentSubject(
        media_type=parsed_media_type,
        sha256=_string(
            obj["sha256"],
            f"{path}.sha256",
            document_name,
            pattern=_SHA256_PATTERN,
            maximum=64,
        ),
        byte_count=_integer(
            obj["byte_count"],
            f"{path}.byte_count",
            document_name,
            minimum=1,
            maximum=maximum_bytes,
        ),
    )


def _parse_subject(value: Any, path: str, document_name: str) -> ApprovalSubject:
    obj = _object(
        value,
        path,
        document_name,
        required={"publication", "verification"},
    )
    return ApprovalSubject(
        publication=_parse_document_subject(
            obj["publication"],
            f"{path}.publication",
            document_name,
            media_type=_PUBLICATION_MEDIA_TYPE,
            maximum_bytes=MAX_AZURE_PUBLICATION_BYTES,
        ),
        verification=_parse_document_subject(
            obj["verification"],
            f"{path}.verification",
            document_name,
            media_type=_AZURE_VERIFICATION_MEDIA_TYPE,
            maximum_bytes=MAX_AZURE_VERIFICATION_BYTES,
        ),
    )


def _parse_authority(value: Any, path: str, document_name: str) -> ApprovalAuthority:
    obj = _object(
        value,
        path,
        document_name,
        required={"authority_id", "key_id"},
    )
    return ApprovalAuthority(
        authority_id=_string(
            obj["authority_id"],
            f"{path}.authority_id",
            document_name,
            pattern=_SAFE_ID_PATTERN,
            maximum=128,
        ),
        key_id=_string(
            obj["key_id"],
            f"{path}.key_id",
            document_name,
            pattern=_SAFE_ID_PATTERN,
            maximum=128,
        ),
    )


def _parse_approver(value: Any, path: str, document_name: str) -> ApproverIdentity:
    obj = _object(
        value,
        path,
        document_name,
        required={
            "identity_provider",
            "subject_id",
            "authentication_method",
            "authentication_event_id",
            "authenticated_at",
        },
    )
    return ApproverIdentity(
        identity_provider=_string(
            obj["identity_provider"],
            f"{path}.identity_provider",
            document_name,
            pattern=_SAFE_ID_PATTERN,
            maximum=128,
        ),
        subject_id=_string(
            obj["subject_id"],
            f"{path}.subject_id",
            document_name,
            pattern=_SAFE_ID_PATTERN,
            maximum=128,
        ),
        authentication_method=_enum(
            obj["authentication_method"],
            f"{path}.authentication_method",
            document_name,
            ApprovalAuthenticationMethod,
        ),
        authentication_event_id=_string(
            obj["authentication_event_id"],
            f"{path}.authentication_event_id",
            document_name,
            pattern=_SAFE_ID_PATTERN,
            maximum=128,
        ),
        authenticated_at=_timestamp(
            obj["authenticated_at"],
            f"{path}.authenticated_at",
            document_name,
        ),
    )


def _parse_exception(value: Any, path: str, document_name: str) -> PolicyException:
    obj = _object(
        value,
        path,
        document_name,
        required={"finding_codes", "justification"},
    )
    finding_codes = tuple(
        _string(
            item,
            f"{path}.finding_codes[{index}]",
            document_name,
            pattern=_FINDING_CODE_PATTERN,
            maximum=128,
        )
        for index, item in enumerate(
            _array(
                obj["finding_codes"],
                f"{path}.finding_codes",
                document_name,
                minimum=1,
                maximum=64,
            )
        )
    )
    if tuple(sorted(finding_codes)) != finding_codes or len(set(finding_codes)) != len(
        finding_codes
    ):
        raise ApprovalValidationError(
            document_name,
            f"{path}.finding_codes",
            "must be unique and sorted",
        )
    return PolicyException(
        finding_codes=finding_codes,
        justification=_string(
            obj["justification"],
            f"{path}.justification",
            document_name,
            pattern=_NO_CONTROL_PATTERN,
            maximum=2048,
        ),
    )


def parse_approval_assertion(document: Any) -> ApprovalAssertion:
    """Strictly parse an untrusted signed approval assertion."""

    name = "approval assertion"
    root = _object(
        document,
        "$",
        name,
        required={
            "schema_version",
            "assertion_id",
            "authority",
            "approver",
            "action",
            "gate_effect",
            "issued_at",
            "expires_at",
            "subject",
            "revocation_list_id",
            "signature",
        },
        optional={"exception"},
    )
    if root["schema_version"] != APPROVAL_ASSERTION_SCHEMA_VERSION:
        raise ApprovalValidationError(
            name,
            "$.schema_version",
            f"expected {APPROVAL_ASSERTION_SCHEMA_VERSION}",
        )
    action = _enum(root["action"], "$.action", name, ApprovalAction)
    gate_effect = _enum(root["gate_effect"], "$.gate_effect", name, ApprovalGateEffect)
    if gate_effect is not ApprovalGateEffect.RECORD_ONLY:
        raise ApprovalValidationError(name, "$.gate_effect", "expected record_only")
    exception = (
        _parse_exception(root["exception"], "$.exception", name) if "exception" in root else None
    )
    if action is ApprovalAction.APPROVE and exception is not None:
        raise ApprovalValidationError(
            name,
            "$.exception",
            "must be absent for an approve action",
        )
    if action is ApprovalAction.EXCEPTION and exception is None:
        raise ApprovalValidationError(
            name,
            "$.exception",
            "is required for an exception action",
        )
    issued_at = _timestamp(root["issued_at"], "$.issued_at", name)
    expires_at = _timestamp(root["expires_at"], "$.expires_at", name)
    approver = _parse_approver(root["approver"], "$.approver", name)
    issued_time = _timestamp_value(issued_at)
    expires_time = _timestamp_value(expires_at)
    authenticated_time = _timestamp_value(approver.authenticated_at)
    if authenticated_time > issued_time:
        raise ApprovalValidationError(
            name,
            "$.approver.authenticated_at",
            "must be at or before issued_at",
        )
    if issued_time - authenticated_time > timedelta(seconds=MAX_AUTHENTICATION_TO_ISSUE_SECONDS):
        raise ApprovalValidationError(
            name,
            "$.issued_at",
            "must be within 15 minutes of approver authentication",
        )
    if expires_time <= issued_time:
        raise ApprovalValidationError(name, "$.expires_at", "must be later than issued_at")
    if expires_time - issued_time > timedelta(seconds=MAX_APPROVAL_LIFETIME_SECONDS):
        raise ApprovalValidationError(
            name,
            "$.expires_at",
            "approval lifetime must not exceed 24 hours",
        )
    signature_obj = _object(
        root["signature"],
        "$.signature",
        name,
        required={"algorithm", "canonicalization", "value"},
    )
    return ApprovalAssertion(
        schema_version=APPROVAL_ASSERTION_SCHEMA_VERSION,
        assertion_id=_string(
            root["assertion_id"],
            "$.assertion_id",
            name,
            pattern=_SAFE_ID_PATTERN,
            maximum=128,
        ),
        authority=_parse_authority(root["authority"], "$.authority", name),
        approver=approver,
        action=action,
        gate_effect=gate_effect,
        issued_at=issued_at,
        expires_at=expires_at,
        subject=_parse_subject(root["subject"], "$.subject", name),
        revocation_list_id=_string(
            root["revocation_list_id"],
            "$.revocation_list_id",
            name,
            pattern=_SAFE_ID_PATTERN,
            maximum=128,
        ),
        signature=ApprovalSignature(
            algorithm=_enum(
                signature_obj["algorithm"],
                "$.signature.algorithm",
                name,
                SignatureAlgorithm,
            ),
            canonicalization=_enum(
                signature_obj["canonicalization"],
                "$.signature.canonicalization",
                name,
                SignatureCanonicalization,
            ),
            value=_base64url(
                signature_obj["value"],
                "$.signature.value",
                name,
                expected_bytes=64,
            ),
        ),
        exception=exception,
    )


def parse_approval_trust_store(document: Any) -> ApprovalTrustStore:
    """Strictly parse protected approval-authority key and action bindings."""

    name = "approval trust store"
    root = _object(
        document,
        "$",
        name,
        required={"schema_version", "store_id", "revocation_list_id", "keys"},
    )
    if root["schema_version"] != APPROVAL_TRUST_STORE_SCHEMA_VERSION:
        raise ApprovalValidationError(
            name,
            "$.schema_version",
            f"expected {APPROVAL_TRUST_STORE_SCHEMA_VERSION}",
        )
    keys: list[TrustedApprovalKey] = []
    for index, item in enumerate(_array(root["keys"], "$.keys", name, minimum=1, maximum=1_000)):
        path = f"$.keys[{index}]"
        obj = _object(
            item,
            path,
            name,
            required={
                "key_id",
                "authority_id",
                "algorithm",
                "public_key_base64url",
                "valid_from",
                "valid_until",
                "allowed_actions",
            },
        )
        valid_from = _timestamp(obj["valid_from"], f"{path}.valid_from", name)
        valid_until = _timestamp(obj["valid_until"], f"{path}.valid_until", name)
        if _timestamp_value(valid_until) <= _timestamp_value(valid_from):
            raise ApprovalValidationError(
                name,
                f"{path}.valid_until",
                "must be later than valid_from",
            )
        allowed_actions = tuple(
            _enum(value, f"{path}.allowed_actions[{action_index}]", name, ApprovalAction)
            for action_index, value in enumerate(
                _array(
                    obj["allowed_actions"],
                    f"{path}.allowed_actions",
                    name,
                    minimum=1,
                    maximum=len(ApprovalAction),
                )
            )
        )
        if tuple(sorted(allowed_actions, key=lambda value: value.value)) != allowed_actions or len(
            set(allowed_actions)
        ) != len(allowed_actions):
            raise ApprovalValidationError(
                name,
                f"{path}.allowed_actions",
                "must be unique and sorted",
            )
        keys.append(
            TrustedApprovalKey(
                key_id=_string(
                    obj["key_id"],
                    f"{path}.key_id",
                    name,
                    pattern=_SAFE_ID_PATTERN,
                    maximum=128,
                ),
                authority_id=_string(
                    obj["authority_id"],
                    f"{path}.authority_id",
                    name,
                    pattern=_SAFE_ID_PATTERN,
                    maximum=128,
                ),
                algorithm=_enum(
                    obj["algorithm"],
                    f"{path}.algorithm",
                    name,
                    SignatureAlgorithm,
                ),
                public_key_base64url=_base64url(
                    obj["public_key_base64url"],
                    f"{path}.public_key_base64url",
                    name,
                    expected_bytes=32,
                ),
                valid_from=valid_from,
                valid_until=valid_until,
                allowed_actions=allowed_actions,
            )
        )
    key_ids = [key.key_id for key in keys]
    if len(set(key_ids)) != len(key_ids):
        raise ApprovalValidationError(name, "$.keys", "key IDs must be unique")
    return ApprovalTrustStore(
        schema_version=APPROVAL_TRUST_STORE_SCHEMA_VERSION,
        store_id=_string(
            root["store_id"],
            "$.store_id",
            name,
            pattern=_SAFE_ID_PATTERN,
            maximum=128,
        ),
        revocation_list_id=_string(
            root["revocation_list_id"],
            "$.revocation_list_id",
            name,
            pattern=_SAFE_ID_PATTERN,
            maximum=128,
        ),
        keys=tuple(keys),
    )


def parse_approval_revocation_list(document: Any) -> ApprovalRevocationList:
    """Strictly parse current approval-authority key revocations."""

    name = "approval revocation list"
    root = _object(
        document,
        "$",
        name,
        required={"schema_version", "list_id", "updated_at", "revoked_keys"},
    )
    if root["schema_version"] != APPROVAL_REVOCATION_LIST_SCHEMA_VERSION:
        raise ApprovalValidationError(
            name,
            "$.schema_version",
            f"expected {APPROVAL_REVOCATION_LIST_SCHEMA_VERSION}",
        )
    revoked_keys: list[ApprovalKeyRevocation] = []
    for index, item in enumerate(
        _array(root["revoked_keys"], "$.revoked_keys", name, maximum=10_000)
    ):
        path = f"$.revoked_keys[{index}]"
        obj = _object(
            item,
            path,
            name,
            required={"key_id", "revoked_at", "mode", "reason"},
        )
        revoked_keys.append(
            ApprovalKeyRevocation(
                key_id=_string(
                    obj["key_id"],
                    f"{path}.key_id",
                    name,
                    pattern=_SAFE_ID_PATTERN,
                    maximum=128,
                ),
                revoked_at=_timestamp(
                    obj["revoked_at"],
                    f"{path}.revoked_at",
                    name,
                ),
                mode=_enum(obj["mode"], f"{path}.mode", name, RevocationMode),
                reason=_string(
                    obj["reason"],
                    f"{path}.reason",
                    name,
                    pattern=_NO_CONTROL_PATTERN,
                    maximum=512,
                ),
            )
        )
    key_ids = [entry.key_id for entry in revoked_keys]
    if len(set(key_ids)) != len(key_ids):
        raise ApprovalValidationError(
            name,
            "$.revoked_keys",
            "key IDs must be unique",
        )
    return ApprovalRevocationList(
        schema_version=APPROVAL_REVOCATION_LIST_SCHEMA_VERSION,
        list_id=_string(
            root["list_id"],
            "$.list_id",
            name,
            pattern=_SAFE_ID_PATTERN,
            maximum=128,
        ),
        updated_at=_timestamp(root["updated_at"], "$.updated_at", name),
        revoked_keys=tuple(revoked_keys),
    )


def approval_payload_bytes(assertion: ApprovalAssertion) -> bytes:
    """Return the versioned canonical bytes covered by the authority signature."""

    document = to_jsonable(assertion)
    document["signature"] = {
        "algorithm": assertion.signature.algorithm.value,
        "canonicalization": assertion.signature.canonicalization.value,
    }
    return json.dumps(
        document,
        allow_nan=False,
        ensure_ascii=False,
        separators=(",", ":"),
        sort_keys=True,
    ).encode("utf-8")


def _cryptography_types() -> tuple[Any, Any, Any, Any]:
    try:
        from cryptography.exceptions import InvalidSignature, UnsupportedAlgorithm
        from cryptography.hazmat.primitives import serialization
        from cryptography.hazmat.primitives.asymmetric.ed25519 import (
            Ed25519PrivateKey,
            Ed25519PublicKey,
        )
    except ImportError as exc:
        raise ApprovalKeyError(
            'Ed25519 approval support requires: pip install "causure[approval]"'
        ) from exc
    return (
        InvalidSignature,
        UnsupportedAlgorithm,
        serialization,
        (
            Ed25519PrivateKey,
            Ed25519PublicKey,
        ),
    )


def _load_private_key(private_key_pem: bytes, password: bytes | None) -> Any:
    _, unsupported, serialization, key_types = _cryptography_types()
    private_type, _ = key_types
    try:
        private_key = serialization.load_pem_private_key(
            private_key_pem,
            password=password,
        )
    except (TypeError, ValueError, unsupported) as exc:
        raise ApprovalKeyError(
            "Ed25519 private key could not be loaded; check the key and password"
        ) from exc
    if not isinstance(private_key, private_type):
        raise ApprovalKeyError("private key must be an Ed25519 PEM key")
    return private_key


def _document_subject(
    raw_bytes: bytes,
    *,
    media_type: str,
    maximum_bytes: int,
    role: str,
) -> ApprovalDocumentSubject:
    if not isinstance(raw_bytes, bytes) or not raw_bytes:
        raise ApprovalValidationError(role, "$", "document must contain exact non-empty bytes")
    if len(raw_bytes) > maximum_bytes:
        raise ApprovalValidationError(
            role,
            "$",
            f"document exceeds the {maximum_bytes}-byte limit",
        )
    return ApprovalDocumentSubject(
        media_type=media_type,
        sha256=hashlib.sha256(raw_bytes).hexdigest(),
        byte_count=len(raw_bytes),
    )


def _assert_subject_matches(
    raw_bytes: bytes,
    expected: ApprovalDocumentSubject,
    *,
    role: str,
) -> None:
    if len(raw_bytes) != expected.byte_count:
        raise ApprovalVerificationError(
            f"{role}_size_mismatch",
            f"{role.replace('_', ' ')} byte count does not match the signed subject",
        )
    if hashlib.sha256(raw_bytes).hexdigest() != expected.sha256:
        raise ApprovalVerificationError(
            f"{role}_digest_mismatch",
            f"{role.replace('_', ' ')} SHA-256 does not match the signed subject",
        )


def _validate_receipt_chain(
    publication_bytes: bytes,
    verification_bytes: bytes,
    review_result_bytes: bytes,
) -> tuple[
    AzureReviewPublication,
    AzureReviewVerification,
    tuple[str, ...],
]:
    try:
        publication = parse_azure_review_publication_bytes(publication_bytes)
        verification = parse_azure_review_verification_bytes(verification_bytes)
        review = parse_review_result_bytes(review_result_bytes)
        findings = parse_review_result_findings_bytes(review_result_bytes)
    except AzureReviewValidationError as exc:
        raise ApprovalValidationError("approval subject", "$", str(exc)) from exc

    expected_publication = PublicationSubject(
        media_type=_PUBLICATION_MEDIA_TYPE,
        sha256=hashlib.sha256(publication_bytes).hexdigest(),
        byte_count=len(publication_bytes),
    )
    if verification.publication != expected_publication:
        raise ApprovalValidationError(
            "approval subject",
            "$.verification.publication",
            "does not bind the exact supplied publication bytes",
        )
    if verification.review != publication.review or review != publication.review:
        raise ApprovalValidationError(
            "approval subject",
            "$.verification.review",
            "review identity does not match the exact publication and result",
        )
    if verification.tfvc != publication.tfvc:
        raise ApprovalValidationError(
            "approval subject",
            "$.verification.tfvc",
            "TFVC target does not match the exact publication",
        )
    if verification.build_id != publication.build.build_id:
        raise ApprovalValidationError(
            "approval subject",
            "$.verification.build_id",
            "build ID does not match the exact publication",
        )
    if verification.artifacts != publication.artifacts:
        raise ApprovalValidationError(
            "approval subject",
            "$.verification.artifacts",
            "artifact bindings do not match the exact publication",
        )
    result_artifact = publication.artifacts.review_result
    if len(review_result_bytes) != result_artifact.byte_count:
        raise ApprovalValidationError(
            "approval subject",
            "$.result",
            "review-result byte count does not match the publication",
        )
    if hashlib.sha256(review_result_bytes).hexdigest() != result_artifact.sha256:
        raise ApprovalValidationError(
            "approval subject",
            "$.result",
            "review-result SHA-256 does not match the publication",
        )
    created = _timestamp_value(publication.created_at)
    verified = _timestamp_value(verification.verified_at)
    if verified < created:
        raise ApprovalValidationError(
            "approval subject",
            "$.verification.verified_at",
            "must be at or after publication creation",
        )
    age_seconds = int((verified - created).total_seconds())
    if age_seconds != verification.publication_age_seconds:
        raise ApprovalValidationError(
            "approval subject",
            "$.verification.publication_age_seconds",
            "does not match the publication and verification timestamps",
        )
    consequential_codes = tuple(
        sorted(finding.code for finding in findings if finding.consequence is not Consequence.NONE)
    )
    return publication, verification, consequential_codes


def _validate_action_scope(
    assertion: ApprovalAssertion,
    publication: AzureReviewPublication,
    verification: AzureReviewVerification,
    consequential_codes: tuple[str, ...],
) -> None:
    verified_time = _timestamp_value(verification.verified_at)
    authenticated_time = _timestamp_value(assertion.approver.authenticated_at)
    if authenticated_time < verified_time:
        raise ApprovalValidationError(
            "approval assertion",
            "$.approver.authenticated_at",
            "must be at or after the bound pre-approval verification",
        )
    if authenticated_time - verified_time > timedelta(
        seconds=MAX_VERIFICATION_TO_AUTHENTICATION_SECONDS
    ):
        raise ApprovalValidationError(
            "approval assertion",
            "$.approver.authenticated_at",
            "must be within 24 hours of the bound pre-approval verification",
        )
    if _timestamp_value(assertion.expires_at) - verified_time > timedelta(
        seconds=MAX_APPROVAL_LIFETIME_SECONDS
    ):
        raise ApprovalValidationError(
            "approval assertion",
            "$.expires_at",
            "must be within 24 hours of the bound pre-approval verification",
        )
    if assertion.action is ApprovalAction.APPROVE:
        if publication.review.decision is not Decision.APPROVE:
            raise ApprovalValidationError(
                "approval assertion",
                "$.action",
                "approve is valid only for an approve gate decision",
            )
        return
    if publication.review.decision is Decision.APPROVE:
        raise ApprovalValidationError(
            "approval assertion",
            "$.action",
            "exception is valid only for a non-approve gate decision",
        )
    if not consequential_codes:
        raise ApprovalValidationError(
            "approval assertion",
            "$.exception.finding_codes",
            "the non-approve result has no decision-affecting findings to except",
        )
    assert assertion.exception is not None
    if assertion.exception.finding_codes != consequential_codes:
        raise ApprovalValidationError(
            "approval assertion",
            "$.exception.finding_codes",
            "must exactly cover every decision-affecting finding",
        )


def create_approval_assertion(
    publication_bytes: bytes,
    verification_bytes: bytes,
    review_result_bytes: bytes,
    *,
    assertion_id: str,
    authority_id: str,
    key_id: str,
    approver_id: str,
    identity_provider: str,
    authentication_method: ApprovalAuthenticationMethod | str,
    authentication_event_id: str,
    authenticated_at: str,
    action: ApprovalAction | str,
    issued_at: str,
    expires_at: str,
    revocation_list_id: str,
    private_key_pem: bytes,
    finding_codes: tuple[str, ...] | list[str] = (),
    justification: str | None = None,
    private_key_password: bytes | None = None,
) -> ApprovalAssertion:
    """Issue an authority-signed record for exact pre-approval artifacts."""

    if not isinstance(private_key_pem, bytes) or not private_key_pem:
        raise ApprovalKeyError("private key must contain PEM bytes")
    publication, verification, consequential_codes = _validate_receipt_chain(
        publication_bytes,
        verification_bytes,
        review_result_bytes,
    )
    try:
        parsed_action = ApprovalAction(action)
    except (TypeError, ValueError) as exc:
        raise ApprovalValidationError(
            "approval assertion",
            "$.action",
            "expected approve or exception",
        ) from exc
    exception_document: dict[str, Any] | None = None
    if parsed_action is ApprovalAction.APPROVE:
        if finding_codes:
            raise ApprovalValidationError(
                "approval assertion",
                "$.exception.finding_codes",
                "must be absent for an approve action",
            )
        if justification is not None:
            raise ApprovalValidationError(
                "approval assertion",
                "$.exception.justification",
                "must be absent for an approve action",
            )
    else:
        exception_document = {
            "finding_codes": sorted(finding_codes),
            "justification": justification,
        }
    placeholder = _base64url_encode(bytes(64))
    document: dict[str, Any] = {
        "schema_version": APPROVAL_ASSERTION_SCHEMA_VERSION,
        "assertion_id": assertion_id,
        "authority": {
            "authority_id": authority_id,
            "key_id": key_id,
        },
        "approver": {
            "identity_provider": identity_provider,
            "subject_id": approver_id,
            "authentication_method": (
                authentication_method.value
                if isinstance(authentication_method, ApprovalAuthenticationMethod)
                else authentication_method
            ),
            "authentication_event_id": authentication_event_id,
            "authenticated_at": authenticated_at,
        },
        "action": parsed_action.value,
        "gate_effect": ApprovalGateEffect.RECORD_ONLY.value,
        "issued_at": issued_at,
        "expires_at": expires_at,
        "subject": {
            "publication": to_jsonable(
                _document_subject(
                    publication_bytes,
                    media_type=_PUBLICATION_MEDIA_TYPE,
                    maximum_bytes=MAX_AZURE_PUBLICATION_BYTES,
                    role="Azure review publication",
                )
            ),
            "verification": to_jsonable(
                _document_subject(
                    verification_bytes,
                    media_type=_AZURE_VERIFICATION_MEDIA_TYPE,
                    maximum_bytes=MAX_AZURE_VERIFICATION_BYTES,
                    role="Azure review verification",
                )
            ),
        },
        "revocation_list_id": revocation_list_id,
        "signature": {
            "algorithm": SignatureAlgorithm.ED25519.value,
            "canonicalization": SignatureCanonicalization.CAUSURE_JSON_V1.value,
            "value": placeholder,
        },
    }
    if exception_document is not None:
        document["exception"] = exception_document
    assertion = parse_approval_assertion(document)
    _validate_action_scope(
        assertion,
        publication,
        verification,
        consequential_codes,
    )
    private_key = _load_private_key(private_key_pem, private_key_password)
    signature = private_key.sign(approval_payload_bytes(assertion))
    return replace(
        assertion,
        signature=replace(assertion.signature, value=_base64url_encode(signature)),
    )


def verify_approval_assertion(
    assertion_bytes: bytes,
    publication_bytes: bytes,
    verification_bytes: bytes,
    review_result_bytes: bytes,
    review_report_bytes: bytes,
    trust_store: ApprovalTrustStore,
    revocations: ApprovalRevocationList,
    *,
    expected_tfvc: TfvcAssociation,
    expected_build: AzureBuildContext,
    checked_at: str,
    max_revocation_age_seconds: int = DEFAULT_MAX_APPROVAL_REVOCATION_AGE_SECONDS,
    clock_skew_seconds: int = DEFAULT_APPROVAL_CLOCK_SKEW_SECONDS,
) -> ApprovalVerification:
    """Verify authority, identity claim, exact Azure chain, scope, and freshness."""

    try:
        assertion_subject = _document_subject(
            assertion_bytes,
            media_type=_APPROVAL_ASSERTION_MEDIA_TYPE,
            maximum_bytes=MAX_APPROVAL_ASSERTION_BYTES,
            role="approval assertion",
        )
        assertion_text = assertion_bytes.decode("utf-8")
        assertion = parse_approval_assertion(
            parse_json_text(
                assertion_text,
                source="approval assertion",
                max_bytes=MAX_APPROVAL_ASSERTION_BYTES,
            )
        )
    except (
        InputDocumentError,
        UnicodeDecodeError,
        ApprovalValidationError,
    ) as exc:
        raise ApprovalVerificationError("assertion_invalid", str(exc)) from exc
    trust_store = parse_approval_trust_store(to_jsonable(trust_store))
    revocations = parse_approval_revocation_list(to_jsonable(revocations))
    if (
        isinstance(max_revocation_age_seconds, bool)
        or not isinstance(max_revocation_age_seconds, int)
        or not 0 <= max_revocation_age_seconds <= MAX_APPROVAL_REVOCATION_AGE_SECONDS
    ):
        raise ValueError(
            "max_revocation_age_seconds must be an integer from 0 to "
            f"{MAX_APPROVAL_REVOCATION_AGE_SECONDS}"
        )
    if (
        isinstance(clock_skew_seconds, bool)
        or not isinstance(clock_skew_seconds, int)
        or not 0 <= clock_skew_seconds <= 3_600
    ):
        raise ValueError("clock_skew_seconds must be an integer from 0 to 3600")
    checked = _timestamp(checked_at, "$.checked_at", "approval verification request")
    checked_time = _timestamp_value(checked)
    skew = timedelta(seconds=clock_skew_seconds)

    if trust_store.revocation_list_id != assertion.revocation_list_id:
        raise ApprovalVerificationError(
            "revocation_list_mismatch",
            "assertion does not name the trust store's revocation list",
        )
    if revocations.list_id != trust_store.revocation_list_id:
        raise ApprovalVerificationError(
            "revocation_list_mismatch",
            "supplied revocation list does not match the trust store",
        )
    trusted_key = next(
        (key for key in trust_store.keys if key.key_id == assertion.authority.key_id),
        None,
    )
    if trusted_key is None:
        raise ApprovalVerificationError(
            "untrusted_key",
            "approval-authority key is not present in the trust store",
        )
    if trusted_key.authority_id != assertion.authority.authority_id:
        raise ApprovalVerificationError(
            "authority_mismatch",
            "approval authority is not bound to the selected key",
        )
    if assertion.action not in trusted_key.allowed_actions:
        raise ApprovalVerificationError(
            "action_not_authorized",
            "trusted authority key is not authorized for this approval action",
        )
    if trusted_key.algorithm is not assertion.signature.algorithm:
        raise ApprovalVerificationError(
            "algorithm_mismatch",
            "assertion and trusted key algorithms do not match",
        )

    invalid_signature, _, _, key_types = _cryptography_types()
    _, public_type = key_types
    public_bytes = base64.urlsafe_b64decode(
        trusted_key.public_key_base64url + ("=" * (-len(trusted_key.public_key_base64url) % 4))
    )
    signature_bytes = base64.urlsafe_b64decode(
        assertion.signature.value + ("=" * (-len(assertion.signature.value) % 4))
    )
    try:
        public_key = public_type.from_public_bytes(public_bytes)
        public_key.verify(signature_bytes, approval_payload_bytes(assertion))
    except invalid_signature as exc:
        raise ApprovalVerificationError(
            "invalid_signature",
            "signature does not authenticate the approval assertion",
        ) from exc
    except ValueError as exc:
        raise ApprovalVerificationError(
            "invalid_public_key",
            "trusted Ed25519 public key could not be loaded",
        ) from exc

    issued_time = _timestamp_value(assertion.issued_at)
    expires_time = _timestamp_value(assertion.expires_at)
    key_start = _timestamp_value(trusted_key.valid_from)
    key_end = _timestamp_value(trusted_key.valid_until)
    if issued_time < key_start:
        raise ApprovalVerificationError(
            "key_not_yet_valid",
            "assertion was issued before the trusted key validity window",
        )
    if issued_time >= key_end or expires_time > key_end:
        raise ApprovalVerificationError(
            "key_validity_exceeded",
            "assertion validity is not contained by the key validity window",
        )
    if issued_time > checked_time + skew:
        raise ApprovalVerificationError(
            "issued_in_future",
            "assertion issue time exceeds the allowed clock skew",
        )
    if checked_time >= expires_time:
        raise ApprovalVerificationError(
            "approval_expired",
            "approval assertion validity window has ended",
        )

    revocation_updated = _timestamp_value(revocations.updated_at)
    if revocation_updated > checked_time + skew:
        raise ApprovalVerificationError(
            "revocation_list_from_future",
            "revocation list timestamp exceeds the allowed clock skew",
        )
    if checked_time - revocation_updated > (timedelta(seconds=max_revocation_age_seconds) + skew):
        raise ApprovalVerificationError(
            "revocation_list_stale",
            "revocation list is older than the allowed freshness window",
        )
    revocation = next(
        (entry for entry in revocations.revoked_keys if entry.key_id == trusted_key.key_id),
        None,
    )
    if revocation is not None:
        revoked_time = _timestamp_value(revocation.revoked_at)
        if revocation.mode is RevocationMode.ALL_SIGNATURES or issued_time >= revoked_time:
            raise ApprovalVerificationError(
                "key_revoked",
                "approval-authority key is revoked for this assertion",
            )

    _assert_subject_matches(
        publication_bytes,
        assertion.subject.publication,
        role="publication",
    )
    _assert_subject_matches(
        verification_bytes,
        assertion.subject.verification,
        role="verification",
    )
    try:
        publication, verification, consequential_codes = _validate_receipt_chain(
            publication_bytes,
            verification_bytes,
            review_result_bytes,
        )
        expected_verification = verify_azure_review_publication(
            publication_bytes,
            review_result_bytes,
            review_report_bytes,
            expected_tfvc=expected_tfvc,
            expected_build=expected_build,
            verified_at=verification.verified_at,
            maximum_age_seconds=verification.maximum_age_seconds,
        )
        if expected_verification != verification:
            raise ApprovalVerificationError(
                "verification_receipt_mismatch",
                "supplied Azure verification is not the deterministic receipt for the artifacts",
            )
        _validate_action_scope(
            assertion,
            publication,
            verification,
            consequential_codes,
        )
    except ApprovalVerificationError:
        raise
    except (ApprovalValidationError, AzureReviewVerificationError) as exc:
        raise ApprovalVerificationError(
            "approval_chain_invalid",
            "the signed Azure publication, receipt, or artifacts do not form a valid chain",
        ) from exc

    return ApprovalVerification(
        schema_version=APPROVAL_VERIFICATION_SCHEMA_VERSION,
        verifier_version=PACKAGE_VERSION,
        status="verified",
        checked_at=checked,
        assertion=assertion_subject,
        authority=assertion.authority,
        approver=assertion.approver,
        action=assertion.action,
        gate_effect=assertion.gate_effect,
        issued_at=assertion.issued_at,
        expires_at=assertion.expires_at,
        subject=assertion.subject,
        review=publication.review,
        tfvc=publication.tfvc,
        build_id=publication.build.build_id,
        trust_store_id=trust_store.store_id,
        revocation_list_id=revocations.list_id,
        revocation_list_updated_at=revocations.updated_at,
        exception=assertion.exception,
    )


def render_approval_assertion(assertion: ApprovalAssertion) -> str:
    """Render a stable signed approval assertion."""

    validated = parse_approval_assertion(to_jsonable(assertion))
    return (
        json.dumps(
            to_jsonable(validated),
            allow_nan=False,
            ensure_ascii=False,
            indent=2,
            sort_keys=True,
        )
        + "\n"
    )


def render_approval_verification(verification: ApprovalVerification) -> str:
    """Render a stable successful approval-verification receipt."""

    return (
        json.dumps(
            to_jsonable(verification),
            allow_nan=False,
            ensure_ascii=False,
            indent=2,
            sort_keys=True,
        )
        + "\n"
    )
