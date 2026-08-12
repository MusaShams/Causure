"""Detached producer attestations for exact evidence artifact bytes."""

from __future__ import annotations

import base64
import binascii
import hashlib
import json
import re
from dataclasses import dataclass, replace
from datetime import UTC, datetime, timedelta
from enum import Enum
from typing import Any, TypeVar

from causure.constants import (
    ARTIFACT_ATTESTATION_SCHEMA_VERSION,
    ATTESTATION_REVOCATION_LIST_SCHEMA_VERSION,
    ATTESTATION_TRUST_STORE_SCHEMA_VERSION,
    ATTESTATION_VERIFICATION_SCHEMA_VERSION,
    PACKAGE_VERSION,
    RevocationMode,
    SignatureAlgorithm,
    SignatureCanonicalization,
)
from causure.models import to_jsonable

MAX_ATTESTED_ARTIFACT_BYTES = 64 * 1024 * 1024
MAX_KEY_DOCUMENT_BYTES = 64 * 1024
DEFAULT_MAX_REVOCATION_AGE_SECONDS = 24 * 60 * 60
MAX_REVOCATION_AGE_SECONDS = 31 * 24 * 60 * 60
DEFAULT_CLOCK_SKEW_SECONDS = 5 * 60

_SAFE_ID_PATTERN = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:+/-]{2,127}$")
_MEDIA_TYPE_PATTERN = re.compile(
    r"^[a-z0-9][a-z0-9!#$&^_.+-]{0,126}/[a-z0-9][a-z0-9!#$&^_.+-]{0,126}$"
)
_SHA256_PATTERN = re.compile(r"^[a-f0-9]{64}$")
_UTC_TIMESTAMP_PATTERN = re.compile(
    r"^[0-9]{4}-(0[1-9]|1[0-2])-([0-2][0-9]|3[01])T"
    r"([01][0-9]|2[0-3]):[0-5][0-9]:[0-5][0-9]Z$"
)
_EnumT = TypeVar("_EnumT", bound=Enum)


class AttestationValidationError(ValueError):
    """Raised when an attestation-side document violates its wire contract."""

    def __init__(self, document_name: str, path: str, message: str) -> None:
        self.document_name = document_name
        self.path = path
        self.message = message
        super().__init__(f"Invalid {document_name} at {path}: {message}")


class AttestationKeyError(ValueError):
    """Raised when Ed25519 key material is unavailable or invalid."""


class AttestationVerificationError(ValueError):
    """Raised with a stable, non-sensitive verification failure code."""

    def __init__(self, code: str, message: str) -> None:
        self.code = code
        self.message = message
        super().__init__(f"Attestation verification failed [{code}]: {message}")


@dataclass(frozen=True, slots=True)
class ArtifactSubject:
    artifact_id: str
    media_type: str
    sha256: str
    byte_count: int


@dataclass(frozen=True, slots=True)
class ProducerIdentity:
    producer_id: str
    key_id: str


@dataclass(frozen=True, slots=True)
class RetentionRequirement:
    class_id: str
    retain_until: str


@dataclass(frozen=True, slots=True)
class ArtifactSignature:
    algorithm: SignatureAlgorithm
    canonicalization: SignatureCanonicalization
    value: str


@dataclass(frozen=True, slots=True)
class ArtifactAttestation:
    schema_version: str
    artifact: ArtifactSubject
    producer: ProducerIdentity
    issued_at: str
    expires_at: str
    retention: RetentionRequirement
    revocation_list_id: str
    signature: ArtifactSignature


@dataclass(frozen=True, slots=True)
class TrustedProducerKey:
    key_id: str
    producer_id: str
    algorithm: SignatureAlgorithm
    public_key_base64url: str
    valid_from: str
    valid_until: str


@dataclass(frozen=True, slots=True)
class AttestationTrustStore:
    schema_version: str
    store_id: str
    revocation_list_id: str
    keys: tuple[TrustedProducerKey, ...]


@dataclass(frozen=True, slots=True)
class KeyRevocation:
    key_id: str
    revoked_at: str
    mode: RevocationMode
    reason: str


@dataclass(frozen=True, slots=True)
class AttestationRevocationList:
    schema_version: str
    list_id: str
    updated_at: str
    revoked_keys: tuple[KeyRevocation, ...]


@dataclass(frozen=True, slots=True)
class AttestationVerification:
    schema_version: str
    verifier_version: str
    status: str
    artifact: ArtifactSubject
    producer: ProducerIdentity
    issued_at: str
    expires_at: str
    retention: RetentionRequirement
    signature_algorithm: SignatureAlgorithm
    canonicalization: SignatureCanonicalization
    trust_store_id: str
    revocation_list_id: str
    revocation_list_updated_at: str
    checked_at: str


def _object(
    value: Any,
    path: str,
    document_name: str,
    *,
    required: set[str],
    optional: set[str] | None = None,
) -> dict[str, Any]:
    if not isinstance(value, dict):
        raise AttestationValidationError(document_name, path, "expected an object")
    allowed = required | (optional or set())
    unknown = sorted(set(value) - allowed)
    if unknown:
        raise AttestationValidationError(
            document_name,
            path,
            f"unknown field: {unknown[0]}",
        )
    missing = sorted(required - set(value))
    if missing:
        raise AttestationValidationError(
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
        raise AttestationValidationError(document_name, path, "expected an array")
    if not minimum <= len(value) <= maximum:
        raise AttestationValidationError(
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
        raise AttestationValidationError(document_name, path, "expected a non-empty string")
    if len(value) > maximum:
        raise AttestationValidationError(
            document_name,
            path,
            f"must not exceed {maximum} characters",
        )
    try:
        value.encode("utf-8")
    except UnicodeEncodeError as exc:
        raise AttestationValidationError(
            document_name,
            path,
            "must contain valid Unicode scalar values",
        ) from exc
    if pattern is not None and not pattern.fullmatch(value):
        raise AttestationValidationError(
            document_name,
            path,
            "value does not match the required format",
        )
    return value


def _integer(
    value: Any,
    path: str,
    document_name: str,
    *,
    minimum: int = 0,
) -> int:
    if isinstance(value, bool) or not isinstance(value, int):
        raise AttestationValidationError(document_name, path, "expected an integer")
    if value < minimum:
        raise AttestationValidationError(
            document_name,
            path,
            f"expected an integer of at least {minimum}",
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
        raise AttestationValidationError(
            document_name,
            path,
            f"expected one of: {allowed}",
        ) from exc


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
        raise AttestationValidationError(
            document_name,
            path,
            "expected a real UTC timestamp in YYYY-MM-DDTHH:MM:SSZ form",
        ) from exc
    if parsed.tzinfo is None or parsed.utcoffset() != timedelta(0):
        raise AttestationValidationError(document_name, path, "expected a UTC timestamp")
    return result


def _timestamp_value(value: str) -> datetime:
    return datetime.fromisoformat(value.replace("Z", "+00:00"))


def utc_timestamp(value: datetime | None = None) -> str:
    """Return a canonical whole-second UTC timestamp."""

    instant = value or datetime.now(UTC)
    if instant.tzinfo is None:
        raise ValueError("timestamp must include a timezone")
    return (
        instant.astimezone(UTC)
        .replace(microsecond=0)
        .isoformat(timespec="seconds")
        .replace("+00:00", "Z")
    )


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
        raise AttestationValidationError(
            document_name,
            path,
            "expected canonical unpadded base64url",
        ) from exc
    if len(decoded) != expected_bytes or _base64url_encode(decoded) != encoded:
        raise AttestationValidationError(
            document_name,
            path,
            f"expected canonical unpadded base64url for {expected_bytes} bytes",
        )
    return encoded


def _parse_artifact(value: Any, path: str, document_name: str) -> ArtifactSubject:
    obj = _object(
        value,
        path,
        document_name,
        required={"artifact_id", "media_type", "sha256", "byte_count"},
    )
    return ArtifactSubject(
        artifact_id=_string(
            obj["artifact_id"],
            f"{path}.artifact_id",
            document_name,
            pattern=_SAFE_ID_PATTERN,
            maximum=128,
        ),
        media_type=_string(
            obj["media_type"],
            f"{path}.media_type",
            document_name,
            pattern=_MEDIA_TYPE_PATTERN,
            maximum=255,
        ),
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
        ),
    )


def _parse_producer(value: Any, path: str, document_name: str) -> ProducerIdentity:
    obj = _object(
        value,
        path,
        document_name,
        required={"producer_id", "key_id"},
    )
    return ProducerIdentity(
        producer_id=_string(
            obj["producer_id"],
            f"{path}.producer_id",
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


def _parse_retention(value: Any, path: str, document_name: str) -> RetentionRequirement:
    obj = _object(
        value,
        path,
        document_name,
        required={"class_id", "retain_until"},
    )
    return RetentionRequirement(
        class_id=_string(
            obj["class_id"],
            f"{path}.class_id",
            document_name,
            pattern=_SAFE_ID_PATTERN,
            maximum=128,
        ),
        retain_until=_timestamp(
            obj["retain_until"],
            f"{path}.retain_until",
            document_name,
        ),
    )


def parse_artifact_attestation(document: Any) -> ArtifactAttestation:
    """Strictly parse an untrusted detached artifact attestation."""

    name = "artifact attestation"
    root = _object(
        document,
        "$",
        name,
        required={
            "schema_version",
            "artifact",
            "producer",
            "issued_at",
            "expires_at",
            "retention",
            "revocation_list_id",
            "signature",
        },
    )
    if root["schema_version"] != ARTIFACT_ATTESTATION_SCHEMA_VERSION:
        raise AttestationValidationError(
            name,
            "$.schema_version",
            f"expected {ARTIFACT_ATTESTATION_SCHEMA_VERSION}",
        )
    signature_obj = _object(
        root["signature"],
        "$.signature",
        name,
        required={"algorithm", "canonicalization", "value"},
    )
    issued_at = _timestamp(root["issued_at"], "$.issued_at", name)
    expires_at = _timestamp(root["expires_at"], "$.expires_at", name)
    retention = _parse_retention(root["retention"], "$.retention", name)
    if _timestamp_value(expires_at) <= _timestamp_value(issued_at):
        raise AttestationValidationError(
            name,
            "$.expires_at",
            "must be later than issued_at",
        )
    if _timestamp_value(retention.retain_until) < _timestamp_value(expires_at):
        raise AttestationValidationError(
            name,
            "$.retention.retain_until",
            "must be at or after expires_at",
        )
    return ArtifactAttestation(
        schema_version=ARTIFACT_ATTESTATION_SCHEMA_VERSION,
        artifact=_parse_artifact(root["artifact"], "$.artifact", name),
        producer=_parse_producer(root["producer"], "$.producer", name),
        issued_at=issued_at,
        expires_at=expires_at,
        retention=retention,
        revocation_list_id=_string(
            root["revocation_list_id"],
            "$.revocation_list_id",
            name,
            pattern=_SAFE_ID_PATTERN,
            maximum=128,
        ),
        signature=ArtifactSignature(
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
    )


def parse_attestation_trust_store(document: Any) -> AttestationTrustStore:
    """Strictly parse trusted producer-to-key bindings."""

    name = "attestation trust store"
    root = _object(
        document,
        "$",
        name,
        required={"schema_version", "store_id", "revocation_list_id", "keys"},
    )
    if root["schema_version"] != ATTESTATION_TRUST_STORE_SCHEMA_VERSION:
        raise AttestationValidationError(
            name,
            "$.schema_version",
            f"expected {ATTESTATION_TRUST_STORE_SCHEMA_VERSION}",
        )
    keys: list[TrustedProducerKey] = []
    for index, item in enumerate(_array(root["keys"], "$.keys", name, minimum=1, maximum=1_000)):
        path = f"$.keys[{index}]"
        obj = _object(
            item,
            path,
            name,
            required={
                "key_id",
                "producer_id",
                "algorithm",
                "public_key_base64url",
                "valid_from",
                "valid_until",
            },
        )
        valid_from = _timestamp(obj["valid_from"], f"{path}.valid_from", name)
        valid_until = _timestamp(obj["valid_until"], f"{path}.valid_until", name)
        if _timestamp_value(valid_until) <= _timestamp_value(valid_from):
            raise AttestationValidationError(
                name,
                f"{path}.valid_until",
                "must be later than valid_from",
            )
        keys.append(
            TrustedProducerKey(
                key_id=_string(
                    obj["key_id"],
                    f"{path}.key_id",
                    name,
                    pattern=_SAFE_ID_PATTERN,
                    maximum=128,
                ),
                producer_id=_string(
                    obj["producer_id"],
                    f"{path}.producer_id",
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
            )
        )
    key_ids = [key.key_id for key in keys]
    if len(set(key_ids)) != len(key_ids):
        raise AttestationValidationError(name, "$.keys", "key IDs must be unique")
    return AttestationTrustStore(
        schema_version=ATTESTATION_TRUST_STORE_SCHEMA_VERSION,
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


def parse_attestation_revocation_list(document: Any) -> AttestationRevocationList:
    """Strictly parse current producer-key revocations."""

    name = "attestation revocation list"
    root = _object(
        document,
        "$",
        name,
        required={"schema_version", "list_id", "updated_at", "revoked_keys"},
    )
    if root["schema_version"] != ATTESTATION_REVOCATION_LIST_SCHEMA_VERSION:
        raise AttestationValidationError(
            name,
            "$.schema_version",
            f"expected {ATTESTATION_REVOCATION_LIST_SCHEMA_VERSION}",
        )
    updated_at = _timestamp(root["updated_at"], "$.updated_at", name)
    revoked_keys: list[KeyRevocation] = []
    for index, item in enumerate(
        _array(
            root["revoked_keys"],
            "$.revoked_keys",
            name,
            maximum=10_000,
        )
    ):
        path = f"$.revoked_keys[{index}]"
        obj = _object(
            item,
            path,
            name,
            required={"key_id", "revoked_at", "mode", "reason"},
        )
        revoked_at = _timestamp(obj["revoked_at"], f"{path}.revoked_at", name)
        if _timestamp_value(revoked_at) > _timestamp_value(updated_at):
            raise AttestationValidationError(
                name,
                f"{path}.revoked_at",
                "must not be later than updated_at",
            )
        revoked_keys.append(
            KeyRevocation(
                key_id=_string(
                    obj["key_id"],
                    f"{path}.key_id",
                    name,
                    pattern=_SAFE_ID_PATTERN,
                    maximum=128,
                ),
                revoked_at=revoked_at,
                mode=_enum(
                    obj["mode"],
                    f"{path}.mode",
                    name,
                    RevocationMode,
                ),
                reason=_string(
                    obj["reason"],
                    f"{path}.reason",
                    name,
                    maximum=256,
                ),
            )
        )
    revoked_ids = [entry.key_id for entry in revoked_keys]
    if len(set(revoked_ids)) != len(revoked_ids):
        raise AttestationValidationError(
            name,
            "$.revoked_keys",
            "key IDs must be unique",
        )
    return AttestationRevocationList(
        schema_version=ATTESTATION_REVOCATION_LIST_SCHEMA_VERSION,
        list_id=_string(
            root["list_id"],
            "$.list_id",
            name,
            pattern=_SAFE_ID_PATTERN,
            maximum=128,
        ),
        updated_at=updated_at,
        revoked_keys=tuple(revoked_keys),
    )


def attestation_payload_bytes(attestation: ArtifactAttestation) -> bytes:
    """Return the versioned canonical bytes covered by the signature."""

    document = to_jsonable(attestation)
    document["signature"] = {
        "algorithm": attestation.signature.algorithm.value,
        "canonicalization": attestation.signature.canonicalization.value,
    }
    return json.dumps(
        document,
        allow_nan=False,
        ensure_ascii=False,
        separators=(",", ":"),
        sort_keys=True,
    ).encode("utf-8")


def _cryptography_types() -> tuple[Any, Any, Any, Any, Any]:
    try:
        from cryptography.exceptions import InvalidSignature, UnsupportedAlgorithm
        from cryptography.hazmat.primitives import serialization
        from cryptography.hazmat.primitives.asymmetric.ed25519 import (
            Ed25519PrivateKey,
            Ed25519PublicKey,
        )
    except ImportError as exc:
        raise AttestationKeyError(
            'Ed25519 support requires: pip install "causure[attestation]"'
        ) from exc
    return (
        InvalidSignature,
        UnsupportedAlgorithm,
        serialization,
        Ed25519PrivateKey,
        Ed25519PublicKey,
    )


def _load_private_key(private_key_pem: bytes, password: bytes | None) -> Any:
    _, unsupported, serialization, private_type, _ = _cryptography_types()
    try:
        private_key = serialization.load_pem_private_key(
            private_key_pem,
            password=password,
        )
    except (TypeError, ValueError, unsupported) as exc:
        raise AttestationKeyError(
            "Ed25519 private key could not be loaded; check the key and password"
        ) from exc
    if not isinstance(private_key, private_type):
        raise AttestationKeyError("private key must be an Ed25519 PEM key")
    return private_key


def public_key_base64url_from_pem(
    key_pem: bytes,
    *,
    password: bytes | None = None,
) -> str:
    """Export an Ed25519 public key as canonical raw, unpadded base64url."""

    _, unsupported, serialization, _, public_type = _cryptography_types()
    public_key: Any | None = None
    try:
        candidate = serialization.load_pem_public_key(key_pem)
        if isinstance(candidate, public_type):
            public_key = candidate
        else:
            raise AttestationKeyError("public key must be an Ed25519 PEM key")
    except (TypeError, ValueError, unsupported):
        private_key = _load_private_key(key_pem, password)
        public_key = private_key.public_key()
    raw = public_key.public_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PublicFormat.Raw,
    )
    return _base64url_encode(raw)


def create_artifact_attestation(
    raw_bytes: bytes,
    *,
    artifact_id: str,
    media_type: str,
    producer_id: str,
    key_id: str,
    private_key_pem: bytes,
    issued_at: str,
    expires_at: str,
    retention_class: str,
    retain_until: str,
    revocation_list_id: str,
    private_key_password: bytes | None = None,
) -> ArtifactAttestation:
    """Sign exact artifact bytes with an Ed25519 producer key."""

    if not isinstance(raw_bytes, bytes) or not raw_bytes:
        raise ValueError("raw_bytes must contain the exact non-empty artifact bytes")
    if not isinstance(private_key_pem, bytes) or not private_key_pem:
        raise AttestationKeyError("private key must contain PEM bytes")
    placeholder = _base64url_encode(bytes(64))
    attestation = parse_artifact_attestation(
        {
            "schema_version": ARTIFACT_ATTESTATION_SCHEMA_VERSION,
            "artifact": {
                "artifact_id": artifact_id,
                "media_type": media_type,
                "sha256": hashlib.sha256(raw_bytes).hexdigest(),
                "byte_count": len(raw_bytes),
            },
            "producer": {
                "producer_id": producer_id,
                "key_id": key_id,
            },
            "issued_at": issued_at,
            "expires_at": expires_at,
            "retention": {
                "class_id": retention_class,
                "retain_until": retain_until,
            },
            "revocation_list_id": revocation_list_id,
            "signature": {
                "algorithm": SignatureAlgorithm.ED25519.value,
                "canonicalization": (SignatureCanonicalization.CAUSURE_JSON_V1.value),
                "value": placeholder,
            },
        }
    )
    private_key = _load_private_key(private_key_pem, private_key_password)
    signature = private_key.sign(attestation_payload_bytes(attestation))
    return replace(
        attestation,
        signature=replace(attestation.signature, value=_base64url_encode(signature)),
    )


def verify_artifact_attestation(
    raw_bytes: bytes,
    attestation: ArtifactAttestation,
    trust_store: AttestationTrustStore,
    revocations: AttestationRevocationList,
    *,
    checked_at: str,
    max_revocation_age_seconds: int = DEFAULT_MAX_REVOCATION_AGE_SECONDS,
    clock_skew_seconds: int = DEFAULT_CLOCK_SKEW_SECONDS,
) -> AttestationVerification:
    """Verify signature, exact bytes, trust, validity, retention, and revocation."""

    attestation = parse_artifact_attestation(to_jsonable(attestation))
    trust_store = parse_attestation_trust_store(to_jsonable(trust_store))
    revocations = parse_attestation_revocation_list(to_jsonable(revocations))
    if not isinstance(raw_bytes, bytes) or not raw_bytes:
        raise AttestationVerificationError(
            "artifact_invalid",
            "artifact must contain non-empty exact bytes",
        )
    if (
        isinstance(max_revocation_age_seconds, bool)
        or not isinstance(max_revocation_age_seconds, int)
        or not 0 <= max_revocation_age_seconds <= MAX_REVOCATION_AGE_SECONDS
    ):
        raise ValueError(
            f"max_revocation_age_seconds must be an integer from 0 to {MAX_REVOCATION_AGE_SECONDS}"
        )
    if (
        isinstance(clock_skew_seconds, bool)
        or not isinstance(clock_skew_seconds, int)
        or not 0 <= clock_skew_seconds <= 3_600
    ):
        raise ValueError("clock_skew_seconds must be an integer from 0 to 3600")
    checked = _timestamp(
        checked_at,
        "$.checked_at",
        "attestation verification request",
    )
    checked_time = _timestamp_value(checked)
    skew = timedelta(seconds=clock_skew_seconds)

    if trust_store.revocation_list_id != attestation.revocation_list_id:
        raise AttestationVerificationError(
            "revocation_list_mismatch",
            "attestation does not name the trust store's revocation list",
        )
    if revocations.list_id != trust_store.revocation_list_id:
        raise AttestationVerificationError(
            "revocation_list_mismatch",
            "supplied revocation list does not match the trust store",
        )

    trusted_key = next(
        (key for key in trust_store.keys if key.key_id == attestation.producer.key_id),
        None,
    )
    if trusted_key is None:
        raise AttestationVerificationError(
            "untrusted_key",
            "producer key is not present in the trust store",
        )
    if trusted_key.producer_id != attestation.producer.producer_id:
        raise AttestationVerificationError(
            "producer_mismatch",
            "producer identity is not bound to the selected key",
        )
    if trusted_key.algorithm is not attestation.signature.algorithm:
        raise AttestationVerificationError(
            "algorithm_mismatch",
            "attestation and trusted key algorithms do not match",
        )

    invalid_signature, _, _, _, public_type = _cryptography_types()
    public_bytes = base64.urlsafe_b64decode(
        trusted_key.public_key_base64url + ("=" * (-len(trusted_key.public_key_base64url) % 4))
    )
    signature_bytes = base64.urlsafe_b64decode(
        attestation.signature.value + ("=" * (-len(attestation.signature.value) % 4))
    )
    try:
        public_key = public_type.from_public_bytes(public_bytes)
        public_key.verify(
            signature_bytes,
            attestation_payload_bytes(attestation),
        )
    except invalid_signature as exc:
        raise AttestationVerificationError(
            "invalid_signature",
            "signature does not authenticate the attestation payload",
        ) from exc
    except ValueError as exc:
        raise AttestationVerificationError(
            "invalid_public_key",
            "trusted Ed25519 public key could not be loaded",
        ) from exc

    if len(raw_bytes) != attestation.artifact.byte_count:
        raise AttestationVerificationError(
            "artifact_size_mismatch",
            "artifact byte count does not match the signed subject",
        )
    if hashlib.sha256(raw_bytes).hexdigest() != attestation.artifact.sha256:
        raise AttestationVerificationError(
            "artifact_digest_mismatch",
            "artifact digest does not match the signed subject",
        )

    issued_time = _timestamp_value(attestation.issued_at)
    expires_time = _timestamp_value(attestation.expires_at)
    key_start = _timestamp_value(trusted_key.valid_from)
    key_end = _timestamp_value(trusted_key.valid_until)
    if issued_time < key_start:
        raise AttestationVerificationError(
            "key_not_yet_valid",
            "attestation was issued before the trusted key validity window",
        )
    if issued_time >= key_end or expires_time > key_end:
        raise AttestationVerificationError(
            "key_validity_exceeded",
            "attestation validity is not contained by the key validity window",
        )
    if issued_time > checked_time + skew:
        raise AttestationVerificationError(
            "issued_in_future",
            "attestation issue time exceeds the allowed clock skew",
        )
    if checked_time >= expires_time:
        raise AttestationVerificationError(
            "attestation_expired",
            "attestation validity window has ended",
        )

    revocation_updated = _timestamp_value(revocations.updated_at)
    if revocation_updated > checked_time + skew:
        raise AttestationVerificationError(
            "revocation_list_from_future",
            "revocation list timestamp exceeds the allowed clock skew",
        )
    if checked_time - revocation_updated > (timedelta(seconds=max_revocation_age_seconds) + skew):
        raise AttestationVerificationError(
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
            raise AttestationVerificationError(
                "key_revoked",
                "producer key is revoked for this attestation",
            )

    return AttestationVerification(
        schema_version=ATTESTATION_VERIFICATION_SCHEMA_VERSION,
        verifier_version=PACKAGE_VERSION,
        status="verified",
        artifact=attestation.artifact,
        producer=attestation.producer,
        issued_at=attestation.issued_at,
        expires_at=attestation.expires_at,
        retention=attestation.retention,
        signature_algorithm=attestation.signature.algorithm,
        canonicalization=attestation.signature.canonicalization,
        trust_store_id=trust_store.store_id,
        revocation_list_id=revocations.list_id,
        revocation_list_updated_at=revocations.updated_at,
        checked_at=checked,
    )


def render_artifact_attestation(attestation: ArtifactAttestation) -> str:
    """Render a stable detached attestation document."""

    return (
        json.dumps(
            to_jsonable(attestation),
            allow_nan=False,
            ensure_ascii=False,
            indent=2,
            sort_keys=True,
        )
        + "\n"
    )


def render_attestation_verification(verification: AttestationVerification) -> str:
    """Render a stable machine-readable verification receipt."""

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
