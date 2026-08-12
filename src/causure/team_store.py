"""Transactional SQLite persistence for Team policy, audit, and export records."""

from __future__ import annotations

import hashlib
import json
import os
import re
import sqlite3
import uuid
from collections.abc import Iterator
from contextlib import contextmanager
from dataclasses import asdict, dataclass, field
from datetime import datetime
from pathlib import Path
from typing import Any

from causure.attestations import utc_timestamp
from causure.constants import (
    TeamAction,
    TeamAuditOutcome,
    TeamInvestigationPriority,
    TeamInvestigationStatus,
    TeamResourceType,
)
from causure.team_cases import (
    MAX_TEAM_CASE_RECORD_BYTES,
    TEAM_CASE_RECORD_MEDIA_TYPE,
    TeamCaseRecord,
    parse_team_case_record_bytes,
    validate_team_case_successor,
)
from causure.team_investigations import (
    MAX_TEAM_INVESTIGATION_OBSERVATIONS,
    MAX_TEAM_INVESTIGATION_RECORD_BYTES,
    TEAM_INVESTIGATION_RECORD_MEDIA_TYPE,
    TeamInvestigationRecord,
    parse_team_investigation_record_bytes,
    validate_team_investigation_successor,
)
from causure.team_service import (
    MAX_TEAM_ACCESS_POLICY_BYTES,
    MAX_TEAM_AUDIT_EVENT_BYTES,
    MAX_TEAM_AUDIT_EXPORT_BYTES,
    MAX_TEAM_EXPORT_EVENTS,
    TeamAccessPolicy,
    TeamAuditEvent,
    TeamAuditExport,
    TeamPolicySubject,
    create_team_audit_export,
    parse_team_access_policy_bytes,
    parse_team_audit_event_bytes,
    parse_team_authorization_bytes,
    render_team_audit_export,
    verify_team_audit_event,
)

TEAM_STORE_SCHEMA_VERSION = 3
TEAM_STORE_APPLICATION_ID = 0x50425050
DEFAULT_TEAM_STORE_BUSY_TIMEOUT_MS = 5_000
MAX_TEAM_STORE_BUSY_TIMEOUT_MS = 60_000
MAX_TEAM_EVENT_PAGE_SIZE = 100
MAX_TEAM_CASE_PAGE_SIZE = 100
MAX_TEAM_INVESTIGATION_PAGE_SIZE = 100

_SAFE_ID_PATTERN = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:+/@-]{0,127}$")
_SHA256_PATTERN = re.compile(r"^[a-f0-9]{64}$")

_SCHEMA_STATEMENTS = (
    """
    CREATE TABLE team_store_metadata (
        key TEXT NOT NULL PRIMARY KEY,
        value TEXT NOT NULL
    ) WITHOUT ROWID
    """,
    f"""
    CREATE TABLE team_policies (
        tenant_id TEXT NOT NULL,
        policy_id TEXT NOT NULL,
        revision INTEGER NOT NULL CHECK (revision >= 1),
        policy_sha256 TEXT NOT NULL
            CHECK (length(policy_sha256) = 64 AND lower(policy_sha256) = policy_sha256),
        byte_count INTEGER NOT NULL
            CHECK (byte_count BETWEEN 1 AND {MAX_TEAM_ACCESS_POLICY_BYTES}),
        effective_at TEXT NOT NULL,
        inserted_at TEXT NOT NULL,
        policy_bytes BLOB NOT NULL
            CHECK (typeof(policy_bytes) = 'blob' AND length(policy_bytes) = byte_count),
        PRIMARY KEY (tenant_id, policy_id, revision),
        UNIQUE (tenant_id, policy_id, revision, policy_sha256, byte_count),
        UNIQUE (tenant_id, policy_sha256)
    ) WITHOUT ROWID
    """,
    """
    CREATE TABLE team_tenants (
        tenant_id TEXT NOT NULL PRIMARY KEY,
        active_policy_id TEXT NOT NULL,
        active_policy_revision INTEGER NOT NULL CHECK (active_policy_revision >= 1),
        active_policy_sha256 TEXT NOT NULL
            CHECK (
                length(active_policy_sha256) = 64
                AND lower(active_policy_sha256) = active_policy_sha256
            ),
        active_policy_byte_count INTEGER NOT NULL CHECK (active_policy_byte_count >= 1),
        head_sequence INTEGER NOT NULL DEFAULT 0 CHECK (head_sequence >= 0),
        head_event_sha256 TEXT,
        updated_at TEXT NOT NULL,
        CHECK (
            (head_sequence = 0 AND head_event_sha256 IS NULL)
            OR (
                head_sequence >= 1
                AND length(head_event_sha256) = 64
                AND lower(head_event_sha256) = head_event_sha256
            )
        ),
        FOREIGN KEY (
            tenant_id,
            active_policy_id,
            active_policy_revision,
            active_policy_sha256,
            active_policy_byte_count
        ) REFERENCES team_policies (
            tenant_id,
            policy_id,
            revision,
            policy_sha256,
            byte_count
        )
    ) WITHOUT ROWID
    """,
    f"""
    CREATE TABLE team_events (
        tenant_id TEXT NOT NULL,
        sequence INTEGER NOT NULL CHECK (sequence >= 1),
        event_id TEXT NOT NULL,
        decision_id TEXT NOT NULL,
        event_sha256 TEXT NOT NULL
            CHECK (length(event_sha256) = 64 AND lower(event_sha256) = event_sha256),
        previous_event_sha256 TEXT,
        policy_id TEXT NOT NULL,
        policy_revision INTEGER NOT NULL CHECK (policy_revision >= 1),
        policy_sha256 TEXT NOT NULL
            CHECK (length(policy_sha256) = 64 AND lower(policy_sha256) = policy_sha256),
        policy_byte_count INTEGER NOT NULL CHECK (policy_byte_count >= 1),
        occurred_at TEXT NOT NULL,
        retain_until TEXT NOT NULL,
        byte_count INTEGER NOT NULL
            CHECK (byte_count BETWEEN 1 AND {MAX_TEAM_AUDIT_EVENT_BYTES}),
        document_sha256 TEXT NOT NULL
            CHECK (length(document_sha256) = 64 AND lower(document_sha256) = document_sha256),
        stored_at TEXT NOT NULL,
        event_bytes BLOB NOT NULL
            CHECK (typeof(event_bytes) = 'blob' AND length(event_bytes) = byte_count),
        CHECK (
            (sequence = 1 AND previous_event_sha256 IS NULL)
            OR (
                sequence > 1
                AND length(previous_event_sha256) = 64
                AND lower(previous_event_sha256) = previous_event_sha256
            )
        ),
        PRIMARY KEY (tenant_id, sequence),
        UNIQUE (tenant_id, event_id),
        UNIQUE (tenant_id, decision_id),
        UNIQUE (tenant_id, event_sha256),
        FOREIGN KEY (tenant_id) REFERENCES team_tenants (tenant_id),
        FOREIGN KEY (
            tenant_id,
            policy_id,
            policy_revision,
            policy_sha256,
            policy_byte_count
        ) REFERENCES team_policies (
            tenant_id,
            policy_id,
            revision,
            policy_sha256,
            byte_count
        )
    ) WITHOUT ROWID
    """,
    f"""
    CREATE TABLE team_exports (
        tenant_id TEXT NOT NULL,
        export_id TEXT NOT NULL,
        authorization_decision_id TEXT NOT NULL,
        head_sequence INTEGER NOT NULL CHECK (head_sequence >= 1),
        head_event_sha256 TEXT NOT NULL
            CHECK (
                length(head_event_sha256) = 64
                AND lower(head_event_sha256) = head_event_sha256
            ),
        policy_id TEXT NOT NULL,
        policy_revision INTEGER NOT NULL CHECK (policy_revision >= 1),
        policy_sha256 TEXT NOT NULL
            CHECK (length(policy_sha256) = 64 AND lower(policy_sha256) = policy_sha256),
        policy_byte_count INTEGER NOT NULL CHECK (policy_byte_count >= 1),
        created_at TEXT NOT NULL,
        retain_until TEXT NOT NULL,
        byte_count INTEGER NOT NULL
            CHECK (byte_count BETWEEN 1 AND {MAX_TEAM_AUDIT_EXPORT_BYTES}),
        document_sha256 TEXT NOT NULL
            CHECK (length(document_sha256) = 64 AND lower(document_sha256) = document_sha256),
        stored_at TEXT NOT NULL,
        export_bytes BLOB NOT NULL
            CHECK (typeof(export_bytes) = 'blob' AND length(export_bytes) = byte_count),
        PRIMARY KEY (tenant_id, export_id),
        UNIQUE (tenant_id, authorization_decision_id),
        UNIQUE (tenant_id, document_sha256),
        FOREIGN KEY (tenant_id) REFERENCES team_tenants (tenant_id),
        FOREIGN KEY (
            tenant_id,
            policy_id,
            policy_revision,
            policy_sha256,
            policy_byte_count
        ) REFERENCES team_policies (
            tenant_id,
            policy_id,
            revision,
            policy_sha256,
            byte_count
        )
    ) WITHOUT ROWID
    """,
    """
    CREATE TRIGGER team_store_metadata_no_update
    BEFORE UPDATE ON team_store_metadata
    BEGIN
        SELECT RAISE(ABORT, 'Team store metadata is immutable');
    END
    """,
    """
    CREATE TRIGGER team_store_metadata_no_delete
    BEFORE DELETE ON team_store_metadata
    BEGIN
        SELECT RAISE(ABORT, 'Team store metadata is immutable');
    END
    """,
    """
    CREATE TRIGGER team_policies_no_update
    BEFORE UPDATE ON team_policies
    BEGIN
        SELECT RAISE(ABORT, 'Team policies are immutable');
    END
    """,
    """
    CREATE TRIGGER team_policies_no_delete
    BEFORE DELETE ON team_policies
    BEGIN
        SELECT RAISE(ABORT, 'Team policies are immutable');
    END
    """,
    """
    CREATE TRIGGER team_events_no_update
    BEFORE UPDATE ON team_events
    BEGIN
        SELECT RAISE(ABORT, 'Team events are immutable');
    END
    """,
    """
    CREATE TRIGGER team_events_no_delete
    BEFORE DELETE ON team_events
    BEGIN
        SELECT RAISE(ABORT, 'Team events are immutable');
    END
    """,
    """
    CREATE TRIGGER team_exports_no_update
    BEFORE UPDATE ON team_exports
    BEGIN
        SELECT RAISE(ABORT, 'Team exports are immutable');
    END
    """,
    """
    CREATE TRIGGER team_exports_no_delete
    BEFORE DELETE ON team_exports
    BEGIN
        SELECT RAISE(ABORT, 'Team exports are immutable');
    END
    """,
    """
    CREATE TRIGGER team_tenants_empty_head_on_insert
    BEFORE INSERT ON team_tenants
    WHEN NEW.head_sequence != 0 OR NEW.head_event_sha256 IS NOT NULL
    BEGIN
        SELECT RAISE(ABORT, 'A new Team tenant must have an empty ledger head');
    END
    """,
    """
    CREATE TRIGGER team_tenants_no_delete
    BEFORE DELETE ON team_tenants
    BEGIN
        SELECT RAISE(ABORT, 'Team tenants are immutable');
    END
    """,
    """
    CREATE TRIGGER team_tenants_policy_forward_only
    BEFORE UPDATE OF
        active_policy_id,
        active_policy_revision,
        active_policy_sha256,
        active_policy_byte_count
    ON team_tenants
    WHEN
        NEW.active_policy_id IS NOT OLD.active_policy_id
        OR NEW.active_policy_revision IS NOT OLD.active_policy_revision
        OR NEW.active_policy_sha256 IS NOT OLD.active_policy_sha256
        OR NEW.active_policy_byte_count IS NOT OLD.active_policy_byte_count
    BEGIN
        SELECT CASE
            WHEN NEW.active_policy_revision <= OLD.active_policy_revision
            THEN RAISE(ABORT, 'Team active policy revision must advance')
        END;
    END
    """,
    """
    CREATE TRIGGER team_events_match_current_head
    BEFORE INSERT ON team_events
    BEGIN
        SELECT CASE
            WHEN NOT EXISTS (
                SELECT 1 FROM team_tenants WHERE tenant_id = NEW.tenant_id
            )
            THEN RAISE(ABORT, 'Team event tenant does not exist')
        END;
        SELECT CASE
            WHEN NEW.sequence != (
                SELECT head_sequence + 1
                FROM team_tenants
                WHERE tenant_id = NEW.tenant_id
            )
            THEN RAISE(ABORT, 'Team event sequence does not follow the current head')
        END;
        SELECT CASE
            WHEN NEW.previous_event_sha256 IS NOT (
                SELECT head_event_sha256
                FROM team_tenants
                WHERE tenant_id = NEW.tenant_id
            )
            THEN RAISE(ABORT, 'Team event predecessor does not match the current head')
        END;
    END
    """,
    """
    CREATE TRIGGER team_events_decision_not_exported
    BEFORE INSERT ON team_events
    WHEN EXISTS (
        SELECT 1
        FROM team_exports
        WHERE tenant_id = NEW.tenant_id
          AND authorization_decision_id = NEW.decision_id
    )
    BEGIN
        SELECT RAISE(ABORT, 'Team authorization decision id is already used by an export');
    END
    """,
    """
    CREATE TRIGGER team_exports_decision_not_event
    BEFORE INSERT ON team_exports
    WHEN EXISTS (
        SELECT 1
        FROM team_events
        WHERE tenant_id = NEW.tenant_id
          AND decision_id = NEW.authorization_decision_id
    )
    BEGIN
        SELECT RAISE(ABORT, 'Team authorization decision id is already used by an event');
    END
    """,
    """
    CREATE TRIGGER team_tenants_head_forward_only
    BEFORE UPDATE OF head_sequence, head_event_sha256 ON team_tenants
    WHEN
        NEW.head_sequence IS NOT OLD.head_sequence
        OR NEW.head_event_sha256 IS NOT OLD.head_event_sha256
    BEGIN
        SELECT CASE
            WHEN NEW.head_sequence != OLD.head_sequence + 1
            THEN RAISE(ABORT, 'Team ledger head must advance by one')
        END;
        SELECT CASE
            WHEN NOT EXISTS (
                SELECT 1
                FROM team_events
                WHERE tenant_id = NEW.tenant_id
                  AND sequence = NEW.head_sequence
                  AND event_sha256 = NEW.head_event_sha256
            )
            THEN RAISE(ABORT, 'Team ledger head must reference the appended event')
        END;
    END
    """,
)

_V1_REQUIRED_SCHEMA_OBJECTS = {
    ("table", "team_store_metadata"),
    ("table", "team_policies"),
    ("table", "team_tenants"),
    ("table", "team_events"),
    ("table", "team_exports"),
    ("trigger", "team_store_metadata_no_update"),
    ("trigger", "team_store_metadata_no_delete"),
    ("trigger", "team_policies_no_update"),
    ("trigger", "team_policies_no_delete"),
    ("trigger", "team_events_no_update"),
    ("trigger", "team_events_no_delete"),
    ("trigger", "team_exports_no_update"),
    ("trigger", "team_exports_no_delete"),
    ("trigger", "team_tenants_empty_head_on_insert"),
    ("trigger", "team_tenants_no_delete"),
    ("trigger", "team_tenants_policy_forward_only"),
    ("trigger", "team_events_match_current_head"),
    ("trigger", "team_events_decision_not_exported"),
    ("trigger", "team_exports_decision_not_event"),
    ("trigger", "team_tenants_head_forward_only"),
}

_CASE_SCHEMA_STATEMENTS = (
    f"""
    CREATE TABLE team_case_records (
        tenant_id TEXT NOT NULL,
        case_id TEXT NOT NULL,
        revision INTEGER NOT NULL CHECK (revision BETWEEN 1 AND 10000),
        published_at TEXT NOT NULL,
        event_sequence INTEGER NOT NULL CHECK (event_sequence >= 1),
        event_sha256 TEXT NOT NULL
            CHECK (length(event_sha256) = 64 AND lower(event_sha256) = event_sha256),
        retain_until TEXT NOT NULL,
        record_sha256 TEXT NOT NULL
            CHECK (length(record_sha256) = 64 AND lower(record_sha256) = record_sha256),
        byte_count INTEGER NOT NULL
            CHECK (byte_count BETWEEN 1 AND {MAX_TEAM_CASE_RECORD_BYTES}),
        stored_at TEXT NOT NULL,
        record_bytes BLOB NOT NULL
            CHECK (typeof(record_bytes) = 'blob' AND length(record_bytes) = byte_count),
        PRIMARY KEY (tenant_id, case_id, revision),
        UNIQUE (tenant_id, event_sequence),
        UNIQUE (tenant_id, record_sha256),
        FOREIGN KEY (tenant_id, event_sequence)
            REFERENCES team_events (tenant_id, sequence)
    ) WITHOUT ROWID
    """,
    """
    CREATE INDEX team_case_records_latest
    ON team_case_records (tenant_id, event_sequence DESC)
    """,
    """
    CREATE TRIGGER team_case_records_no_update
    BEFORE UPDATE ON team_case_records
    BEGIN
        SELECT RAISE(ABORT, 'Team case records are immutable');
    END
    """,
    """
    CREATE TRIGGER team_case_records_no_delete
    BEFORE DELETE ON team_case_records
    BEGIN
        SELECT RAISE(ABORT, 'Team case records are immutable');
    END
    """,
    """
    CREATE TRIGGER team_case_records_revision_successor
    BEFORE INSERT ON team_case_records
    WHEN NEW.revision != COALESCE(
        (
            SELECT max(revision) + 1
            FROM team_case_records
            WHERE tenant_id = NEW.tenant_id AND case_id = NEW.case_id
        ),
        1
    )
    BEGIN
        SELECT RAISE(ABORT, 'Team case revision must follow the current case revision');
    END
    """,
    """
    CREATE TRIGGER team_case_records_match_event
    BEFORE INSERT ON team_case_records
    WHEN NOT EXISTS (
        SELECT 1
        FROM team_events
        WHERE tenant_id = NEW.tenant_id
          AND sequence = NEW.event_sequence
          AND event_sha256 = NEW.event_sha256
          AND retain_until = NEW.retain_until
    )
    BEGIN
        SELECT RAISE(ABORT, 'Team case record must bind its exact audit event');
    END
    """,
)

_V2_REQUIRED_SCHEMA_OBJECTS = _V1_REQUIRED_SCHEMA_OBJECTS | {
    ("table", "team_case_records"),
    ("trigger", "team_case_records_no_update"),
    ("trigger", "team_case_records_no_delete"),
    ("trigger", "team_case_records_revision_successor"),
    ("trigger", "team_case_records_match_event"),
}

_INVESTIGATION_SCHEMA_STATEMENTS = (
    f"""
    CREATE TABLE team_investigation_records (
        tenant_id TEXT NOT NULL,
        investigation_id TEXT NOT NULL,
        revision INTEGER NOT NULL CHECK (revision BETWEEN 1 AND 10000),
        created_at TEXT NOT NULL,
        updated_at TEXT NOT NULL,
        status TEXT NOT NULL
            CHECK (status IN ('queued', 'investigating', 'blocked', 'closed')),
        priority TEXT NOT NULL
            CHECK (priority IN ('low', 'normal', 'high', 'critical')),
        assigned_identity_provider TEXT,
        assigned_subject_id TEXT,
        resolution TEXT CHECK (
            resolution IS NULL
            OR resolution IN (
                'change_case_opened',
                'duplicate',
                'not_a_failure',
                'no_change_required',
                'insufficient_evidence'
            )
        ),
        linked_case_id TEXT,
        duplicate_of TEXT,
        observation_count INTEGER NOT NULL
            CHECK (observation_count BETWEEN 1 AND {MAX_TEAM_INVESTIGATION_OBSERVATIONS}),
        event_sequence INTEGER NOT NULL CHECK (event_sequence >= 1),
        event_sha256 TEXT NOT NULL
            CHECK (length(event_sha256) = 64 AND lower(event_sha256) = event_sha256),
        retain_until TEXT NOT NULL,
        record_sha256 TEXT NOT NULL
            CHECK (length(record_sha256) = 64 AND lower(record_sha256) = record_sha256),
        byte_count INTEGER NOT NULL
            CHECK (byte_count BETWEEN 1 AND {MAX_TEAM_INVESTIGATION_RECORD_BYTES}),
        stored_at TEXT NOT NULL,
        record_bytes BLOB NOT NULL
            CHECK (typeof(record_bytes) = 'blob' AND length(record_bytes) = byte_count),
        CHECK (
            (assigned_identity_provider IS NULL AND assigned_subject_id IS NULL)
            OR (
                assigned_identity_provider IS NOT NULL
                AND assigned_subject_id IS NOT NULL
                AND length(assigned_identity_provider) BETWEEN 1 AND 128
                AND length(assigned_subject_id) BETWEEN 1 AND 128
            )
        ),
        CHECK (
            (status != 'closed' AND resolution IS NULL
                AND linked_case_id IS NULL AND duplicate_of IS NULL)
            OR (status = 'closed' AND resolution IS NOT NULL)
        ),
        CHECK (
            (resolution = 'change_case_opened'
                AND linked_case_id IS NOT NULL AND duplicate_of IS NULL)
            OR (resolution = 'duplicate'
                AND duplicate_of IS NOT NULL AND linked_case_id IS NULL)
            OR (resolution IN ('not_a_failure', 'no_change_required', 'insufficient_evidence')
                AND linked_case_id IS NULL AND duplicate_of IS NULL)
            OR resolution IS NULL
        ),
        PRIMARY KEY (tenant_id, investigation_id, revision),
        UNIQUE (tenant_id, event_sequence),
        UNIQUE (tenant_id, record_sha256),
        FOREIGN KEY (tenant_id, event_sequence)
            REFERENCES team_events (tenant_id, sequence)
    ) WITHOUT ROWID
    """,
    """
    CREATE INDEX team_investigation_records_latest
    ON team_investigation_records (tenant_id, event_sequence DESC)
    """,
    """
    CREATE INDEX team_investigation_records_queue
    ON team_investigation_records (tenant_id, status, priority, event_sequence DESC)
    """,
    """
    CREATE TRIGGER team_investigation_records_no_update
    BEFORE UPDATE ON team_investigation_records
    BEGIN
        SELECT RAISE(ABORT, 'Team investigation records are immutable');
    END
    """,
    """
    CREATE TRIGGER team_investigation_records_no_delete
    BEFORE DELETE ON team_investigation_records
    BEGIN
        SELECT RAISE(ABORT, 'Team investigation records are immutable');
    END
    """,
    """
    CREATE TRIGGER team_investigation_records_revision_successor
    BEFORE INSERT ON team_investigation_records
    WHEN NEW.revision != COALESCE(
        (
            SELECT max(revision) + 1
            FROM team_investigation_records
            WHERE tenant_id = NEW.tenant_id
              AND investigation_id = NEW.investigation_id
        ),
        1
    )
    BEGIN
        SELECT RAISE(ABORT, 'Team investigation revision must follow the current revision');
    END
    """,
    """
    CREATE TRIGGER team_investigation_records_match_event
    BEFORE INSERT ON team_investigation_records
    WHEN NOT EXISTS (
        SELECT 1
        FROM team_events
        WHERE tenant_id = NEW.tenant_id
          AND sequence = NEW.event_sequence
          AND event_sha256 = NEW.event_sha256
          AND retain_until = NEW.retain_until
    )
    BEGIN
        SELECT RAISE(ABORT, 'Team investigation record must bind its exact audit event');
    END
    """,
    """
    CREATE TRIGGER team_investigation_records_linked_case_exists
    BEFORE INSERT ON team_investigation_records
    WHEN NEW.linked_case_id IS NOT NULL AND NOT EXISTS (
        SELECT 1
        FROM team_case_records
        WHERE tenant_id = NEW.tenant_id AND case_id = NEW.linked_case_id
    )
    BEGIN
        SELECT RAISE(ABORT, 'Team investigation linked case must exist in the tenant');
    END
    """,
    """
    CREATE TRIGGER team_investigation_records_duplicate_exists
    BEFORE INSERT ON team_investigation_records
    WHEN NEW.duplicate_of IS NOT NULL AND NOT EXISTS (
        SELECT 1
        FROM team_investigation_records
        WHERE tenant_id = NEW.tenant_id
          AND investigation_id = NEW.duplicate_of
    )
    BEGIN
        SELECT RAISE(ABORT, 'Team investigation duplicate target must exist in the tenant');
    END
    """,
)

_ALL_SCHEMA_STATEMENTS = (
    _SCHEMA_STATEMENTS + _CASE_SCHEMA_STATEMENTS + _INVESTIGATION_SCHEMA_STATEMENTS
)
_REQUIRED_SCHEMA_OBJECTS = _V2_REQUIRED_SCHEMA_OBJECTS | {
    ("table", "team_investigation_records"),
    ("trigger", "team_investigation_records_no_update"),
    ("trigger", "team_investigation_records_no_delete"),
    ("trigger", "team_investigation_records_revision_successor"),
    ("trigger", "team_investigation_records_match_event"),
    ("trigger", "team_investigation_records_linked_case_exists"),
    ("trigger", "team_investigation_records_duplicate_exists"),
}


class TeamStoreError(ValueError):
    """Raised when a Team persistence operation cannot be completed."""

    def __init__(self, code: str, message: str) -> None:
        self.code = code
        self.message = message
        super().__init__(f"Team store failed [{code}]: {message}")


class TeamStoreConflictError(TeamStoreError):
    """Raised for stale compare-and-swap state or a concurrent writer."""


class TeamStoreSchemaError(TeamStoreError):
    """Raised when the database is missing, incompatible, or structurally damaged."""


@dataclass(frozen=True, slots=True)
class TeamLedgerHead:
    tenant_id: str
    sequence: int
    event_sha256: str | None


@dataclass(frozen=True, slots=True)
class TeamTenantSnapshot:
    """One consistent read of a tenant's active policy, head, and optional event."""

    tenant_id: str
    policy_bytes: bytes = field(repr=False)
    head: TeamLedgerHead
    event_bytes: bytes | None = field(default=None, repr=False)


@dataclass(frozen=True, slots=True)
class TeamEventPageSnapshot:
    """One consistent read of policy, head, and a bounded recent event page."""

    tenant_id: str
    policy_bytes: bytes = field(repr=False)
    head: TeamLedgerHead
    event_bytes: tuple[bytes, ...] = field(repr=False)
    next_before_sequence: int | None


@dataclass(frozen=True, slots=True)
class TeamCaseRecordItem:
    """Exact minimized case-record bytes and the audit event that published them."""

    record_bytes: bytes = field(repr=False)
    event_bytes: bytes = field(repr=False)


@dataclass(frozen=True, slots=True)
class TeamCaseRecordSnapshot:
    """One consistent read of policy, head, and an optional latest case record."""

    tenant_id: str
    policy_bytes: bytes = field(repr=False)
    head: TeamLedgerHead
    item: TeamCaseRecordItem | None = field(default=None, repr=False)


@dataclass(frozen=True, slots=True)
class TeamCasePageSnapshot:
    """One consistent read of policy, head, and bounded latest case records."""

    tenant_id: str
    policy_bytes: bytes = field(repr=False)
    head: TeamLedgerHead
    items: tuple[TeamCaseRecordItem, ...] = field(repr=False)
    next_before_sequence: int | None


@dataclass(frozen=True, slots=True)
class TeamInvestigationRecordItem:
    """Exact investigation-record bytes and the audit event that published them."""

    record_bytes: bytes = field(repr=False)
    event_bytes: bytes = field(repr=False)


@dataclass(frozen=True, slots=True)
class TeamInvestigationRecordSnapshot:
    """One consistent read of policy, head, and an optional latest investigation."""

    tenant_id: str
    policy_bytes: bytes = field(repr=False)
    head: TeamLedgerHead
    item: TeamInvestigationRecordItem | None = field(default=None, repr=False)


@dataclass(frozen=True, slots=True)
class TeamInvestigationPageSnapshot:
    """One consistent read of policy, head, and bounded latest investigations."""

    tenant_id: str
    policy_bytes: bytes = field(repr=False)
    head: TeamLedgerHead
    items: tuple[TeamInvestigationRecordItem, ...] = field(repr=False)
    next_before_sequence: int | None


def render_team_ledger_head(head: TeamLedgerHead) -> str:
    """Render a stable machine-readable tenant ledger head."""

    return json.dumps(asdict(head), ensure_ascii=False, indent=2) + "\n"


def _sha256(raw_bytes: bytes) -> str:
    return hashlib.sha256(raw_bytes).hexdigest()


def _validate_identifier(value: str, name: str) -> str:
    if not isinstance(value, str) or _SAFE_ID_PATTERN.fullmatch(value) is None:
        raise TeamStoreError("invalid_identifier", f"{name} is not a valid Team identifier")
    return value


def _validate_sha256(value: str, name: str) -> str:
    if not isinstance(value, str) or _SHA256_PATTERN.fullmatch(value) is None:
        raise TeamStoreError("invalid_sha256", f"{name} must be a lowercase SHA-256 digest")
    return value


def _validate_timestamp(value: str, name: str) -> str:
    if not isinstance(value, str):
        raise TeamStoreError("invalid_timestamp", f"{name} must be a whole-second UTC timestamp")
    try:
        parsed = datetime.strptime(value, "%Y-%m-%dT%H:%M:%SZ")
    except ValueError as exc:
        raise TeamStoreError(
            "invalid_timestamp",
            f"{name} must be a whole-second UTC timestamp",
        ) from exc
    if parsed.strftime("%Y-%m-%dT%H:%M:%SZ") != value:
        raise TeamStoreError("invalid_timestamp", f"{name} must be a whole-second UTC timestamp")
    return value


def _translate_sqlite_error(exc: sqlite3.Error) -> TeamStoreError:
    code = getattr(exc, "sqlite_errorname", "")
    if code in {"SQLITE_BUSY", "SQLITE_LOCKED"} or "locked" in str(exc).lower():
        return TeamStoreConflictError(
            "store_busy",
            "the database is busy with another writer; retry from the current tenant head",
        )
    if isinstance(exc, sqlite3.IntegrityError):
        return TeamStoreError("store_constraint", str(exc))
    if isinstance(exc, sqlite3.DatabaseError):
        return TeamStoreSchemaError("store_database_error", str(exc))
    return TeamStoreError("store_sqlite_error", str(exc))


def _verified_blob(
    raw_value: Any,
    *,
    expected_byte_count: int,
    expected_sha256: str,
    record_name: str,
) -> bytes:
    raw_bytes = bytes(raw_value)
    if len(raw_bytes) != expected_byte_count or _sha256(raw_bytes) != expected_sha256:
        raise TeamStoreSchemaError(
            "stored_bytes_corrupt",
            f"the stored {record_name} bytes do not match their protected content subject",
        )
    return raw_bytes


class SQLiteTeamStore:
    """A zero-dependency local transactional store for Team records."""

    def __init__(
        self,
        database_path: str | os.PathLike[str],
        *,
        busy_timeout_ms: int = DEFAULT_TEAM_STORE_BUSY_TIMEOUT_MS,
    ) -> None:
        raw_path = os.fspath(database_path)
        if not raw_path or raw_path == ":memory:" or raw_path.startswith("file:"):
            raise TeamStoreError(
                "invalid_database_path",
                "database_path must be a persistent filesystem path",
            )
        if (
            isinstance(busy_timeout_ms, bool)
            or not isinstance(busy_timeout_ms, int)
            or not 1 <= busy_timeout_ms <= MAX_TEAM_STORE_BUSY_TIMEOUT_MS
        ):
            raise TeamStoreError(
                "invalid_busy_timeout",
                f"busy_timeout_ms must be an integer from 1 to {MAX_TEAM_STORE_BUSY_TIMEOUT_MS}",
            )
        self._path = Path(raw_path)
        self._busy_timeout_ms = busy_timeout_ms

    @property
    def database_path(self) -> Path:
        return self._path

    def _connect(self, *, create: bool = False) -> sqlite3.Connection:
        if not create and not self._path.is_file():
            raise TeamStoreSchemaError(
                "store_not_initialized",
                f"the Team store does not exist: {self._path}",
            )
        if self._path.exists() and not self._path.is_file():
            raise TeamStoreSchemaError(
                "invalid_database_path",
                f"the Team store path is not a file: {self._path}",
            )
        connection: sqlite3.Connection | None = None
        try:
            connection = sqlite3.connect(
                self._path,
                isolation_level=None,
                timeout=self._busy_timeout_ms / 1_000,
            )
            connection.row_factory = sqlite3.Row
            connection.execute(f"PRAGMA busy_timeout = {self._busy_timeout_ms}")
            connection.execute("PRAGMA foreign_keys = ON")
            connection.execute("PRAGMA recursive_triggers = ON")
            connection.execute("PRAGMA trusted_schema = OFF")
            connection.execute("PRAGMA synchronous = FULL")
            if connection.execute("PRAGMA foreign_keys").fetchone()[0] != 1:
                raise TeamStoreSchemaError(
                    "foreign_keys_unavailable",
                    "SQLite foreign-key enforcement could not be enabled",
                )
            return connection
        except TeamStoreError:
            if connection is not None:
                connection.close()
            raise
        except sqlite3.Error as exc:
            if connection is not None:
                connection.close()
            raise _translate_sqlite_error(exc) from exc

    def _require_schema_state(
        self,
        connection: sqlite3.Connection,
        *,
        version: int,
        required_objects: set[tuple[str, str]],
    ) -> None:
        user_version = int(connection.execute("PRAGMA user_version").fetchone()[0])
        application_id = int(connection.execute("PRAGMA application_id").fetchone()[0])
        if user_version != version:
            raise TeamStoreSchemaError(
                "schema_incompatible",
                f"expected Team store schema {version}, found {user_version}",
            )
        if application_id != TEAM_STORE_APPLICATION_ID:
            raise TeamStoreSchemaError(
                "application_id_mismatch",
                "the database is not a Causure Team store",
            )
        rows = connection.execute(
            "SELECT type, name FROM sqlite_master WHERE type IN ('table', 'trigger')"
        ).fetchall()
        found = {(str(row["type"]), str(row["name"])) for row in rows}
        missing = sorted(required_objects - found)
        if missing:
            names = ", ".join(name for _, name in missing)
            raise TeamStoreSchemaError(
                "schema_objects_missing",
                f"required Team store objects are missing: {names}",
            )
        metadata = connection.execute(
            "SELECT value FROM team_store_metadata WHERE key = 'schema_version'"
        ).fetchone()
        if metadata is None or metadata["value"] != str(version):
            raise TeamStoreSchemaError(
                "schema_metadata_mismatch",
                "the Team store schema metadata is missing or inconsistent",
            )
        journal_mode = str(connection.execute("PRAGMA journal_mode").fetchone()[0]).lower()
        if journal_mode != "wal":
            raise TeamStoreSchemaError(
                "journal_mode_mismatch",
                "the Team store must use SQLite WAL journal mode",
            )

    def _require_schema(self, connection: sqlite3.Connection) -> None:
        self._require_schema_state(
            connection,
            version=TEAM_STORE_SCHEMA_VERSION,
            required_objects=_REQUIRED_SCHEMA_OBJECTS,
        )

    def _migrate_to_v3(
        self,
        connection: sqlite3.Connection,
        *,
        source_version: int,
        migrated_at: str,
    ) -> None:
        """Apply additive case and investigation migrations in one transaction."""

        connection.execute("BEGIN IMMEDIATE")
        user_version = int(connection.execute("PRAGMA user_version").fetchone()[0])
        application_id = int(connection.execute("PRAGMA application_id").fetchone()[0])
        if (
            user_version == TEAM_STORE_SCHEMA_VERSION
            and application_id == TEAM_STORE_APPLICATION_ID
        ):
            connection.execute("COMMIT")
            self._require_schema(connection)
            return
        if user_version != source_version or application_id != TEAM_STORE_APPLICATION_ID:
            raise TeamStoreSchemaError(
                "schema_incompatible",
                "the Team store changed before the schema migration could start",
            )
        self._require_schema_state(
            connection,
            version=source_version,
            required_objects=(
                _V1_REQUIRED_SCHEMA_OBJECTS if source_version == 1 else _V2_REQUIRED_SCHEMA_OBJECTS
            ),
        )
        statements = (
            _CASE_SCHEMA_STATEMENTS + _INVESTIGATION_SCHEMA_STATEMENTS
            if source_version == 1
            else _INVESTIGATION_SCHEMA_STATEMENTS
        )
        for statement in statements:
            connection.execute(statement)
        connection.execute("DROP TRIGGER team_store_metadata_no_update")
        connection.execute(
            "UPDATE team_store_metadata SET value = ? WHERE key = 'schema_version'",
            (str(TEAM_STORE_SCHEMA_VERSION),),
        )
        if source_version == 1:
            connection.execute(
                "INSERT INTO team_store_metadata (key, value) VALUES (?, ?)",
                ("migrated_to_v2_at", migrated_at),
            )
        connection.execute(
            "INSERT INTO team_store_metadata (key, value) VALUES (?, ?)",
            ("migrated_to_v3_at", migrated_at),
        )
        connection.execute(
            """
            CREATE TRIGGER team_store_metadata_no_update
            BEFORE UPDATE ON team_store_metadata
            BEGIN
                SELECT RAISE(ABORT, 'Team store metadata is immutable');
            END
            """
        )
        connection.execute(f"PRAGMA user_version = {TEAM_STORE_SCHEMA_VERSION}")
        connection.execute("COMMIT")
        self._require_schema(connection)

    @contextmanager
    def _read_connection(self) -> Iterator[sqlite3.Connection]:
        connection = self._connect()
        try:
            self._require_schema(connection)
            connection.execute("PRAGMA query_only = ON")
            connection.execute("BEGIN")
            yield connection
            connection.execute("COMMIT")
        except TeamStoreError:
            if connection.in_transaction:
                connection.execute("ROLLBACK")
            raise
        except sqlite3.Error as exc:
            if connection.in_transaction:
                connection.execute("ROLLBACK")
            raise _translate_sqlite_error(exc) from exc
        except Exception:
            if connection.in_transaction:
                connection.execute("ROLLBACK")
            raise
        finally:
            connection.close()

    @contextmanager
    def _write_transaction(self) -> Iterator[sqlite3.Connection]:
        connection = self._connect()
        try:
            connection.execute("BEGIN IMMEDIATE")
            self._require_schema(connection)
            yield connection
            connection.execute("COMMIT")
        except TeamStoreError:
            if connection.in_transaction:
                connection.execute("ROLLBACK")
            raise
        except sqlite3.Error as exc:
            if connection.in_transaction:
                connection.execute("ROLLBACK")
            raise _translate_sqlite_error(exc) from exc
        except Exception:
            if connection.in_transaction:
                connection.execute("ROLLBACK")
            raise
        finally:
            connection.close()

    def initialize(self, *, created_at: str | None = None) -> None:
        """Create the store schema, or validate an already initialized store."""

        instant = _validate_timestamp(created_at or utc_timestamp(), "created_at")
        if not self._path.parent.is_dir():
            raise TeamStoreError(
                "database_parent_missing",
                f"the database parent directory does not exist: {self._path.parent}",
            )
        connection = self._connect(create=True)
        try:
            connection.execute("BEGIN")
            user_version = int(connection.execute("PRAGMA user_version").fetchone()[0])
            application_id = int(connection.execute("PRAGMA application_id").fetchone()[0])
            object_count = int(
                connection.execute(
                    """
                    SELECT count(*)
                    FROM sqlite_master
                    WHERE name NOT LIKE 'sqlite_%'
                    """
                ).fetchone()[0]
            )
            connection.execute("COMMIT")
            if user_version == TEAM_STORE_SCHEMA_VERSION:
                if application_id != TEAM_STORE_APPLICATION_ID:
                    raise TeamStoreSchemaError(
                        "application_id_mismatch",
                        "the database is not a Causure Team store",
                    )
                mode = str(connection.execute("PRAGMA journal_mode = WAL").fetchone()[0]).lower()
                if mode != "wal":
                    raise TeamStoreSchemaError(
                        "wal_unavailable",
                        "SQLite WAL journal mode could not be enabled",
                    )
                self._require_schema(connection)
                return
            if user_version in {1, 2} and application_id == TEAM_STORE_APPLICATION_ID:
                mode = str(connection.execute("PRAGMA journal_mode = WAL").fetchone()[0]).lower()
                if mode != "wal":
                    raise TeamStoreSchemaError(
                        "wal_unavailable",
                        "SQLite WAL journal mode could not be enabled",
                    )
                self._migrate_to_v3(
                    connection,
                    source_version=user_version,
                    migrated_at=instant,
                )
                return
            if user_version != 0 or application_id != 0 or object_count != 0:
                raise TeamStoreSchemaError(
                    "schema_incompatible",
                    "refusing to initialize a non-empty or incompatible database",
                )

            mode = str(connection.execute("PRAGMA journal_mode = WAL").fetchone()[0]).lower()
            if mode != "wal":
                raise TeamStoreSchemaError(
                    "wal_unavailable",
                    "SQLite WAL journal mode could not be enabled",
                )
            connection.execute("BEGIN IMMEDIATE")
            user_version = int(connection.execute("PRAGMA user_version").fetchone()[0])
            application_id = int(connection.execute("PRAGMA application_id").fetchone()[0])
            object_count = int(
                connection.execute(
                    """
                    SELECT count(*)
                    FROM sqlite_master
                    WHERE name NOT LIKE 'sqlite_%'
                    """
                ).fetchone()[0]
            )
            if (
                user_version == TEAM_STORE_SCHEMA_VERSION
                and application_id == TEAM_STORE_APPLICATION_ID
            ):
                connection.execute("COMMIT")
                self._require_schema(connection)
                return
            if user_version != 0 or application_id != 0 or object_count != 0:
                raise TeamStoreSchemaError(
                    "schema_incompatible",
                    "refusing to initialize a non-empty or incompatible database",
                )
            for statement in _ALL_SCHEMA_STATEMENTS:
                connection.execute(statement)
            connection.execute(
                "INSERT INTO team_store_metadata (key, value) VALUES (?, ?)",
                ("schema_version", str(TEAM_STORE_SCHEMA_VERSION)),
            )
            connection.execute(
                "INSERT INTO team_store_metadata (key, value) VALUES (?, ?)",
                ("created_at", instant),
            )
            connection.execute(f"PRAGMA application_id = {TEAM_STORE_APPLICATION_ID}")
            connection.execute(f"PRAGMA user_version = {TEAM_STORE_SCHEMA_VERSION}")
            connection.execute("COMMIT")
            self._require_schema(connection)
        except TeamStoreError:
            if connection.in_transaction:
                connection.execute("ROLLBACK")
            raise
        except sqlite3.Error as exc:
            if connection.in_transaction:
                connection.execute("ROLLBACK")
            raise _translate_sqlite_error(exc) from exc
        finally:
            connection.close()

    def check(self) -> None:
        """Validate that the initialized store is readable and structurally compatible."""

        with self._read_connection() as connection:
            connection.execute("SELECT 1").fetchone()

    def put_policy(self, policy_bytes: bytes) -> TeamAccessPolicy:
        """Append a policy snapshot and advance the tenant's active revision."""

        policy = parse_team_access_policy_bytes(policy_bytes)
        digest = _sha256(policy_bytes)
        stored_at = utc_timestamp()
        with self._write_transaction() as connection:
            existing = connection.execute(
                """
                SELECT policy_sha256, byte_count, policy_bytes
                FROM team_policies
                WHERE tenant_id = ? AND policy_id = ? AND revision = ?
                """,
                (policy.tenant_id, policy.policy_id, policy.revision),
            ).fetchone()
            if existing is not None:
                existing_bytes = _verified_blob(
                    existing["policy_bytes"],
                    expected_byte_count=int(existing["byte_count"]),
                    expected_sha256=str(existing["policy_sha256"]),
                    record_name="policy",
                )
                if existing_bytes == policy_bytes:
                    return policy
                raise TeamStoreConflictError(
                    "policy_revision_conflict",
                    "the tenant policy id and revision already bind different exact bytes",
                )

            tenant = connection.execute(
                """
                SELECT active_policy_revision
                FROM team_tenants
                WHERE tenant_id = ?
                """,
                (policy.tenant_id,),
            ).fetchone()
            if tenant is not None and policy.revision <= int(tenant["active_policy_revision"]):
                raise TeamStoreConflictError(
                    "policy_revision_stale",
                    "a tenant policy revision must be greater than the active revision",
                )

            connection.execute(
                """
                INSERT INTO team_policies (
                    tenant_id,
                    policy_id,
                    revision,
                    policy_sha256,
                    byte_count,
                    effective_at,
                    inserted_at,
                    policy_bytes
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    policy.tenant_id,
                    policy.policy_id,
                    policy.revision,
                    digest,
                    len(policy_bytes),
                    policy.effective_at,
                    stored_at,
                    sqlite3.Binary(policy_bytes),
                ),
            )
            if tenant is None:
                connection.execute(
                    """
                    INSERT INTO team_tenants (
                        tenant_id,
                        active_policy_id,
                        active_policy_revision,
                        active_policy_sha256,
                        active_policy_byte_count,
                        head_sequence,
                        head_event_sha256,
                        updated_at
                    ) VALUES (?, ?, ?, ?, ?, 0, NULL, ?)
                    """,
                    (
                        policy.tenant_id,
                        policy.policy_id,
                        policy.revision,
                        digest,
                        len(policy_bytes),
                        stored_at,
                    ),
                )
            else:
                connection.execute(
                    """
                    UPDATE team_tenants
                    SET active_policy_id = ?,
                        active_policy_revision = ?,
                        active_policy_sha256 = ?,
                        active_policy_byte_count = ?,
                        updated_at = ?
                    WHERE tenant_id = ?
                    """,
                    (
                        policy.policy_id,
                        policy.revision,
                        digest,
                        len(policy_bytes),
                        stored_at,
                        policy.tenant_id,
                    ),
                )
        return policy

    def _policy_bytes_for_subject(
        self,
        connection: sqlite3.Connection,
        tenant_id: str,
        subject: TeamPolicySubject,
    ) -> bytes:
        row = connection.execute(
            """
            SELECT policy_bytes, byte_count, policy_sha256
            FROM team_policies
            WHERE tenant_id = ?
              AND policy_id = ?
              AND revision = ?
              AND policy_sha256 = ?
              AND byte_count = ?
            """,
            (
                tenant_id,
                subject.policy_id,
                subject.revision,
                subject.sha256,
                subject.byte_count,
            ),
        ).fetchone()
        if row is None:
            raise TeamStoreSchemaError(
                "historical_policy_not_found",
                "the exact historical policy bound to the Team record is unavailable",
            )
        return _verified_blob(
            row["policy_bytes"],
            expected_byte_count=int(row["byte_count"]),
            expected_sha256=str(row["policy_sha256"]),
            record_name="policy",
        )

    def _validated_head(
        self,
        connection: sqlite3.Connection,
        tenant_id: str,
        sequence: int,
        digest: str | None,
    ) -> TeamLedgerHead:
        if sequence == 0:
            unexpected = connection.execute(
                "SELECT 1 FROM team_events WHERE tenant_id = ? LIMIT 1",
                (tenant_id,),
            ).fetchone()
            if unexpected is not None:
                raise TeamStoreSchemaError(
                    "ledger_head_mismatch",
                    "the empty tenant head has stored events",
                )
        else:
            event_row = connection.execute(
                """
                SELECT event_bytes, byte_count, document_sha256
                FROM team_events
                WHERE tenant_id = ? AND sequence = ? AND event_sha256 = ?
                """,
                (tenant_id, sequence, digest),
            ).fetchone()
            if event_row is None:
                raise TeamStoreSchemaError(
                    "ledger_head_orphaned",
                    "the tenant head does not resolve to its stored event",
                )
            event_bytes = _verified_blob(
                event_row["event_bytes"],
                expected_byte_count=int(event_row["byte_count"]),
                expected_sha256=str(event_row["document_sha256"]),
                record_name="event",
            )
            if parse_team_audit_event_bytes(event_bytes).event_sha256 != digest:
                raise TeamStoreSchemaError(
                    "ledger_head_mismatch",
                    "the tenant head does not match its stored event bytes",
                )
        return TeamLedgerHead(
            tenant_id=tenant_id,
            sequence=sequence,
            event_sha256=digest,
        )

    def _tenant_policy_and_head(
        self,
        connection: sqlite3.Connection,
        tenant_id: str,
    ) -> tuple[bytes, TeamLedgerHead]:
        row = connection.execute(
            """
            SELECT
                p.policy_bytes,
                p.byte_count AS policy_byte_count,
                p.policy_sha256,
                t.head_sequence,
                t.head_event_sha256
            FROM team_tenants AS t
            JOIN team_policies AS p
              ON p.tenant_id = t.tenant_id
             AND p.policy_id = t.active_policy_id
             AND p.revision = t.active_policy_revision
             AND p.policy_sha256 = t.active_policy_sha256
             AND p.byte_count = t.active_policy_byte_count
            WHERE t.tenant_id = ?
            """,
            (tenant_id,),
        ).fetchone()
        if row is None:
            raise TeamStoreError(
                "tenant_not_found",
                f"the Team tenant does not exist: {tenant_id}",
            )
        policy_bytes = _verified_blob(
            row["policy_bytes"],
            expected_byte_count=int(row["policy_byte_count"]),
            expected_sha256=str(row["policy_sha256"]),
            record_name="policy",
        )
        head = self._validated_head(
            connection,
            tenant_id,
            int(row["head_sequence"]),
            (None if row["head_event_sha256"] is None else str(row["head_event_sha256"])),
        )
        return policy_bytes, head

    def get_tenant_snapshot(
        self,
        tenant_id: str,
        *,
        event_sequence: int | None = None,
    ) -> TeamTenantSnapshot:
        """Read active policy, protected head, and an optional event in one snapshot."""

        resolved_tenant = _validate_identifier(tenant_id, "tenant_id")
        if event_sequence is not None and (
            isinstance(event_sequence, bool)
            or not isinstance(event_sequence, int)
            or event_sequence < 1
        ):
            raise TeamStoreError(
                "invalid_sequence",
                "event_sequence must be a positive integer",
            )
        with self._read_connection() as connection:
            policy_bytes, head = self._tenant_policy_and_head(connection, resolved_tenant)
            event_bytes: bytes | None = None
            if event_sequence is not None:
                event_row = connection.execute(
                    """
                    SELECT event_bytes, byte_count, document_sha256
                    FROM team_events
                    WHERE tenant_id = ? AND sequence = ?
                    """,
                    (resolved_tenant, event_sequence),
                ).fetchone()
                if event_row is not None:
                    event_bytes = _verified_blob(
                        event_row["event_bytes"],
                        expected_byte_count=int(event_row["byte_count"]),
                        expected_sha256=str(event_row["document_sha256"]),
                        record_name="event",
                    )
            return TeamTenantSnapshot(
                tenant_id=resolved_tenant,
                policy_bytes=policy_bytes,
                head=head,
                event_bytes=event_bytes,
            )

    def get_event_page_snapshot(
        self,
        tenant_id: str,
        *,
        limit: int = 50,
        before_sequence: int | None = None,
    ) -> TeamEventPageSnapshot:
        """Read a newest-first bounded event page with policy and head in one snapshot."""

        resolved_tenant = _validate_identifier(tenant_id, "tenant_id")
        if (
            isinstance(limit, bool)
            or not isinstance(limit, int)
            or not 1 <= limit <= MAX_TEAM_EVENT_PAGE_SIZE
        ):
            raise TeamStoreError(
                "invalid_page_limit",
                f"limit must be an integer from 1 to {MAX_TEAM_EVENT_PAGE_SIZE}",
            )
        if before_sequence is not None and (
            isinstance(before_sequence, bool)
            or not isinstance(before_sequence, int)
            or not 1 <= before_sequence <= MAX_TEAM_EXPORT_EVENTS + 1
        ):
            raise TeamStoreError(
                "invalid_before_sequence",
                "before_sequence must be a positive sequence within this store revision",
            )

        with self._read_connection() as connection:
            policy_bytes, head = self._tenant_policy_and_head(connection, resolved_tenant)
            exclusive_upper_bound = (
                head.sequence + 1 if before_sequence is None else before_sequence
            )
            rows = connection.execute(
                """
                SELECT
                    sequence,
                    event_sha256,
                    event_bytes,
                    byte_count,
                    document_sha256
                FROM team_events
                WHERE tenant_id = ? AND sequence < ?
                ORDER BY sequence DESC
                LIMIT ?
                """,
                (resolved_tenant, exclusive_upper_bound, limit + 1),
            ).fetchall()
            has_more = len(rows) > limit
            included_rows = rows[:limit]
            verified_events: list[bytes] = []
            for row in included_rows:
                raw_bytes = _verified_blob(
                    row["event_bytes"],
                    expected_byte_count=int(row["byte_count"]),
                    expected_sha256=str(row["document_sha256"]),
                    record_name="event",
                )
                event = parse_team_audit_event_bytes(raw_bytes)
                if (
                    event.entry.tenant_id != resolved_tenant
                    or event.entry.sequence != int(row["sequence"])
                    or event.event_sha256 != str(row["event_sha256"])
                ):
                    raise TeamStoreSchemaError(
                        "stored_event_mismatch",
                        "stored event bytes do not match their tenant, sequence, or digest",
                    )
                verified_events.append(raw_bytes)
            next_before_sequence = int(included_rows[-1]["sequence"]) if has_more else None
            return TeamEventPageSnapshot(
                tenant_id=resolved_tenant,
                policy_bytes=policy_bytes,
                head=head,
                event_bytes=tuple(verified_events),
                next_before_sequence=next_before_sequence,
            )

    @staticmethod
    def _verified_case_item(row: sqlite3.Row, tenant_id: str) -> TeamCaseRecordItem:
        record_bytes = _verified_blob(
            row["record_bytes"],
            expected_byte_count=int(row["record_byte_count"]),
            expected_sha256=str(row["record_sha256"]),
            record_name="case record",
        )
        try:
            record = parse_team_case_record_bytes(record_bytes)
        except ValueError as exc:
            raise TeamStoreSchemaError(
                "stored_case_record_invalid",
                "stored case-record bytes no longer satisfy their closed contract",
            ) from exc
        event_bytes = _verified_blob(
            row["event_bytes"],
            expected_byte_count=int(row["event_byte_count"]),
            expected_sha256=str(row["event_document_sha256"]),
            record_name="event",
        )
        event = parse_team_audit_event_bytes(event_bytes)
        event_sequence = int(row["event_sequence"])
        event_sha256 = str(row["event_sha256"])
        case_id = str(row["case_id"])
        revision = int(row["revision"])
        if (
            record.tenant_id != tenant_id
            or record.case_id != case_id
            or record.revision != revision
            or record.published_at != str(row["published_at"])
            or event.entry.tenant_id != tenant_id
            or event.entry.sequence != event_sequence
            or event.event_sha256 != event_sha256
            or event.entry.retention.retain_until != str(row["retain_until"])
            or not event.entry.authorization.authorized
            or event.entry.authorization.action is not TeamAction.INVESTIGATION_WRITE
            or event.entry.authorization.resource.resource_type
            is not TeamResourceType.INVESTIGATION
            or event.entry.authorization.resource.resource_id != case_id
            or event.entry.outcome is not TeamAuditOutcome.SUCCEEDED
            or event.entry.payload.media_type != TEAM_CASE_RECORD_MEDIA_TYPE
            or event.entry.payload.sha256 != str(row["record_sha256"])
            or event.entry.payload.byte_count != int(row["record_byte_count"])
        ):
            raise TeamStoreSchemaError(
                "stored_case_binding_mismatch",
                "stored case record does not match its tenant, revision, or audit event",
            )
        return TeamCaseRecordItem(record_bytes=record_bytes, event_bytes=event_bytes)

    def get_case_record_snapshot(
        self,
        tenant_id: str,
        case_id: str,
    ) -> TeamCaseRecordSnapshot:
        """Read the latest case revision, active policy, and head in one snapshot."""

        resolved_tenant = _validate_identifier(tenant_id, "tenant_id")
        resolved_case = _validate_identifier(case_id, "case_id")
        with self._read_connection() as connection:
            policy_bytes, head = self._tenant_policy_and_head(connection, resolved_tenant)
            row = connection.execute(
                """
                SELECT
                    c.case_id,
                    c.revision,
                    c.published_at,
                    c.event_sequence,
                    c.event_sha256,
                    c.retain_until,
                    c.record_sha256,
                    c.byte_count AS record_byte_count,
                    c.record_bytes,
                    e.byte_count AS event_byte_count,
                    e.document_sha256 AS event_document_sha256,
                    e.event_bytes
                FROM team_case_records AS c
                JOIN team_events AS e
                  ON e.tenant_id = c.tenant_id
                 AND e.sequence = c.event_sequence
                 AND e.event_sha256 = c.event_sha256
                WHERE c.tenant_id = ? AND c.case_id = ?
                ORDER BY c.revision DESC
                LIMIT 1
                """,
                (resolved_tenant, resolved_case),
            ).fetchone()
            item = None if row is None else self._verified_case_item(row, resolved_tenant)
            return TeamCaseRecordSnapshot(
                tenant_id=resolved_tenant,
                policy_bytes=policy_bytes,
                head=head,
                item=item,
            )

    def get_case_page_snapshot(
        self,
        tenant_id: str,
        *,
        limit: int = 50,
        before_sequence: int | None = None,
    ) -> TeamCasePageSnapshot:
        """Read bounded latest case revisions with policy and head in one snapshot."""

        resolved_tenant = _validate_identifier(tenant_id, "tenant_id")
        if (
            isinstance(limit, bool)
            or not isinstance(limit, int)
            or not 1 <= limit <= MAX_TEAM_CASE_PAGE_SIZE
        ):
            raise TeamStoreError(
                "invalid_page_limit",
                f"limit must be an integer from 1 to {MAX_TEAM_CASE_PAGE_SIZE}",
            )
        if before_sequence is not None and (
            isinstance(before_sequence, bool)
            or not isinstance(before_sequence, int)
            or not 1 <= before_sequence <= MAX_TEAM_EXPORT_EVENTS + 1
        ):
            raise TeamStoreError(
                "invalid_before_sequence",
                "before_sequence must be a positive sequence within this store revision",
            )
        with self._read_connection() as connection:
            policy_bytes, head = self._tenant_policy_and_head(connection, resolved_tenant)
            exclusive_upper_bound = (
                head.sequence + 1 if before_sequence is None else before_sequence
            )
            rows = connection.execute(
                """
                SELECT
                    c.case_id,
                    c.revision,
                    c.published_at,
                    c.event_sequence,
                    c.event_sha256,
                    c.retain_until,
                    c.record_sha256,
                    c.byte_count AS record_byte_count,
                    c.record_bytes,
                    e.byte_count AS event_byte_count,
                    e.document_sha256 AS event_document_sha256,
                    e.event_bytes
                FROM team_case_records AS c
                JOIN (
                    SELECT case_id, max(revision) AS revision
                    FROM team_case_records
                    WHERE tenant_id = ?
                    GROUP BY case_id
                ) AS latest
                  ON latest.case_id = c.case_id
                 AND latest.revision = c.revision
                JOIN team_events AS e
                  ON e.tenant_id = c.tenant_id
                 AND e.sequence = c.event_sequence
                 AND e.event_sha256 = c.event_sha256
                WHERE c.tenant_id = ? AND c.event_sequence < ?
                ORDER BY c.event_sequence DESC
                LIMIT ?
                """,
                (resolved_tenant, resolved_tenant, exclusive_upper_bound, limit + 1),
            ).fetchall()
            has_more = len(rows) > limit
            included_rows = rows[:limit]
            items = tuple(self._verified_case_item(row, resolved_tenant) for row in included_rows)
            next_before_sequence = int(included_rows[-1]["event_sequence"]) if has_more else None
            return TeamCasePageSnapshot(
                tenant_id=resolved_tenant,
                policy_bytes=policy_bytes,
                head=head,
                items=items,
                next_before_sequence=next_before_sequence,
            )

    @staticmethod
    def _verified_investigation_item(
        row: sqlite3.Row,
        tenant_id: str,
    ) -> TeamInvestigationRecordItem:
        record_bytes = _verified_blob(
            row["record_bytes"],
            expected_byte_count=int(row["record_byte_count"]),
            expected_sha256=str(row["record_sha256"]),
            record_name="investigation record",
        )
        try:
            record = parse_team_investigation_record_bytes(record_bytes)
        except ValueError as exc:
            raise TeamStoreSchemaError(
                "stored_investigation_record_invalid",
                "stored investigation-record bytes no longer satisfy their closed contract",
            ) from exc
        event_bytes = _verified_blob(
            row["event_bytes"],
            expected_byte_count=int(row["event_byte_count"]),
            expected_sha256=str(row["event_document_sha256"]),
            record_name="event",
        )
        event = parse_team_audit_event_bytes(event_bytes)
        event_sequence = int(row["event_sequence"])
        event_sha256 = str(row["event_sha256"])
        investigation_id = str(row["investigation_id"])
        assigned_identity_provider = (
            None
            if row["assigned_identity_provider"] is None
            else str(row["assigned_identity_provider"])
        )
        assigned_subject_id = (
            None if row["assigned_subject_id"] is None else str(row["assigned_subject_id"])
        )
        if (
            record.tenant_id != tenant_id
            or record.investigation_id != investigation_id
            or record.revision != int(row["revision"])
            or record.created_at != str(row["created_at"])
            or record.updated_at != str(row["updated_at"])
            or record.status.value != str(row["status"])
            or record.priority.value != str(row["priority"])
            or (None if record.assigned_to is None else record.assigned_to.identity_provider)
            != assigned_identity_provider
            or (None if record.assigned_to is None else record.assigned_to.subject_id)
            != assigned_subject_id
            or (None if record.resolution is None else record.resolution.value)
            != (None if row["resolution"] is None else str(row["resolution"]))
            or record.linked_case_id
            != (None if row["linked_case_id"] is None else str(row["linked_case_id"]))
            or record.duplicate_of
            != (None if row["duplicate_of"] is None else str(row["duplicate_of"]))
            or len(record.observations) != int(row["observation_count"])
            or event.entry.tenant_id != tenant_id
            or event.entry.sequence != event_sequence
            or event.event_sha256 != event_sha256
            or event.entry.retention.retain_until != str(row["retain_until"])
            or not event.entry.authorization.authorized
            or event.entry.authorization.action is not TeamAction.INVESTIGATION_WRITE
            or event.entry.authorization.resource.resource_type
            is not TeamResourceType.INVESTIGATION
            or event.entry.authorization.resource.resource_id != investigation_id
            or event.entry.outcome is not TeamAuditOutcome.SUCCEEDED
            or event.entry.payload.media_type != TEAM_INVESTIGATION_RECORD_MEDIA_TYPE
            or event.entry.payload.sha256 != str(row["record_sha256"])
            or event.entry.payload.byte_count != int(row["record_byte_count"])
        ):
            raise TeamStoreSchemaError(
                "stored_investigation_binding_mismatch",
                "stored investigation record does not match its indexed fields or audit event",
            )
        return TeamInvestigationRecordItem(record_bytes=record_bytes, event_bytes=event_bytes)

    def get_investigation_record_snapshot(
        self,
        tenant_id: str,
        investigation_id: str,
    ) -> TeamInvestigationRecordSnapshot:
        """Read the latest investigation revision, policy, and head in one snapshot."""

        resolved_tenant = _validate_identifier(tenant_id, "tenant_id")
        resolved_investigation = _validate_identifier(investigation_id, "investigation_id")
        with self._read_connection() as connection:
            policy_bytes, head = self._tenant_policy_and_head(connection, resolved_tenant)
            row = connection.execute(
                """
                SELECT
                    i.investigation_id,
                    i.revision,
                    i.created_at,
                    i.updated_at,
                    i.status,
                    i.priority,
                    i.assigned_identity_provider,
                    i.assigned_subject_id,
                    i.resolution,
                    i.linked_case_id,
                    i.duplicate_of,
                    i.observation_count,
                    i.event_sequence,
                    i.event_sha256,
                    i.retain_until,
                    i.record_sha256,
                    i.byte_count AS record_byte_count,
                    i.record_bytes,
                    e.byte_count AS event_byte_count,
                    e.document_sha256 AS event_document_sha256,
                    e.event_bytes
                FROM team_investigation_records AS i
                JOIN team_events AS e
                  ON e.tenant_id = i.tenant_id
                 AND e.sequence = i.event_sequence
                 AND e.event_sha256 = i.event_sha256
                WHERE i.tenant_id = ? AND i.investigation_id = ?
                ORDER BY i.revision DESC
                LIMIT 1
                """,
                (resolved_tenant, resolved_investigation),
            ).fetchone()
            item = None if row is None else self._verified_investigation_item(row, resolved_tenant)
            return TeamInvestigationRecordSnapshot(
                tenant_id=resolved_tenant,
                policy_bytes=policy_bytes,
                head=head,
                item=item,
            )

    def get_investigation_page_snapshot(
        self,
        tenant_id: str,
        *,
        limit: int = 50,
        before_sequence: int | None = None,
        status: TeamInvestigationStatus | str | None = None,
        priority: TeamInvestigationPriority | str | None = None,
    ) -> TeamInvestigationPageSnapshot:
        """Read bounded latest investigation revisions with optional queue filters."""

        resolved_tenant = _validate_identifier(tenant_id, "tenant_id")
        if (
            isinstance(limit, bool)
            or not isinstance(limit, int)
            or not 1 <= limit <= MAX_TEAM_INVESTIGATION_PAGE_SIZE
        ):
            raise TeamStoreError(
                "invalid_page_limit",
                f"limit must be an integer from 1 to {MAX_TEAM_INVESTIGATION_PAGE_SIZE}",
            )
        if before_sequence is not None and (
            isinstance(before_sequence, bool)
            or not isinstance(before_sequence, int)
            or not 1 <= before_sequence <= MAX_TEAM_EXPORT_EVENTS + 1
        ):
            raise TeamStoreError(
                "invalid_before_sequence",
                "before_sequence must be a positive sequence within this store revision",
            )
        try:
            resolved_status = None if status is None else TeamInvestigationStatus(status)
        except (TypeError, ValueError) as exc:
            raise TeamStoreError(
                "invalid_investigation_status",
                "status is not a supported investigation status",
            ) from exc
        try:
            resolved_priority = None if priority is None else TeamInvestigationPriority(priority)
        except (TypeError, ValueError) as exc:
            raise TeamStoreError(
                "invalid_investigation_priority",
                "priority is not a supported investigation priority",
            ) from exc
        with self._read_connection() as connection:
            policy_bytes, head = self._tenant_policy_and_head(connection, resolved_tenant)
            exclusive_upper_bound = (
                head.sequence + 1 if before_sequence is None else before_sequence
            )
            filters = ["i.tenant_id = ?", "i.event_sequence < ?"]
            parameters: list[Any] = [
                resolved_tenant,
                resolved_tenant,
                exclusive_upper_bound,
            ]
            if resolved_status is not None:
                filters.append("i.status = ?")
                parameters.append(resolved_status.value)
            if resolved_priority is not None:
                filters.append("i.priority = ?")
                parameters.append(resolved_priority.value)
            parameters.append(limit + 1)
            rows = connection.execute(
                f"""
                SELECT
                    i.investigation_id,
                    i.revision,
                    i.created_at,
                    i.updated_at,
                    i.status,
                    i.priority,
                    i.assigned_identity_provider,
                    i.assigned_subject_id,
                    i.resolution,
                    i.linked_case_id,
                    i.duplicate_of,
                    i.observation_count,
                    i.event_sequence,
                    i.event_sha256,
                    i.retain_until,
                    i.record_sha256,
                    i.byte_count AS record_byte_count,
                    i.record_bytes,
                    e.byte_count AS event_byte_count,
                    e.document_sha256 AS event_document_sha256,
                    e.event_bytes
                FROM team_investigation_records AS i
                JOIN (
                    SELECT investigation_id, max(revision) AS revision
                    FROM team_investigation_records
                    WHERE tenant_id = ?
                    GROUP BY investigation_id
                ) AS latest
                  ON latest.investigation_id = i.investigation_id
                 AND latest.revision = i.revision
                JOIN team_events AS e
                  ON e.tenant_id = i.tenant_id
                 AND e.sequence = i.event_sequence
                 AND e.event_sha256 = i.event_sha256
                WHERE {" AND ".join(filters)}
                ORDER BY i.event_sequence DESC
                LIMIT ?
                """,
                parameters,
            ).fetchall()
            has_more = len(rows) > limit
            included_rows = rows[:limit]
            items = tuple(
                self._verified_investigation_item(row, resolved_tenant) for row in included_rows
            )
            next_before_sequence = int(included_rows[-1]["event_sequence"]) if has_more else None
            return TeamInvestigationPageSnapshot(
                tenant_id=resolved_tenant,
                policy_bytes=policy_bytes,
                head=head,
                items=items,
                next_before_sequence=next_before_sequence,
            )

    def get_active_policy_bytes(self, tenant_id: str) -> bytes:
        """Return the exact bytes of a tenant's current policy snapshot."""

        return self.get_tenant_snapshot(tenant_id).policy_bytes

    def get_policy_bytes(
        self,
        tenant_id: str,
        policy_id: str,
        revision: int,
        *,
        sha256: str | None = None,
        byte_count: int | None = None,
    ) -> bytes:
        """Resolve exact historical policy bytes, optionally by their full subject."""

        resolved_tenant = _validate_identifier(tenant_id, "tenant_id")
        resolved_policy = _validate_identifier(policy_id, "policy_id")
        if isinstance(revision, bool) or not isinstance(revision, int) or revision < 1:
            raise TeamStoreError("invalid_revision", "revision must be a positive integer")
        if (sha256 is None) != (byte_count is None):
            raise TeamStoreError(
                "incomplete_policy_subject",
                "sha256 and byte_count must be supplied together",
            )
        if sha256 is not None:
            _validate_sha256(sha256, "sha256")
        if byte_count is not None and (
            isinstance(byte_count, bool)
            or not isinstance(byte_count, int)
            or not 1 <= byte_count <= MAX_TEAM_ACCESS_POLICY_BYTES
        ):
            raise TeamStoreError(
                "invalid_byte_count",
                f"byte_count must be from 1 to {MAX_TEAM_ACCESS_POLICY_BYTES}",
            )

        with self._read_connection() as connection:
            row = connection.execute(
                """
                SELECT policy_bytes, byte_count, policy_sha256
                FROM team_policies
                WHERE tenant_id = ? AND policy_id = ? AND revision = ?
                """,
                (resolved_tenant, resolved_policy, revision),
            ).fetchone()
            if row is None:
                raise TeamStoreError(
                    "policy_not_found",
                    "the requested historical Team policy does not exist",
                )
            if sha256 is not None and (
                str(row["policy_sha256"]) != sha256 or int(row["byte_count"]) != byte_count
            ):
                raise TeamStoreError(
                    "policy_subject_mismatch",
                    "the requested historical policy does not match the supplied subject",
                )
            return _verified_blob(
                row["policy_bytes"],
                expected_byte_count=int(row["byte_count"]),
                expected_sha256=str(row["policy_sha256"]),
                record_name="policy",
            )

    def get_head(self, tenant_id: str) -> TeamLedgerHead:
        """Read the authoritative current ledger head for one tenant."""

        return self.get_tenant_snapshot(tenant_id).head

    def append_event(
        self,
        event_bytes: bytes,
        *,
        expected_head_sha256: str | None,
        require_active_policy: bool = False,
    ) -> TeamLedgerHead:
        """Verify and atomically append an event against the expected tenant head."""

        return self._append_event(
            event_bytes,
            expected_head_sha256=expected_head_sha256,
            require_active_policy=require_active_policy,
            case_record_bytes=None,
            investigation_record_bytes=None,
        )

    def append_case_record(
        self,
        event_bytes: bytes,
        case_record_bytes: bytes,
        *,
        expected_head_sha256: str | None,
        require_active_policy: bool = False,
    ) -> TeamLedgerHead:
        """Atomically append a successful event and its minimized case record."""

        return self._append_event(
            event_bytes,
            expected_head_sha256=expected_head_sha256,
            require_active_policy=require_active_policy,
            case_record_bytes=case_record_bytes,
            investigation_record_bytes=None,
        )

    def append_investigation_record(
        self,
        event_bytes: bytes,
        investigation_record_bytes: bytes,
        *,
        expected_head_sha256: str | None,
        require_active_policy: bool = False,
    ) -> TeamLedgerHead:
        """Atomically append a successful event and investigation queue revision."""

        return self._append_event(
            event_bytes,
            expected_head_sha256=expected_head_sha256,
            require_active_policy=require_active_policy,
            case_record_bytes=None,
            investigation_record_bytes=investigation_record_bytes,
        )

    def _append_event(
        self,
        event_bytes: bytes,
        *,
        expected_head_sha256: str | None,
        require_active_policy: bool,
        case_record_bytes: bytes | None,
        investigation_record_bytes: bytes | None,
    ) -> TeamLedgerHead:
        """Implement the shared event and optional indexed-record transaction."""

        event = parse_team_audit_event_bytes(event_bytes)
        if case_record_bytes is not None and investigation_record_bytes is not None:
            raise TeamStoreError(
                "indexed_record_ambiguous",
                "one audit event cannot append both a case and investigation record",
            )
        case_record: TeamCaseRecord | None = None
        if case_record_bytes is not None:
            try:
                case_record = parse_team_case_record_bytes(case_record_bytes)
            except (TypeError, ValueError) as exc:
                raise TeamStoreError(
                    "case_record_invalid",
                    "case_record_bytes do not satisfy the closed Team case contract",
                ) from exc
            authorization = event.entry.authorization
            if (
                case_record.tenant_id != event.entry.tenant_id
                or case_record.case_id != authorization.resource.resource_id
                or case_record.published_at != event.entry.occurred_at
                or not authorization.authorized
                or authorization.action is not TeamAction.INVESTIGATION_WRITE
                or authorization.resource.resource_type is not TeamResourceType.INVESTIGATION
                or event.entry.outcome is not TeamAuditOutcome.SUCCEEDED
                or event.entry.payload.media_type != TEAM_CASE_RECORD_MEDIA_TYPE
                or event.entry.payload.sha256 != _sha256(case_record_bytes)
                or event.entry.payload.byte_count != len(case_record_bytes)
            ):
                raise TeamStoreError(
                    "case_event_binding_invalid",
                    "case record does not match its successful investigation audit event",
                )
        investigation_record: TeamInvestigationRecord | None = None
        if investigation_record_bytes is not None:
            try:
                investigation_record = parse_team_investigation_record_bytes(
                    investigation_record_bytes
                )
            except (TypeError, ValueError) as exc:
                raise TeamStoreError(
                    "investigation_record_invalid",
                    "investigation_record_bytes do not satisfy the closed Team contract",
                ) from exc
            authorization = event.entry.authorization
            if (
                investigation_record.tenant_id != event.entry.tenant_id
                or investigation_record.investigation_id != authorization.resource.resource_id
                or investigation_record.updated_at != event.entry.occurred_at
                or not authorization.authorized
                or authorization.action is not TeamAction.INVESTIGATION_WRITE
                or authorization.resource.resource_type is not TeamResourceType.INVESTIGATION
                or event.entry.outcome is not TeamAuditOutcome.SUCCEEDED
                or event.entry.payload.media_type != TEAM_INVESTIGATION_RECORD_MEDIA_TYPE
                or event.entry.payload.sha256 != _sha256(investigation_record_bytes)
                or event.entry.payload.byte_count != len(investigation_record_bytes)
            ):
                raise TeamStoreError(
                    "investigation_event_binding_invalid",
                    "investigation record does not match its successful audit event",
                )
        if expected_head_sha256 is not None:
            _validate_sha256(expected_head_sha256, "expected_head_sha256")
        if not isinstance(require_active_policy, bool):
            raise TeamStoreError(
                "active_policy_requirement_invalid",
                "require_active_policy must be a boolean",
            )
        stored_at = utc_timestamp()

        with self._write_transaction() as connection:
            tenant = connection.execute(
                """
                SELECT
                    active_policy_id,
                    active_policy_revision,
                    active_policy_sha256,
                    active_policy_byte_count,
                    head_sequence,
                    head_event_sha256
                FROM team_tenants
                WHERE tenant_id = ?
                """,
                (event.entry.tenant_id,),
            ).fetchone()
            if tenant is None:
                raise TeamStoreError(
                    "tenant_not_found",
                    f"the Team tenant does not exist: {event.entry.tenant_id}",
                )
            current_sequence = int(tenant["head_sequence"])
            current_digest = (
                None if tenant["head_event_sha256"] is None else str(tenant["head_event_sha256"])
            )
            if current_digest != expected_head_sha256:
                raise TeamStoreConflictError(
                    "head_conflict",
                    "the expected tenant head is stale; reload it before creating a successor",
                )
            if current_sequence >= MAX_TEAM_EXPORT_EVENTS:
                raise TeamStoreConflictError(
                    "ledger_export_limit",
                    "this store revision supports at most "
                    f"{MAX_TEAM_EXPORT_EVENTS} events per tenant",
                )
            if (
                event.entry.sequence != current_sequence + 1
                or event.entry.previous_event_sha256 != current_digest
            ):
                raise TeamStoreConflictError(
                    "event_not_successor",
                    "the event is not the immediate successor of the authoritative tenant head",
                )
            if require_active_policy:
                subject = event.entry.authorization.policy
                if (
                    subject.policy_id,
                    subject.revision,
                    subject.sha256,
                    subject.byte_count,
                ) != (
                    str(tenant["active_policy_id"]),
                    int(tenant["active_policy_revision"]),
                    str(tenant["active_policy_sha256"]),
                    int(tenant["active_policy_byte_count"]),
                ):
                    raise TeamStoreConflictError(
                        "event_policy_stale",
                        "the event authorization no longer binds the active tenant policy",
                    )

            duplicate = connection.execute(
                """
                SELECT
                    EXISTS (
                        SELECT 1 FROM team_events
                        WHERE tenant_id = ? AND event_id = ?
                    ) AS event_id_exists,
                    EXISTS (
                        SELECT 1
                        FROM team_events
                        WHERE tenant_id = ? AND decision_id = ?
                        UNION ALL
                        SELECT 1
                        FROM team_exports
                        WHERE tenant_id = ? AND authorization_decision_id = ?
                    ) AS decision_id_exists,
                    EXISTS (
                        SELECT 1 FROM team_events
                        WHERE tenant_id = ? AND event_sha256 = ?
                    ) AS event_sha256_exists
                """,
                (
                    event.entry.tenant_id,
                    event.entry.event_id,
                    event.entry.tenant_id,
                    event.entry.authorization.decision_id,
                    event.entry.tenant_id,
                    event.entry.authorization.decision_id,
                    event.entry.tenant_id,
                    event.event_sha256,
                ),
            ).fetchone()
            if duplicate["event_id_exists"]:
                raise TeamStoreConflictError(
                    "duplicate_event_id",
                    "the event id already exists in this tenant ledger",
                )
            if duplicate["decision_id_exists"]:
                raise TeamStoreConflictError(
                    "duplicate_decision_id",
                    "the authorization decision id already exists in this tenant ledger",
                )
            if duplicate["event_sha256_exists"]:
                raise TeamStoreConflictError(
                    "duplicate_event_digest",
                    "the event digest already exists in this tenant ledger",
                )

            policy_bytes = self._policy_bytes_for_subject(
                connection,
                event.entry.tenant_id,
                event.entry.authorization.policy,
            )
            previous: TeamAuditEvent | None = None
            if current_sequence:
                previous_row = connection.execute(
                    """
                    SELECT event_bytes, byte_count, document_sha256
                    FROM team_events
                    WHERE tenant_id = ? AND sequence = ?
                    """,
                    (event.entry.tenant_id, current_sequence),
                ).fetchone()
                if previous_row is None:
                    raise TeamStoreSchemaError(
                        "ledger_head_orphaned",
                        "the tenant head does not resolve to a stored predecessor event",
                    )
                previous_bytes = _verified_blob(
                    previous_row["event_bytes"],
                    expected_byte_count=int(previous_row["byte_count"]),
                    expected_sha256=str(previous_row["document_sha256"]),
                    record_name="event",
                )
                previous = parse_team_audit_event_bytes(previous_bytes)
                if previous.event_sha256 != current_digest:
                    raise TeamStoreSchemaError(
                        "ledger_head_mismatch",
                        "the stored predecessor does not match the authoritative tenant head",
                    )
            verify_team_audit_event(policy_bytes, event, previous_event=previous)

            subject = event.entry.authorization.policy
            connection.execute(
                """
                INSERT INTO team_events (
                    tenant_id,
                    sequence,
                    event_id,
                    decision_id,
                    event_sha256,
                    previous_event_sha256,
                    policy_id,
                    policy_revision,
                    policy_sha256,
                    policy_byte_count,
                    occurred_at,
                    retain_until,
                    byte_count,
                    document_sha256,
                    stored_at,
                    event_bytes
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    event.entry.tenant_id,
                    event.entry.sequence,
                    event.entry.event_id,
                    event.entry.authorization.decision_id,
                    event.event_sha256,
                    event.entry.previous_event_sha256,
                    subject.policy_id,
                    subject.revision,
                    subject.sha256,
                    subject.byte_count,
                    event.entry.occurred_at,
                    event.entry.retention.retain_until,
                    len(event_bytes),
                    _sha256(event_bytes),
                    stored_at,
                    sqlite3.Binary(event_bytes),
                ),
            )
            if case_record is not None and case_record_bytes is not None:
                previous_case_row = connection.execute(
                    """
                    SELECT record_bytes, byte_count, record_sha256
                    FROM team_case_records
                    WHERE tenant_id = ? AND case_id = ?
                    ORDER BY revision DESC
                    LIMIT 1
                    """,
                    (case_record.tenant_id, case_record.case_id),
                ).fetchone()
                previous_case: TeamCaseRecord | None = None
                if previous_case_row is not None:
                    previous_case_bytes = _verified_blob(
                        previous_case_row["record_bytes"],
                        expected_byte_count=int(previous_case_row["byte_count"]),
                        expected_sha256=str(previous_case_row["record_sha256"]),
                        record_name="case record",
                    )
                    try:
                        previous_case = parse_team_case_record_bytes(previous_case_bytes)
                    except ValueError as exc:
                        raise TeamStoreSchemaError(
                            "stored_case_record_invalid",
                            "the previous stored case record violates its closed contract",
                        ) from exc
                try:
                    validate_team_case_successor(previous_case, case_record)
                except ValueError as exc:
                    raise TeamStoreConflictError(
                        "case_revision_conflict",
                        "the case record does not validly advance its stored predecessor",
                    ) from exc
                record_digest = _sha256(case_record_bytes)
                duplicate_case = connection.execute(
                    """
                    SELECT 1
                    FROM team_case_records
                    WHERE tenant_id = ? AND record_sha256 = ?
                    """,
                    (case_record.tenant_id, record_digest),
                ).fetchone()
                if duplicate_case is not None:
                    raise TeamStoreConflictError(
                        "duplicate_case_record",
                        "the exact case record already exists in this tenant",
                    )
                connection.execute(
                    """
                    INSERT INTO team_case_records (
                        tenant_id,
                        case_id,
                        revision,
                        published_at,
                        event_sequence,
                        event_sha256,
                        retain_until,
                        record_sha256,
                        byte_count,
                        stored_at,
                        record_bytes
                    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                    """,
                    (
                        case_record.tenant_id,
                        case_record.case_id,
                        case_record.revision,
                        case_record.published_at,
                        event.entry.sequence,
                        event.event_sha256,
                        event.entry.retention.retain_until,
                        record_digest,
                        len(case_record_bytes),
                        stored_at,
                        sqlite3.Binary(case_record_bytes),
                    ),
                )
            if investigation_record is not None and investigation_record_bytes is not None:
                previous_investigation_row = connection.execute(
                    """
                    SELECT record_bytes, byte_count, record_sha256
                    FROM team_investigation_records
                    WHERE tenant_id = ? AND investigation_id = ?
                    ORDER BY revision DESC
                    LIMIT 1
                    """,
                    (
                        investigation_record.tenant_id,
                        investigation_record.investigation_id,
                    ),
                ).fetchone()
                previous_investigation: TeamInvestigationRecord | None = None
                if previous_investigation_row is not None:
                    previous_investigation_bytes = _verified_blob(
                        previous_investigation_row["record_bytes"],
                        expected_byte_count=int(previous_investigation_row["byte_count"]),
                        expected_sha256=str(previous_investigation_row["record_sha256"]),
                        record_name="investigation record",
                    )
                    try:
                        previous_investigation = parse_team_investigation_record_bytes(
                            previous_investigation_bytes
                        )
                    except ValueError as exc:
                        raise TeamStoreSchemaError(
                            "stored_investigation_record_invalid",
                            "the previous stored investigation violates its contract",
                        ) from exc
                try:
                    validate_team_investigation_successor(
                        previous_investigation,
                        investigation_record,
                    )
                except ValueError as exc:
                    raise TeamStoreConflictError(
                        "investigation_revision_conflict",
                        "the investigation record does not validly advance its predecessor",
                    ) from exc
                if investigation_record.linked_case_id is not None:
                    linked_case = connection.execute(
                        """
                        SELECT 1
                        FROM team_case_records
                        WHERE tenant_id = ? AND case_id = ?
                        LIMIT 1
                        """,
                        (
                            investigation_record.tenant_id,
                            investigation_record.linked_case_id,
                        ),
                    ).fetchone()
                    if linked_case is None:
                        raise TeamStoreConflictError(
                            "investigation_linked_case_missing",
                            "the linked case does not exist in this tenant",
                        )
                if investigation_record.duplicate_of is not None:
                    duplicate_target = connection.execute(
                        """
                        SELECT 1
                        FROM team_investigation_records
                        WHERE tenant_id = ? AND investigation_id = ?
                        LIMIT 1
                        """,
                        (
                            investigation_record.tenant_id,
                            investigation_record.duplicate_of,
                        ),
                    ).fetchone()
                    if duplicate_target is None:
                        raise TeamStoreConflictError(
                            "investigation_duplicate_target_missing",
                            "the duplicate target does not exist in this tenant",
                        )
                record_digest = _sha256(investigation_record_bytes)
                duplicate_record = connection.execute(
                    """
                    SELECT 1
                    FROM team_investigation_records
                    WHERE tenant_id = ? AND record_sha256 = ?
                    """,
                    (investigation_record.tenant_id, record_digest),
                ).fetchone()
                if duplicate_record is not None:
                    raise TeamStoreConflictError(
                        "duplicate_investigation_record",
                        "the exact investigation record already exists in this tenant",
                    )
                assigned_identity_provider = (
                    None
                    if investigation_record.assigned_to is None
                    else investigation_record.assigned_to.identity_provider
                )
                assigned_subject_id = (
                    None
                    if investigation_record.assigned_to is None
                    else investigation_record.assigned_to.subject_id
                )
                connection.execute(
                    """
                    INSERT INTO team_investigation_records (
                        tenant_id,
                        investigation_id,
                        revision,
                        created_at,
                        updated_at,
                        status,
                        priority,
                        assigned_identity_provider,
                        assigned_subject_id,
                        resolution,
                        linked_case_id,
                        duplicate_of,
                        observation_count,
                        event_sequence,
                        event_sha256,
                        retain_until,
                        record_sha256,
                        byte_count,
                        stored_at,
                        record_bytes
                    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                    """,
                    (
                        investigation_record.tenant_id,
                        investigation_record.investigation_id,
                        investigation_record.revision,
                        investigation_record.created_at,
                        investigation_record.updated_at,
                        investigation_record.status.value,
                        investigation_record.priority.value,
                        assigned_identity_provider,
                        assigned_subject_id,
                        (
                            None
                            if investigation_record.resolution is None
                            else investigation_record.resolution.value
                        ),
                        investigation_record.linked_case_id,
                        investigation_record.duplicate_of,
                        len(investigation_record.observations),
                        event.entry.sequence,
                        event.event_sha256,
                        event.entry.retention.retain_until,
                        record_digest,
                        len(investigation_record_bytes),
                        stored_at,
                        sqlite3.Binary(investigation_record_bytes),
                    ),
                )
            updated = connection.execute(
                """
                UPDATE team_tenants
                SET head_sequence = ?,
                    head_event_sha256 = ?,
                    updated_at = ?
                WHERE tenant_id = ?
                  AND head_sequence = ?
                  AND head_event_sha256 IS ?
                """,
                (
                    event.entry.sequence,
                    event.event_sha256,
                    stored_at,
                    event.entry.tenant_id,
                    current_sequence,
                    current_digest,
                ),
            )
            if updated.rowcount != 1:
                raise TeamStoreConflictError(
                    "head_conflict",
                    "the tenant head changed before the event could be committed",
                )

        return TeamLedgerHead(
            tenant_id=event.entry.tenant_id,
            sequence=event.entry.sequence,
            event_sha256=event.event_sha256,
        )

    def get_event_bytes(self, tenant_id: str, sequence: int) -> bytes:
        """Return the exact stored bytes for one tenant event."""

        snapshot = self.get_tenant_snapshot(tenant_id, event_sequence=sequence)
        if snapshot.event_bytes is None:
            raise TeamStoreError(
                "event_not_found",
                "the requested Team audit event does not exist",
            )
        return snapshot.event_bytes

    def list_event_bytes(self, tenant_id: str) -> tuple[bytes, ...]:
        """Return one tenant's exact stored event bytes in ledger order."""

        resolved_tenant = _validate_identifier(tenant_id, "tenant_id")
        with self._read_connection() as connection:
            tenant = connection.execute(
                "SELECT 1 FROM team_tenants WHERE tenant_id = ?",
                (resolved_tenant,),
            ).fetchone()
            if tenant is None:
                raise TeamStoreError(
                    "tenant_not_found",
                    f"the Team tenant does not exist: {resolved_tenant}",
                )
            rows = connection.execute(
                """
                SELECT event_bytes, byte_count, document_sha256
                FROM team_events
                WHERE tenant_id = ?
                ORDER BY sequence
                """,
                (resolved_tenant,),
            ).fetchall()
            return tuple(
                _verified_blob(
                    row["event_bytes"],
                    expected_byte_count=int(row["byte_count"]),
                    expected_sha256=str(row["document_sha256"]),
                    record_name="event",
                )
                for row in rows
            )

    def _verified_event_rows(
        self,
        connection: sqlite3.Connection,
        tenant_id: str,
    ) -> tuple[list[bytes], list[TeamAuditEvent]]:
        rows = connection.execute(
            """
            SELECT event_bytes, byte_count, document_sha256
            FROM team_events
            WHERE tenant_id = ?
            ORDER BY sequence
            """,
            (tenant_id,),
        ).fetchall()
        raw_events: list[bytes] = []
        events: list[TeamAuditEvent] = []
        previous: TeamAuditEvent | None = None
        policy_cache: dict[tuple[str, int, str, int], bytes] = {}
        for row in rows:
            raw_bytes = _verified_blob(
                row["event_bytes"],
                expected_byte_count=int(row["byte_count"]),
                expected_sha256=str(row["document_sha256"]),
                record_name="event",
            )
            event = parse_team_audit_event_bytes(raw_bytes)
            subject = event.entry.authorization.policy
            cache_key = (
                subject.policy_id,
                subject.revision,
                subject.sha256,
                subject.byte_count,
            )
            policy_bytes = policy_cache.get(cache_key)
            if policy_bytes is None:
                policy_bytes = self._policy_bytes_for_subject(connection, tenant_id, subject)
                policy_cache[cache_key] = policy_bytes
            verify_team_audit_event(policy_bytes, event, previous_event=previous)
            raw_events.append(raw_bytes)
            events.append(event)
            previous = event
        return raw_events, events

    def create_export(
        self,
        authorization_bytes: bytes,
        *,
        export_id: str,
        created_at: str | None = None,
    ) -> TeamAuditExport:
        """Create and persist a complete export at one protected tenant snapshot."""

        resolved_export_id = _validate_identifier(export_id, "export_id")
        authorization = parse_team_authorization_bytes(authorization_bytes)
        creation_time = _validate_timestamp(created_at or utc_timestamp(), "created_at")
        stored_at = utc_timestamp()

        with self._write_transaction() as connection:
            tenant = connection.execute(
                """
                SELECT
                    active_policy_id,
                    active_policy_revision,
                    active_policy_sha256,
                    active_policy_byte_count,
                    head_sequence,
                    head_event_sha256
                FROM team_tenants
                WHERE tenant_id = ?
                """,
                (authorization.tenant_id,),
            ).fetchone()
            if tenant is None:
                raise TeamStoreError(
                    "tenant_not_found",
                    f"the Team tenant does not exist: {authorization.tenant_id}",
                )
            subject = authorization.policy
            active_subject = (
                str(tenant["active_policy_id"]),
                int(tenant["active_policy_revision"]),
                str(tenant["active_policy_sha256"]),
                int(tenant["active_policy_byte_count"]),
            )
            authorization_subject = (
                subject.policy_id,
                subject.revision,
                subject.sha256,
                subject.byte_count,
            )
            if authorization_subject != active_subject:
                raise TeamStoreConflictError(
                    "export_policy_stale",
                    "export authorization must bind the tenant's active policy snapshot",
                )
            head_sequence = int(tenant["head_sequence"])
            head_digest = (
                None if tenant["head_event_sha256"] is None else str(tenant["head_event_sha256"])
            )
            if head_sequence == 0 or head_digest is None:
                raise TeamStoreError(
                    "ledger_empty",
                    "a complete audit export requires at least one stored event",
                )
            if head_sequence > MAX_TEAM_EXPORT_EVENTS:
                raise TeamStoreError(
                    "ledger_export_limit",
                    f"this export format supports at most {MAX_TEAM_EXPORT_EVENTS} events",
                )

            duplicate = connection.execute(
                """
                SELECT
                    EXISTS (
                        SELECT 1 FROM team_exports
                        WHERE tenant_id = ? AND export_id = ?
                    ) AS export_id_exists,
                    EXISTS (
                        SELECT 1
                        FROM team_exports
                        WHERE tenant_id = ? AND authorization_decision_id = ?
                        UNION ALL
                        SELECT 1
                        FROM team_events
                        WHERE tenant_id = ? AND decision_id = ?
                    ) AS decision_id_exists
                """,
                (
                    authorization.tenant_id,
                    resolved_export_id,
                    authorization.tenant_id,
                    authorization.decision_id,
                    authorization.tenant_id,
                    authorization.decision_id,
                ),
            ).fetchone()
            if duplicate["export_id_exists"]:
                raise TeamStoreConflictError(
                    "duplicate_export_id",
                    "the export id already exists for this tenant",
                )
            if duplicate["decision_id_exists"]:
                raise TeamStoreConflictError(
                    "duplicate_export_decision_id",
                    "the export authorization decision was already used",
                )

            policy_bytes = self._policy_bytes_for_subject(
                connection,
                authorization.tenant_id,
                subject,
            )
            raw_events, events = self._verified_event_rows(
                connection,
                authorization.tenant_id,
            )
            if len(events) != head_sequence or events[-1].event_sha256 != head_digest:
                raise TeamStoreSchemaError(
                    "ledger_head_mismatch",
                    "the authoritative tenant head does not match its complete stored chain",
                )
            export = create_team_audit_export(
                policy_bytes,
                authorization_bytes,
                raw_events,
                export_id=resolved_export_id,
                authoritative_head_sha256=head_digest,
                created_at=creation_time,
            )
            export_bytes = render_team_audit_export(export).encode("utf-8")
            connection.execute(
                """
                INSERT INTO team_exports (
                    tenant_id,
                    export_id,
                    authorization_decision_id,
                    head_sequence,
                    head_event_sha256,
                    policy_id,
                    policy_revision,
                    policy_sha256,
                    policy_byte_count,
                    created_at,
                    retain_until,
                    byte_count,
                    document_sha256,
                    stored_at,
                    export_bytes
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    export.tenant_id,
                    export.export_id,
                    export.authorization.decision_id,
                    export.audit_range.last_sequence,
                    export.head_event_sha256,
                    subject.policy_id,
                    subject.revision,
                    subject.sha256,
                    subject.byte_count,
                    export.created_at,
                    export.retention.retain_until,
                    len(export_bytes),
                    _sha256(export_bytes),
                    stored_at,
                    sqlite3.Binary(export_bytes),
                ),
            )
        return export

    def get_export_bytes(self, tenant_id: str, export_id: str) -> bytes:
        """Return the exact stored bytes of a complete Team audit export."""

        resolved_tenant = _validate_identifier(tenant_id, "tenant_id")
        resolved_export = _validate_identifier(export_id, "export_id")
        with self._read_connection() as connection:
            row = connection.execute(
                """
                SELECT export_bytes, byte_count, document_sha256
                FROM team_exports
                WHERE tenant_id = ? AND export_id = ?
                """,
                (resolved_tenant, resolved_export),
            ).fetchone()
            if row is None:
                raise TeamStoreError(
                    "export_not_found",
                    "the requested Team audit export does not exist",
                )
            return _verified_blob(
                row["export_bytes"],
                expected_byte_count=int(row["byte_count"]),
                expected_sha256=str(row["document_sha256"]),
                record_name="export",
            )

    def backup(self, destination_path: str | os.PathLike[str]) -> Path:
        """Create a consistent online backup without overwriting an existing path."""

        destination = Path(os.fspath(destination_path))
        if self._path.resolve() == destination.resolve():
            raise TeamStoreError(
                "backup_path_collision",
                "the backup destination must differ from the source database",
            )
        if not destination.parent.is_dir():
            raise TeamStoreError(
                "backup_parent_missing",
                f"the backup parent directory does not exist: {destination.parent}",
            )
        try:
            reservation = os.open(
                destination,
                os.O_CREAT | os.O_EXCL | os.O_WRONLY,
                0o600,
            )
        except FileExistsError as exc:
            raise TeamStoreError(
                "backup_exists",
                f"refusing to overwrite an existing backup: {destination}",
            ) from exc
        except OSError as exc:
            raise TeamStoreError(
                "backup_open_failed",
                f"could not reserve the backup destination: {exc}",
            ) from exc
        else:
            os.close(reservation)

        temporary = destination.with_name(f".{destination.name}.{uuid.uuid4().hex}.tmp")
        temporary_sidecars = (
            temporary.with_name(f"{temporary.name}-wal"),
            temporary.with_name(f"{temporary.name}-shm"),
        )
        try:
            with self._read_connection() as source:
                target = sqlite3.connect(temporary, isolation_level=None)
                try:
                    source.backup(target)
                finally:
                    target.close()
            probe = SQLiteTeamStore(
                temporary,
                busy_timeout_ms=self._busy_timeout_ms,
            )
            with probe._read_connection():
                pass
            os.replace(temporary, destination)
            return destination
        except TeamStoreError:
            raise
        except (OSError, sqlite3.Error) as exc:
            if isinstance(exc, sqlite3.Error):
                raise _translate_sqlite_error(exc) from exc
            raise TeamStoreError("backup_failed", str(exc)) from exc
        finally:
            for path in (temporary, *temporary_sidecars):
                try:
                    path.unlink()
                except FileNotFoundError:
                    pass
            if temporary.exists():
                try:
                    temporary.unlink()
                except OSError:
                    pass
            if destination.exists() and destination.stat().st_size == 0:
                try:
                    destination.unlink()
                except OSError:
                    pass
