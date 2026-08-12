"""Team-service tenant authorization and audit-chain tests."""

from __future__ import annotations

import copy
import json
import unittest
from dataclasses import replace

from causure.constants import (
    TeamAction,
    TeamAuditOutcome,
    TeamAuthorizationReason,
    TeamResourceType,
    TeamRole,
)
from causure.models import to_jsonable
from causure.team_service import (
    TeamAuditVerificationError,
    TeamAuthorizationError,
    TeamValidationError,
    create_team_audit_event,
    create_team_audit_export,
    create_team_authorization,
    parse_team_access_policy,
    parse_team_access_policy_bytes,
    parse_team_audit_event_bytes,
    parse_team_audit_export_bytes,
    parse_team_audit_verification,
    parse_team_authorization,
    parse_team_authorization_bytes,
    render_team_audit_event,
    render_team_audit_export,
    render_team_audit_verification,
    render_team_authorization,
    verify_team_audit_event,
    verify_team_audit_export,
    verify_team_authorization,
)


def _policy_document(
    *,
    tenant_id: str = "tenant-acme",
    policy_id: str = "access-acme",
    revision: int = 1,
) -> dict:
    return {
        "schema_version": "1.0",
        "tenant_id": tenant_id,
        "policy_id": policy_id,
        "revision": revision,
        "effective_at": "2026-07-01T00:00:00Z",
        "default_retention_class_id": "audit-365",
        "memberships": [
            {
                "principal": {
                    "identity_provider": "entra:contoso",
                    "subject_id": "alice-investigator",
                },
                "roles": ["investigator"],
            },
            {
                "principal": {
                    "identity_provider": "entra:contoso",
                    "subject_id": "pat-policy",
                },
                "roles": ["policy_administrator"],
            },
            {
                "principal": {
                    "identity_provider": "entra:contoso",
                    "subject_id": "ava-approver",
                },
                "roles": ["approver"],
            },
        ],
        "retention_classes": [
            {"class_id": "audit-365", "minimum_days": 365},
            {"class_id": "incident-30", "minimum_days": 30},
        ],
    }


def _policy_bytes(**kwargs: object) -> bytes:
    return (json.dumps(_policy_document(**kwargs), ensure_ascii=False, indent=2) + "\n").encode()


def _authorization_bytes(
    policy_bytes: bytes,
    *,
    decision_id: str,
    subject_id: str,
    action: TeamAction,
    resource_type: TeamResourceType,
    resource_id: str,
    decided_at: str,
) -> bytes:
    decision = create_team_authorization(
        policy_bytes,
        decision_id=decision_id,
        identity_provider="entra:contoso",
        subject_id=subject_id,
        action=action,
        resource_type=resource_type,
        resource_id=resource_id,
        decided_at=decided_at,
    )
    return render_team_authorization(decision).encode()


class TeamAuthorizationTests(unittest.TestCase):
    def test_roles_allow_only_declared_actions(self) -> None:
        policy_bytes = _policy_bytes()
        allowed = create_team_authorization(
            policy_bytes,
            decision_id="decision-allow",
            identity_provider="entra:contoso",
            subject_id="alice-investigator",
            action=TeamAction.INVESTIGATION_WRITE,
            resource_type=TeamResourceType.INVESTIGATION,
            resource_id="investigation-17",
            decided_at="2026-07-28T10:00:00Z",
        )
        denied = create_team_authorization(
            policy_bytes,
            decision_id="decision-deny",
            identity_provider="entra:contoso",
            subject_id="alice-investigator",
            action=TeamAction.APPROVAL_ISSUE,
            resource_type=TeamResourceType.APPROVAL,
            resource_id="approval-17",
            decided_at="2026-07-28T10:00:00Z",
        )
        outsider = create_team_authorization(
            policy_bytes,
            decision_id="decision-outsider",
            identity_provider="entra:contoso",
            subject_id="mallory-outsider",
            action=TeamAction.EVIDENCE_READ,
            resource_type=TeamResourceType.EVIDENCE_CASE,
            resource_id="case-17",
            decided_at="2026-07-28T10:00:00Z",
        )

        self.assertTrue(allowed.authorized)
        self.assertEqual((TeamRole.INVESTIGATOR,), allowed.assigned_roles)
        self.assertEqual((TeamRole.INVESTIGATOR,), allowed.granting_roles)
        self.assertIs(TeamAuthorizationReason.ROLE_GRANT, allowed.reason)
        self.assertFalse(denied.authorized)
        self.assertEqual((TeamRole.INVESTIGATOR,), denied.assigned_roles)
        self.assertEqual((), denied.granting_roles)
        self.assertIs(TeamAuthorizationReason.ROLE_NOT_GRANTED, denied.reason)
        self.assertFalse(outsider.authorized)
        self.assertIs(
            TeamAuthorizationReason.PRINCIPAL_NOT_MEMBER,
            outsider.reason,
        )

    def test_action_resource_pairs_are_closed(self) -> None:
        with self.assertRaisesRegex(
            TeamValidationError,
            "investigation_write requires resource type: investigation",
        ):
            create_team_authorization(
                _policy_bytes(),
                decision_id="decision-wrong-resource",
                identity_provider="entra:contoso",
                subject_id="alice-investigator",
                action=TeamAction.INVESTIGATION_WRITE,
                resource_type=TeamResourceType.GATE_POLICY,
                resource_id="policy-17",
                decided_at="2026-07-28T10:00:00Z",
            )

    def test_exact_policy_and_role_result_are_reproduced(self) -> None:
        policy_bytes = _policy_bytes()
        decision = create_team_authorization(
            policy_bytes,
            decision_id="decision-exact",
            identity_provider="entra:contoso",
            subject_id="ava-approver",
            action=TeamAction.APPROVAL_ISSUE,
            resource_type=TeamResourceType.APPROVAL,
            resource_id="approval-17",
            decided_at="2026-07-28T10:00:00Z",
        )
        self.assertEqual(decision, verify_team_authorization(policy_bytes, decision))

        semantically_equal_but_different_bytes = json.dumps(
            _policy_document(),
            separators=(",", ":"),
        ).encode()
        with self.assertRaisesRegex(
            TeamAuthorizationError,
            "policy_subject_mismatch",
        ):
            verify_team_authorization(semantically_equal_but_different_bytes, decision)

        forged = replace(
            create_team_authorization(
                policy_bytes,
                decision_id="decision-forged",
                identity_provider="entra:contoso",
                subject_id="alice-investigator",
                action=TeamAction.APPROVAL_ISSUE,
                resource_type=TeamResourceType.APPROVAL,
                resource_id="approval-18",
                decided_at="2026-07-28T10:00:00Z",
            ),
            authorized=True,
            granting_roles=(TeamRole.INVESTIGATOR,),
            reason=TeamAuthorizationReason.ROLE_GRANT,
        )
        with self.assertRaisesRegex(TeamAuthorizationError, "decision_mismatch"):
            verify_team_authorization(policy_bytes, forged)

    def test_policy_rejects_duplicate_members_and_duplicate_json_keys(self) -> None:
        duplicate_member = _policy_document()
        duplicate_member["memberships"].append(copy.deepcopy(duplicate_member["memberships"][0]))
        with self.assertRaisesRegex(TeamValidationError, "membership must be unique"):
            parse_team_access_policy(duplicate_member)

        duplicate_key = b'{"schema_version":"1.0","schema_version":"1.0"}'
        with self.assertRaisesRegex(TeamValidationError, "duplicate JSON key"):
            parse_team_access_policy_bytes(duplicate_key)

    def test_authorization_parser_rejects_inconsistent_denial(self) -> None:
        decision = create_team_authorization(
            _policy_bytes(),
            decision_id="decision-inconsistent",
            identity_provider="entra:contoso",
            subject_id="alice-investigator",
            action=TeamAction.APPROVAL_ISSUE,
            resource_type=TeamResourceType.APPROVAL,
            resource_id="approval-17",
            decided_at="2026-07-28T10:00:00Z",
        )
        document = to_jsonable(decision)
        document["granting_roles"] = ["investigator"]
        with self.assertRaisesRegex(
            TeamValidationError,
            "denied decision cannot contain a granting role",
        ):
            parse_team_authorization(document)


class TeamAuditTests(unittest.TestCase):
    def _event_chain(self) -> tuple[bytes, bytes, bytes]:
        policy_bytes = _policy_bytes()
        first_authorization = _authorization_bytes(
            policy_bytes,
            decision_id="decision-event-1",
            subject_id="alice-investigator",
            action=TeamAction.INVESTIGATION_WRITE,
            resource_type=TeamResourceType.INVESTIGATION,
            resource_id="investigation-17",
            decided_at="2026-07-28T10:00:00Z",
        )
        first = create_team_audit_event(
            policy_bytes,
            first_authorization,
            b'{"status":"opened"}',
            payload_media_type="application/json",
            event_id="event-1",
            outcome=TeamAuditOutcome.SUCCEEDED,
            occurred_at="2026-07-28T10:01:00Z",
        )
        first_bytes = render_team_audit_event(first).encode()

        second_authorization = _authorization_bytes(
            policy_bytes,
            decision_id="decision-event-2",
            subject_id="ava-approver",
            action=TeamAction.APPROVAL_ISSUE,
            resource_type=TeamResourceType.APPROVAL,
            resource_id="approval-17",
            decided_at="2026-07-28T10:02:00Z",
        )
        second = create_team_audit_event(
            policy_bytes,
            second_authorization,
            b'{"status":"recorded"}',
            payload_media_type="application/json",
            event_id="event-2",
            outcome=TeamAuditOutcome.SUCCEEDED,
            occurred_at="2026-07-28T10:03:00Z",
            previous_event_bytes=first_bytes,
        )
        return policy_bytes, first_bytes, render_team_audit_event(second).encode()

    def test_hash_chain_export_and_receipt_verify(self) -> None:
        policy_bytes, first_bytes, second_bytes = self._event_chain()
        first = parse_team_audit_event_bytes(first_bytes)
        second = parse_team_audit_event_bytes(second_bytes)

        self.assertEqual(first.event_sha256, second.entry.previous_event_sha256)
        self.assertEqual(first, verify_team_audit_event(policy_bytes, first))
        self.assertEqual(
            second,
            verify_team_audit_event(policy_bytes, second, previous_event=first),
        )

        export_authorization = _authorization_bytes(
            policy_bytes,
            decision_id="decision-export-1",
            subject_id="pat-policy",
            action=TeamAction.AUDIT_EXPORT,
            resource_type=TeamResourceType.AUDIT_EXPORT,
            resource_id="export-17",
            decided_at="2026-07-28T10:04:00Z",
        )
        export = create_team_audit_export(
            policy_bytes,
            export_authorization,
            [first_bytes, second_bytes],
            export_id="export-17",
            authoritative_head_sha256=second.event_sha256,
            created_at="2026-07-28T10:05:00Z",
        )
        export_bytes = render_team_audit_export(export).encode()
        verification = verify_team_audit_export(
            export_bytes,
            policy_bytes,
            checked_at="2026-07-28T10:06:00Z",
        )
        receipt = parse_team_audit_verification(
            json.loads(render_team_audit_verification(verification))
        )

        self.assertEqual(2, export.audit_range.event_count)
        self.assertEqual(second.event_sha256, export.head_event_sha256)
        self.assertEqual("verified", receipt.status)
        self.assertEqual("pat-policy", receipt.exporter.subject_id)
        self.assertEqual(export.head_event_sha256, receipt.head_event_sha256)
        self.assertEqual(export, parse_team_audit_export_bytes(export_bytes))

    def test_denied_action_can_only_be_recorded_as_denied(self) -> None:
        policy_bytes = _policy_bytes()
        denied_authorization = _authorization_bytes(
            policy_bytes,
            decision_id="decision-denied-event",
            subject_id="alice-investigator",
            action=TeamAction.APPROVAL_ISSUE,
            resource_type=TeamResourceType.APPROVAL,
            resource_id="approval-17",
            decided_at="2026-07-28T10:00:00Z",
        )
        denied = create_team_audit_event(
            policy_bytes,
            denied_authorization,
            b'{"request":"approval-17"}',
            payload_media_type="application/json",
            event_id="event-denied",
            outcome=TeamAuditOutcome.DENIED,
            occurred_at="2026-07-28T10:01:00Z",
        )
        self.assertIs(TeamAuditOutcome.DENIED, denied.entry.outcome)
        self.assertFalse(denied.entry.authorization.authorized)

        with self.assertRaisesRegex(
            TeamValidationError,
            "unauthorized action must use denied",
        ):
            create_team_audit_event(
                policy_bytes,
                denied_authorization,
                b'{"request":"approval-17"}',
                payload_media_type="application/json",
                event_id="event-false-success",
                outcome=TeamAuditOutcome.SUCCEEDED,
                occurred_at="2026-07-28T10:01:00Z",
            )

    def test_event_rejects_stale_authorization_and_short_retention(self) -> None:
        policy_bytes = _policy_bytes()
        authorization = _authorization_bytes(
            policy_bytes,
            decision_id="decision-stale",
            subject_id="alice-investigator",
            action=TeamAction.INVESTIGATION_WRITE,
            resource_type=TeamResourceType.INVESTIGATION,
            resource_id="investigation-17",
            decided_at="2026-07-28T10:00:00Z",
        )
        with self.assertRaisesRegex(TeamValidationError, "authorization decision is too old"):
            create_team_audit_event(
                policy_bytes,
                authorization,
                b"{}",
                payload_media_type="application/json",
                event_id="event-stale",
                outcome=TeamAuditOutcome.SUCCEEDED,
                occurred_at="2026-07-28T10:16:00Z",
            )
        with self.assertRaisesRegex(TeamValidationError, "at least 365 day"):
            create_team_audit_event(
                policy_bytes,
                authorization,
                b"{}",
                payload_media_type="application/json",
                event_id="event-short-retention",
                outcome=TeamAuditOutcome.SUCCEEDED,
                occurred_at="2026-07-28T10:01:00Z",
                retain_until="2026-08-28T10:01:00Z",
            )

    def test_tampering_and_cross_tenant_predecessors_fail(self) -> None:
        policy_bytes, first_bytes, _ = self._event_chain()
        tampered = json.loads(first_bytes)
        tampered["entry"]["payload"]["sha256"] = "0" * 64
        with self.assertRaisesRegex(TeamValidationError, "canonical audit entry"):
            parse_team_audit_event_bytes(json.dumps(tampered).encode())

        other_policy = _policy_bytes(
            tenant_id="tenant-beta",
            policy_id="access-beta",
        )
        other_authorization = _authorization_bytes(
            other_policy,
            decision_id="decision-beta",
            subject_id="alice-investigator",
            action=TeamAction.INVESTIGATION_WRITE,
            resource_type=TeamResourceType.INVESTIGATION,
            resource_id="investigation-beta",
            decided_at="2026-07-28T10:02:00Z",
        )
        with self.assertRaisesRegex(TeamValidationError, "different tenant"):
            create_team_audit_event(
                other_policy,
                other_authorization,
                b"{}",
                payload_media_type="application/json",
                event_id="event-beta",
                outcome=TeamAuditOutcome.SUCCEEDED,
                occurred_at="2026-07-28T10:03:00Z",
                previous_event_bytes=first_bytes,
            )
        self.assertEqual("tenant-acme", parse_team_access_policy_bytes(policy_bytes).tenant_id)

    def test_export_requires_policy_admin_and_complete_chain(self) -> None:
        policy_bytes, first_bytes, second_bytes = self._event_chain()
        denied_export_authorization = _authorization_bytes(
            policy_bytes,
            decision_id="decision-export-denied",
            subject_id="alice-investigator",
            action=TeamAction.AUDIT_EXPORT,
            resource_type=TeamResourceType.AUDIT_EXPORT,
            resource_id="export-denied",
            decided_at="2026-07-28T10:04:00Z",
        )
        with self.assertRaisesRegex(
            TeamValidationError,
            "authorized audit_export decision",
        ):
            create_team_audit_export(
                policy_bytes,
                denied_export_authorization,
                [first_bytes, second_bytes],
                export_id="export-denied",
                authoritative_head_sha256=parse_team_audit_event_bytes(second_bytes).event_sha256,
                created_at="2026-07-28T10:05:00Z",
            )

        allowed_export_authorization = _authorization_bytes(
            policy_bytes,
            decision_id="decision-export-partial",
            subject_id="pat-policy",
            action=TeamAction.AUDIT_EXPORT,
            resource_type=TeamResourceType.AUDIT_EXPORT,
            resource_id="export-partial",
            decided_at="2026-07-28T10:04:00Z",
        )
        with self.assertRaisesRegex(TeamValidationError, "begin at sequence 1"):
            create_team_audit_export(
                policy_bytes,
                allowed_export_authorization,
                [second_bytes],
                export_id="export-partial",
                authoritative_head_sha256=parse_team_audit_event_bytes(second_bytes).event_sha256,
                created_at="2026-07-28T10:05:00Z",
            )

        with self.assertRaisesRegex(TeamValidationError, "authoritative tenant head"):
            create_team_audit_export(
                policy_bytes,
                allowed_export_authorization,
                [first_bytes, second_bytes],
                export_id="export-partial",
                authoritative_head_sha256="0" * 64,
                created_at="2026-07-28T10:05:00Z",
            )

        first = parse_team_audit_event_bytes(first_bytes)
        with self.assertRaisesRegex(TeamValidationError, "event ids must be unique"):
            create_team_audit_export(
                policy_bytes,
                allowed_export_authorization,
                [first_bytes, first_bytes],
                export_id="export-partial",
                authoritative_head_sha256=first.event_sha256,
                created_at="2026-07-28T10:05:00Z",
            )

        repeated_decision_event = create_team_audit_event(
            policy_bytes,
            render_team_authorization(first.entry.authorization).encode(),
            b'{"status":"updated"}',
            payload_media_type="application/json",
            event_id="event-reused-decision",
            outcome=TeamAuditOutcome.SUCCEEDED,
            occurred_at="2026-07-28T10:02:00Z",
            previous_event_bytes=first_bytes,
        )
        repeated_decision_bytes = render_team_audit_event(repeated_decision_event).encode()
        with self.assertRaisesRegex(
            TeamValidationError,
            "authorization decision ids must be unique",
        ):
            create_team_audit_export(
                policy_bytes,
                allowed_export_authorization,
                [first_bytes, repeated_decision_bytes],
                export_id="export-partial",
                authoritative_head_sha256=repeated_decision_event.event_sha256,
                created_at="2026-07-28T10:05:00Z",
            )

    def test_export_exact_bytes_and_policy_are_verified(self) -> None:
        policy_bytes, first_bytes, second_bytes = self._event_chain()
        export_authorization = _authorization_bytes(
            policy_bytes,
            decision_id="decision-export-exact",
            subject_id="pat-policy",
            action=TeamAction.AUDIT_EXPORT,
            resource_type=TeamResourceType.AUDIT_EXPORT,
            resource_id="export-exact",
            decided_at="2026-07-28T10:04:00Z",
        )
        export = create_team_audit_export(
            policy_bytes,
            export_authorization,
            [first_bytes, second_bytes],
            export_id="export-exact",
            authoritative_head_sha256=parse_team_audit_event_bytes(second_bytes).event_sha256,
            created_at="2026-07-28T10:05:00Z",
        )
        export_bytes = render_team_audit_export(export).encode()
        different_policy_bytes = (
            json.dumps(_policy_document(), separators=(",", ":")) + "\n"
        ).encode()

        with self.assertRaisesRegex(
            TeamAuditVerificationError,
            "authorization_invalid",
        ):
            verify_team_audit_export(
                export_bytes,
                different_policy_bytes,
                checked_at="2026-07-28T10:06:00Z",
            )

        tampered_export = json.loads(export_bytes)
        tampered_export["events"][0]["entry"]["payload"]["sha256"] = "0" * 64
        with self.assertRaisesRegex(TeamAuditVerificationError, "export_invalid"):
            verify_team_audit_export(
                json.dumps(tampered_export).encode(),
                policy_bytes,
                checked_at="2026-07-28T10:06:00Z",
            )
        with self.assertRaisesRegex(ValueError, "integer from 0 to 3600"):
            verify_team_audit_export(
                export_bytes,
                policy_bytes,
                checked_at="2026-07-28T10:06:00Z",
                clock_skew_seconds=1.5,  # type: ignore[arg-type]
            )

        duplicate_key_bytes = render_team_authorization(export.authorization).replace(
            '"decision_id": "decision-export-exact",',
            ('"decision_id": "decision-export-exact",\n  "decision_id": "decision-export-exact",'),
        )
        with self.assertRaisesRegex(TeamValidationError, "duplicate JSON key"):
            parse_team_authorization_bytes(duplicate_key_bytes.encode())


if __name__ == "__main__":
    unittest.main()
