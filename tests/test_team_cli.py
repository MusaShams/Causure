"""CLI integration tests for Team authorization and audit workflows."""

from __future__ import annotations

import contextlib
import io
import json
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from causure.cli import main


def _policy_document() -> dict:
    return {
        "schema_version": "1.0",
        "tenant_id": "tenant-acme",
        "policy_id": "access-acme",
        "revision": 1,
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
        ],
        "retention_classes": [
            {"class_id": "audit-365", "minimum_days": 365},
        ],
    }


class TeamCliTests(unittest.TestCase):
    def test_authorize_append_export_and_verify(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            policy = root / "policy.json"
            payload = root / "payload.json"
            action = root / "action.json"
            event = root / "event.json"
            export_action = root / "export-action.json"
            export = root / "export.json"
            verification = root / "verification.json"
            policy.write_text(
                json.dumps(_policy_document(), indent=2) + "\n",
                encoding="utf-8",
            )
            payload.write_text('{"status":"opened"}\n', encoding="utf-8")

            with contextlib.redirect_stdout(io.StringIO()):
                authorize_exit = main(
                    [
                        "team-authorize",
                        str(policy),
                        "--decision-id",
                        "decision-event-1",
                        "--identity-provider",
                        "entra:contoso",
                        "--subject-id",
                        "alice-investigator",
                        "--action",
                        "investigation_write",
                        "--resource-type",
                        "investigation",
                        "--resource-id",
                        "investigation-17",
                        "--decided-at",
                        "2026-07-28T10:00:00Z",
                        "--output",
                        str(action),
                        "--quiet",
                    ]
                )
                append_exit = main(
                    [
                        "team-audit-append",
                        str(policy),
                        str(action),
                        str(payload),
                        "--payload-media-type",
                        "application/json",
                        "--event-id",
                        "event-1",
                        "--outcome",
                        "succeeded",
                        "--occurred-at",
                        "2026-07-28T10:01:00Z",
                        "--output",
                        str(event),
                        "--quiet",
                    ]
                )
                event_head = json.loads(event.read_text(encoding="utf-8"))["event_sha256"]
                export_authorize_exit = main(
                    [
                        "team-authorize",
                        str(policy),
                        "--decision-id",
                        "decision-export-1",
                        "--identity-provider",
                        "entra:contoso",
                        "--subject-id",
                        "pat-policy",
                        "--action",
                        "audit_export",
                        "--resource-type",
                        "audit_export",
                        "--resource-id",
                        "export-17",
                        "--decided-at",
                        "2026-07-28T10:02:00Z",
                        "--output",
                        str(export_action),
                        "--quiet",
                    ]
                )
                export_exit = main(
                    [
                        "team-audit-export",
                        str(policy),
                        str(export_action),
                        str(event),
                        "--export-id",
                        "export-17",
                        "--authoritative-head-sha256",
                        event_head,
                        "--created-at",
                        "2026-07-28T10:03:00Z",
                        "--output",
                        str(export),
                        "--quiet",
                    ]
                )
            with (
                patch(
                    "causure.cli.utc_timestamp",
                    return_value="2026-07-28T10:04:00Z",
                ),
                contextlib.redirect_stdout(io.StringIO()),
            ):
                verify_exit = main(
                    [
                        "team-audit-verify",
                        str(policy),
                        str(export),
                        "--output",
                        str(verification),
                        "--quiet",
                    ]
                )

            self.assertEqual(
                (0, 0, 0, 0, 0),
                (
                    authorize_exit,
                    append_exit,
                    export_authorize_exit,
                    export_exit,
                    verify_exit,
                ),
            )
            self.assertTrue(json.loads(action.read_text())["authorized"])
            self.assertEqual(1, json.loads(event.read_text())["entry"]["sequence"])
            self.assertEqual(1, json.loads(export.read_text())["audit_range"]["event_count"])
            self.assertEqual("verified", json.loads(verification.read_text())["status"])

    def test_denial_is_machine_readable_and_returns_gate_exit(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            policy = root / "policy.json"
            decision = root / "decision.json"
            policy.write_text(
                json.dumps(_policy_document(), indent=2) + "\n",
                encoding="utf-8",
            )
            with contextlib.redirect_stdout(io.StringIO()):
                exit_code = main(
                    [
                        "team-authorize",
                        str(policy),
                        "--decision-id",
                        "decision-denied",
                        "--identity-provider",
                        "entra:contoso",
                        "--subject-id",
                        "alice-investigator",
                        "--action",
                        "approval_issue",
                        "--resource-type",
                        "approval",
                        "--resource-id",
                        "approval-17",
                        "--decided-at",
                        "2026-07-28T10:00:00Z",
                        "--output",
                        str(decision),
                        "--quiet",
                    ]
                )

            document = json.loads(decision.read_text(encoding="utf-8"))
            self.assertEqual(1, exit_code)
            self.assertFalse(document["authorized"])
            self.assertEqual("role_not_granted", document["reason"])


if __name__ == "__main__":
    unittest.main()
