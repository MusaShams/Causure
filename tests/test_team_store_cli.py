"""CLI integration tests for transactional Team-store operations."""

from __future__ import annotations

import contextlib
import io
import json
import tempfile
import unittest
from pathlib import Path

from causure.cli import main
from causure.constants import TeamAction, TeamResourceType
from causure.team_store import SQLiteTeamStore
from tests.test_team_service import _authorization_bytes, _policy_bytes
from tests.test_team_store import _event_bytes


class TeamStoreCliTests(unittest.TestCase):
    def test_policy_head_append_export_retrieval_and_backup(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            database = root / "team.sqlite3"
            backup = root / "team-backup.sqlite3"
            policy_path = root / "policy.json"
            event_path = root / "event.json"
            export_authorization_path = root / "export-authorization.json"
            empty_head_path = root / "empty-head.json"
            appended_head_path = root / "appended-head.json"
            retrieved_policy_path = root / "retrieved-policy.json"
            retrieved_event_path = root / "retrieved-event.json"
            export_path = root / "export.json"

            policy_bytes = _policy_bytes()
            event_bytes = _event_bytes(
                policy_bytes,
                decision_id="decision-event-1",
                event_id="event-1",
                decided_at="2026-07-28T10:00:00Z",
                occurred_at="2026-07-28T10:01:00Z",
            )
            export_authorization = _authorization_bytes(
                policy_bytes,
                decision_id="decision-export-1",
                subject_id="pat-policy",
                action=TeamAction.AUDIT_EXPORT,
                resource_type=TeamResourceType.AUDIT_EXPORT,
                resource_id="export-1",
                decided_at="2026-07-28T10:02:00Z",
            )
            policy_path.write_bytes(policy_bytes)
            event_path.write_bytes(event_bytes)
            export_authorization_path.write_bytes(export_authorization)

            with contextlib.redirect_stdout(io.StringIO()):
                exit_codes = (
                    main(["team-store-init", str(database)]),
                    main(["team-store-policy-put", str(database), str(policy_path)]),
                    main(
                        [
                            "team-store-head",
                            str(database),
                            "--tenant-id",
                            "tenant-acme",
                            "--output",
                            str(empty_head_path),
                            "--quiet",
                        ]
                    ),
                    main(
                        [
                            "team-store-append",
                            str(database),
                            str(event_path),
                            "--expect-empty",
                            "--output",
                            str(appended_head_path),
                            "--quiet",
                        ]
                    ),
                    main(
                        [
                            "team-store-policy-get",
                            str(database),
                            "--tenant-id",
                            "tenant-acme",
                            "--policy-id",
                            "access-acme",
                            "--revision",
                            "1",
                            "--output",
                            str(retrieved_policy_path),
                            "--quiet",
                        ]
                    ),
                    main(
                        [
                            "team-store-event-get",
                            str(database),
                            "--tenant-id",
                            "tenant-acme",
                            "--sequence",
                            "1",
                            "--output",
                            str(retrieved_event_path),
                            "--quiet",
                        ]
                    ),
                    main(
                        [
                            "team-store-export",
                            str(database),
                            str(export_authorization_path),
                            "--export-id",
                            "export-1",
                            "--created-at",
                            "2026-07-28T10:03:00Z",
                            "--output",
                            str(export_path),
                            "--quiet",
                        ]
                    ),
                    main(["team-store-backup", str(database), str(backup)]),
                )

            self.assertEqual((0, 0, 0, 0, 0, 0, 0, 0), exit_codes)
            self.assertEqual(0, json.loads(empty_head_path.read_text())["sequence"])
            appended_head = json.loads(appended_head_path.read_text())
            self.assertEqual(1, appended_head["sequence"])
            self.assertEqual(policy_bytes, retrieved_policy_path.read_bytes())
            self.assertEqual(event_bytes, retrieved_event_path.read_bytes())
            self.assertEqual(1, json.loads(export_path.read_text())["audit_range"]["event_count"])

            restored = SQLiteTeamStore(backup)
            self.assertEqual(
                appended_head["event_sha256"],
                restored.get_head("tenant-acme").event_sha256,
            )
            self.assertEqual(
                export_path.read_bytes(),
                restored.get_export_bytes("tenant-acme", "export-1"),
            )

    def test_stale_cli_append_returns_invalid_input_exit(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            database = root / "team.sqlite3"
            policy_path = root / "policy.json"
            event_path = root / "event.json"
            policy_bytes = _policy_bytes()
            policy_path.write_bytes(policy_bytes)
            event_path.write_bytes(
                _event_bytes(
                    policy_bytes,
                    decision_id="decision-event-1",
                    event_id="event-1",
                    decided_at="2026-07-28T10:00:00Z",
                    occurred_at="2026-07-28T10:01:00Z",
                )
            )
            with contextlib.redirect_stdout(io.StringIO()):
                self.assertEqual(0, main(["team-store-init", str(database)]))
                self.assertEqual(
                    0,
                    main(["team-store-policy-put", str(database), str(policy_path)]),
                )
                self.assertEqual(
                    0,
                    main(
                        [
                            "team-store-append",
                            str(database),
                            str(event_path),
                            "--expect-empty",
                        ]
                    ),
                )
            stderr = io.StringIO()
            with (
                contextlib.redirect_stdout(io.StringIO()),
                contextlib.redirect_stderr(stderr),
            ):
                exit_code = main(
                    [
                        "team-store-append",
                        str(database),
                        str(event_path),
                        "--expect-empty",
                    ]
                )

            self.assertEqual(2, exit_code)
            self.assertIn("head_conflict", stderr.getvalue())


if __name__ == "__main__":
    unittest.main()
