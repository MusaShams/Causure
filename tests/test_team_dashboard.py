"""Read-only Team dashboard rendering tests."""

from __future__ import annotations

import unittest

from causure.constants import (
    TeamAction,
    TeamAuditOutcome,
    TeamAuthorizationReason,
    TeamResourceType,
    TeamRole,
)
from causure.team_application import (
    TeamEventPage,
    TeamEventSummary,
    TeamTenantSummary,
)
from causure.team_dashboard import render_team_dashboard
from causure.team_service import (
    TeamDocumentSubject,
    TeamPolicySubject,
    TeamPrincipal,
    TeamResource,
    TeamRetentionRequirement,
)
from causure.team_store import TeamLedgerHead


class TeamDashboardTests(unittest.TestCase):
    def test_renderer_escapes_every_displayed_string(self) -> None:
        malicious = '<script>alert("xss")</script>'
        page = TeamEventPage(
            summary=TeamTenantSummary(
                tenant_id=malicious,
                policy_id=malicious,
                policy_revision=1,
                policy_effective_at="2026-07-29T10:00:00Z",
                policy_sha256="a" * 64,
                policy_byte_count=100,
                assigned_roles=(TeamRole.INVESTIGATOR,),
                head=TeamLedgerHead(
                    tenant_id=malicious,
                    sequence=1,
                    event_sha256="b" * 64,
                ),
            ),
            events=(
                TeamEventSummary(
                    sequence=1,
                    event_id=malicious,
                    event_sha256="b" * 64,
                    decision_id=malicious,
                    occurred_at="2026-07-29T10:00:00Z",
                    principal=TeamPrincipal(
                        identity_provider=malicious,
                        subject_id=malicious,
                    ),
                    action=TeamAction.INVESTIGATION_WRITE,
                    resource=TeamResource(
                        resource_type=TeamResourceType.INVESTIGATION,
                        resource_id=malicious,
                    ),
                    authorized=True,
                    authorization_reason=TeamAuthorizationReason.ROLE_GRANT,
                    outcome=TeamAuditOutcome.SUCCEEDED,
                    payload=TeamDocumentSubject(
                        media_type="application/json",
                        sha256="c" * 64,
                        byte_count=42,
                    ),
                    retention=TeamRetentionRequirement(
                        class_id=malicious,
                        retain_until="2027-07-29T10:00:00Z",
                    ),
                    policy=TeamPolicySubject(
                        media_type=("application/vnd.causure.team-access-policy+json"),
                        policy_id=malicious,
                        revision=1,
                        sha256="a" * 64,
                        byte_count=100,
                    ),
                ),
            ),
            next_before_sequence=None,
        )

        rendered = render_team_dashboard(page, page_size=50).decode("utf-8")

        self.assertNotIn(malicious, rendered)
        self.assertIn("&lt;script&gt;alert(&quot;xss&quot;)&lt;/script&gt;", rendered)
        self.assertNotIn("<form", rendered)
        self.assertNotIn("<script", rendered)


if __name__ == "__main__":
    unittest.main()
