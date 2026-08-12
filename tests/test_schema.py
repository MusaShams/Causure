"""Committed schema drift checks."""

from __future__ import annotations

import json
import unittest

from causure.schema import (
    approval_assertion_schema,
    approval_revocation_list_schema,
    approval_trust_store_schema,
    approval_verification_schema,
    artifact_attestation_schema,
    attestation_revocation_list_schema,
    attestation_trust_store_schema,
    attestation_verification_schema,
    azure_review_publication_schema,
    azure_review_verification_schema,
    canary_observation_schema,
    canary_policy_schema,
    canary_result_schema,
    change_case_schema,
    entra_refresh_config_schema,
    entra_trust_store_schema,
    github_check_run_receipt_schema,
    github_check_run_request_schema,
    github_review_publication_schema,
    github_review_verification_schema,
    investigation_fixture_schema,
    investigation_selection_schema,
    openai_quota_config_schema,
    openai_quota_host_config_schema,
    policy_schema,
    review_result_schema,
    sandbox_policy_schema,
    sandbox_worker_request_schema,
    sandbox_worker_response_schema,
    team_access_policy_schema,
    team_audit_event_schema,
    team_audit_export_schema,
    team_audit_verification_schema,
    team_authorization_schema,
    team_case_record_schema,
    team_host_config_schema,
    team_http_action_request_schema,
    team_http_case_detail_schema,
    team_http_case_page_schema,
    team_http_case_publication_request_schema,
    team_http_event_page_schema,
    team_http_investigation_attach_request_schema,
    team_http_investigation_detail_schema,
    team_http_investigation_open_request_schema,
    team_http_investigation_page_schema,
    team_http_investigation_transition_request_schema,
    team_investigation_record_schema,
    trace_manifest_schema,
    trusted_case_generation_receipt_schema,
)
from tests.helpers import PROJECT_ROOT


class SchemaTests(unittest.TestCase):
    def test_committed_approval_schemas_match_code(self) -> None:
        expected = {
            "approval-assertion.schema.json": approval_assertion_schema(),
            "approval-revocations.schema.json": approval_revocation_list_schema(),
            "approval-trust-store.schema.json": approval_trust_store_schema(),
            "approval-verification.schema.json": approval_verification_schema(),
        }

        for name, schema in expected.items():
            with self.subTest(name=name):
                self.assertEqual(schema, self._load_schema(name))

    def test_committed_attestation_schemas_match_code(self) -> None:
        expected = {
            "artifact-attestation.schema.json": artifact_attestation_schema(),
            "attestation-revocations.schema.json": (attestation_revocation_list_schema()),
            "attestation-trust-store.schema.json": attestation_trust_store_schema(),
            "attestation-verification.schema.json": (attestation_verification_schema()),
        }

        for name, schema in expected.items():
            with self.subTest(name=name):
                self.assertEqual(schema, self._load_schema(name))

    def test_committed_change_case_schema_matches_code(self) -> None:
        self.assertEqual(
            change_case_schema(),
            self._load_schema("change-case.schema.json"),
        )

    def test_committed_canary_schemas_match_code(self) -> None:
        expected = {
            "canary-observation.schema.json": canary_observation_schema(),
            "canary-policy.schema.json": canary_policy_schema(),
            "canary-result.schema.json": canary_result_schema(),
        }

        for name, schema in expected.items():
            with self.subTest(name=name):
                self.assertEqual(schema, self._load_schema(name))

    def test_committed_azure_review_schemas_match_code(self) -> None:
        expected = {
            "azure-review-publication.schema.json": azure_review_publication_schema(),
            "azure-review-verification.schema.json": azure_review_verification_schema(),
        }

        for name, schema in expected.items():
            with self.subTest(name=name):
                self.assertEqual(schema, self._load_schema(name))

    def test_committed_github_review_schemas_match_code(self) -> None:
        expected = {
            "github-check-run-receipt.schema.json": github_check_run_receipt_schema(),
            "github-check-run-request.schema.json": github_check_run_request_schema(),
            "github-review-publication.schema.json": github_review_publication_schema(),
            "github-review-verification.schema.json": github_review_verification_schema(),
        }

        for name, schema in expected.items():
            with self.subTest(name=name):
                self.assertEqual(schema, self._load_schema(name))

    def test_committed_trusted_case_generation_schema_matches_code(self) -> None:
        self.assertEqual(
            trusted_case_generation_receipt_schema(),
            self._load_schema("trusted-case-generation.schema.json"),
        )

    def test_committed_policy_schema_matches_code(self) -> None:
        self.assertEqual(
            policy_schema(),
            self._load_schema("policy.schema.json"),
        )

    def test_committed_review_result_schema_matches_code(self) -> None:
        self.assertEqual(
            review_result_schema(),
            self._load_schema("review-result.schema.json"),
        )

    def test_committed_trace_manifest_schema_matches_code(self) -> None:
        self.assertEqual(
            trace_manifest_schema(),
            self._load_schema("trace-manifest.schema.json"),
        )

    def test_committed_investigation_fixture_schema_matches_code(self) -> None:
        self.assertEqual(
            investigation_fixture_schema(),
            self._load_schema("investigation-fixture.schema.json"),
        )

    def test_committed_investigation_selection_schema_matches_code(self) -> None:
        self.assertEqual(
            investigation_selection_schema(),
            self._load_schema("investigation-selection.schema.json"),
        )

    def test_committed_sandbox_schemas_match_code(self) -> None:
        expected = {
            "sandbox-policy.schema.json": sandbox_policy_schema(),
            "sandbox-worker-request.schema.json": sandbox_worker_request_schema(),
            "sandbox-worker-response.schema.json": sandbox_worker_response_schema(),
        }

        for name, schema in expected.items():
            with self.subTest(name=name):
                self.assertEqual(schema, self._load_schema(name))

    def test_committed_openai_quota_schemas_match_code(self) -> None:
        expected = {
            "openai-quota-config.schema.json": openai_quota_config_schema(),
            "openai-quota-host-config.schema.json": openai_quota_host_config_schema(),
        }

        for name, schema in expected.items():
            with self.subTest(name=name):
                self.assertEqual(schema, self._load_schema(name))

    def test_committed_team_service_schemas_match_code(self) -> None:
        expected = {
            "team-access-policy.schema.json": team_access_policy_schema(),
            "team-authorization.schema.json": team_authorization_schema(),
            "team-audit-event.schema.json": team_audit_event_schema(),
            "team-audit-export.schema.json": team_audit_export_schema(),
            "team-audit-verification.schema.json": team_audit_verification_schema(),
            "team-http-action-request.schema.json": team_http_action_request_schema(),
            "team-case-record.schema.json": team_case_record_schema(),
            "team-http-case-detail.schema.json": team_http_case_detail_schema(),
            "team-http-case-page.schema.json": team_http_case_page_schema(),
            "team-http-case-publication-request.schema.json": (
                team_http_case_publication_request_schema()
            ),
            "team-http-event-page.schema.json": team_http_event_page_schema(),
            "team-investigation-record.schema.json": team_investigation_record_schema(),
            "team-http-investigation-attach-request.schema.json": (
                team_http_investigation_attach_request_schema()
            ),
            "team-http-investigation-detail.schema.json": (team_http_investigation_detail_schema()),
            "team-http-investigation-open-request.schema.json": (
                team_http_investigation_open_request_schema()
            ),
            "team-http-investigation-page.schema.json": (team_http_investigation_page_schema()),
            "team-http-investigation-transition-request.schema.json": (
                team_http_investigation_transition_request_schema()
            ),
            "team-host-config.schema.json": team_host_config_schema(),
        }

        for name, schema in expected.items():
            with self.subTest(name=name):
                self.assertEqual(schema, self._load_schema(name))

    def test_committed_entra_trust_store_schema_matches_code(self) -> None:
        self.assertEqual(
            entra_trust_store_schema(),
            self._load_schema("entra-trust-store.schema.json"),
        )

    def test_committed_entra_refresh_config_schema_matches_code(self) -> None:
        self.assertEqual(
            entra_refresh_config_schema(),
            self._load_schema("entra-refresh-config.schema.json"),
        )

    def test_trace_manifest_schema_separates_text_and_numeric_metadata(self) -> None:
        attributes = trace_manifest_schema()["properties"]["spans"]["items"]["properties"][
            "attributes"
        ]

        self.assertFalse(attributes["additionalProperties"])
        self.assertEqual(
            "string",
            attributes["properties"]["llm.model_name"]["type"],
        )
        self.assertEqual(
            "number",
            attributes["properties"]["llm.token_count.total"]["type"],
        )
        self.assertNotIn("patternProperties", attributes)
        self.assertNotIn("gen_ai.usage.user_id", attributes["properties"])

    @staticmethod
    def _load_schema(name: str) -> dict:
        path = PROJECT_ROOT / "schemas" / name
        return json.loads(path.read_text(encoding="utf-8"))


if __name__ == "__main__":
    unittest.main()
