"""Command-line interface contracts."""

from __future__ import annotations

import contextlib
import hashlib
import io
import json
import tempfile
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch

from causure.cli import main
from tests.helpers import PROJECT_ROOT
from tests.test_canary import _artifacts as canary_artifacts


class CliTests(unittest.TestCase):
    def test_validate_returns_zero_for_a_valid_case(self) -> None:
        stdout = io.StringIO()
        case_path = (
            PROJECT_ROOT / "examples" / "change-cases" / "approve-refund-tool-description.json"
        )

        with contextlib.redirect_stdout(stdout):
            exit_code = main(["validate", str(case_path)])

        self.assertEqual(0, exit_code)
        self.assertIn("refund-tool-description-001", stdout.getvalue())

    def test_review_returns_zero_for_approve_and_one_for_reject(self) -> None:
        approved = (
            PROJECT_ROOT / "examples" / "change-cases" / "approve-refund-tool-description.json"
        )
        rejected = PROJECT_ROOT / "examples" / "change-cases" / "reject-overbroad-prompt.json"

        with contextlib.redirect_stdout(io.StringIO()):
            approved_exit = main(["review", str(approved), "--format", "json"])
            rejected_exit = main(["review", str(rejected), "--format", "json"])

        self.assertEqual(0, approved_exit)
        self.assertEqual(1, rejected_exit)

    def test_review_writes_machine_output_atomically(self) -> None:
        approved = (
            PROJECT_ROOT / "examples" / "change-cases" / "approve-refund-tool-description.json"
        )
        with tempfile.TemporaryDirectory() as directory:
            output = Path(directory) / "results" / "review.json"
            with contextlib.redirect_stdout(io.StringIO()):
                exit_code = main(
                    [
                        "review",
                        str(approved),
                        "--format",
                        "json",
                        "--output",
                        str(output),
                        "--quiet",
                    ]
                )

            self.assertEqual(0, exit_code)
            self.assertEqual("approve", json.loads(output.read_text())["decision"])

    def test_review_can_write_markdown_and_json_from_one_decision(self) -> None:
        approved = (
            PROJECT_ROOT / "examples" / "change-cases" / "approve-refund-tool-description.json"
        )
        with tempfile.TemporaryDirectory() as directory:
            report = Path(directory) / "report.md"
            result = Path(directory) / "result.json"
            with contextlib.redirect_stdout(io.StringIO()):
                exit_code = main(
                    [
                        "review",
                        str(approved),
                        "--output",
                        str(report),
                        "--result-output",
                        str(result),
                        "--quiet",
                    ]
                )

            self.assertEqual(0, exit_code)
            report_text = report.read_text(encoding="utf-8")
            result_document = json.loads(result.read_text())
            self.assertIn("**APPROVE**", report_text)
            self.assertEqual("approve", result_document["decision"])
            self.assertIn(result_document["reviewed_at"], report_text)

    def test_review_rejects_colliding_output_paths(self) -> None:
        approved = (
            PROJECT_ROOT / "examples" / "change-cases" / "approve-refund-tool-description.json"
        )
        with tempfile.TemporaryDirectory() as directory:
            output = Path(directory) / "result"
            stderr = io.StringIO()
            with contextlib.redirect_stderr(stderr):
                exit_code = main(
                    [
                        "review",
                        str(approved),
                        "--output",
                        str(output),
                        "--result-output",
                        str(output),
                    ]
                )

            self.assertEqual(2, exit_code)
            self.assertIn("different paths", stderr.getvalue())

    def test_invalid_document_returns_configuration_exit_code(self) -> None:
        stderr = io.StringIO()
        with tempfile.TemporaryDirectory() as directory:
            invalid = Path(directory) / "invalid.json"
            invalid.write_text("{}", encoding="utf-8")
            with contextlib.redirect_stderr(stderr):
                exit_code = main(["review", str(invalid)])

        self.assertEqual(2, exit_code)
        self.assertIn("Invalid change case", stderr.getvalue())

    def test_schema_command_returns_json(self) -> None:
        stdout = io.StringIO()

        with contextlib.redirect_stdout(stdout):
            exit_code = main(["schema", "policy"])

        self.assertEqual(0, exit_code)
        self.assertEqual(
            "Causure policy override",
            json.loads(stdout.getvalue())["title"],
        )

    def test_canary_compare_writes_human_and_machine_results(self) -> None:
        observation, policy, case, review, _ = canary_artifacts()
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            inputs = {
                "observation": root / "observation.json",
                "policy": root / "policy.json",
                "case": root / "case.json",
                "review": root / "review.json",
            }
            for path, content in zip(
                inputs.values(),
                (observation, policy, case, review),
                strict=True,
            ):
                path.write_bytes(content)
            report = root / "canary.md"
            result = root / "canary-result.json"
            with (
                patch(
                    "causure.canary.utc_timestamp",
                    return_value="2026-07-29T16:00:00Z",
                ),
                contextlib.redirect_stdout(io.StringIO()),
            ):
                exit_code = main(
                    [
                        "canary-compare",
                        str(inputs["observation"]),
                        "--policy",
                        str(inputs["policy"]),
                        "--case",
                        str(inputs["case"]),
                        "--review-result",
                        str(inputs["review"]),
                        "--output",
                        str(report),
                        "--result-output",
                        str(result),
                        "--quiet",
                    ]
                )

            self.assertEqual(0, exit_code)
            self.assertIn("> **PROMOTE**", report.read_text(encoding="utf-8"))
            self.assertEqual("promote", json.loads(result.read_text())["decision"])

    def test_canary_schema_commands_return_json(self) -> None:
        expected_titles = {
            "canary-observation": "Causure canary observation",
            "canary-policy": "Causure canary policy",
            "canary-result": "Causure canary comparison result",
        }
        for name, title in expected_titles.items():
            with self.subTest(name=name):
                stdout = io.StringIO()
                with contextlib.redirect_stdout(stdout):
                    exit_code = main(["schema", name])
                self.assertEqual(0, exit_code)
                self.assertEqual(title, json.loads(stdout.getvalue())["title"])

    def test_canary_continue_requires_explicit_exit_override(self) -> None:
        observation, policy, case, review, _ = canary_artifacts()
        policy_document = json.loads(policy)
        policy_document["metrics"] = [
            {
                "direction": "higher",
                "maximum_degradation": 0.0,
                "metric_id": "task_success",
            }
        ]
        policy = (
            json.dumps(policy_document, ensure_ascii=False, indent=2, sort_keys=True) + "\n"
        ).encode()
        observation_document = json.loads(observation)
        observation_document["policy"]["policy_sha256"] = hashlib.sha256(policy).hexdigest()
        observation_document["baseline"]["metrics"] = [
            observation_document["baseline"]["metrics"][0]
        ]
        observation_document["candidate"]["metrics"] = [
            observation_document["candidate"]["metrics"][0]
        ]
        observation_document["candidate"]["metrics"][0]["event_count"] = 9000
        observation = (
            json.dumps(observation_document, ensure_ascii=False, indent=2, sort_keys=True) + "\n"
        ).encode()

        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            paths = [
                root / "observation.json",
                root / "policy.json",
                root / "case.json",
                root / "review.json",
            ]
            for path, content in zip(paths, (observation, policy, case, review), strict=True):
                path.write_bytes(content)
            arguments = [
                "canary-compare",
                str(paths[0]),
                "--policy",
                str(paths[1]),
                "--case",
                str(paths[2]),
                "--review-result",
                str(paths[3]),
                "--format",
                "json",
            ]
            with (
                patch(
                    "causure.canary.utc_timestamp",
                    return_value="2026-07-29T16:00:00Z",
                ),
                contextlib.redirect_stdout(io.StringIO()),
            ):
                default_exit = main(arguments)
                allowed_exit = main([*arguments, "--allow-continue"])

        self.assertEqual(1, default_exit)
        self.assertEqual(0, allowed_exit)

    def test_collect_writes_redacted_trace_manifest(self) -> None:
        traces = PROJECT_ROOT / "examples" / "traces" / "refund-openinference-otlp.json"
        with tempfile.TemporaryDirectory() as directory:
            output = Path(directory) / "trace-manifest.json"
            stdout = io.StringIO()
            with contextlib.redirect_stdout(stdout):
                exit_code = main(
                    [
                        "collect",
                        str(traces),
                        "--source-id",
                        "refund-openinference-fixture",
                        "--output",
                        str(output),
                    ]
                )

            document = json.loads(output.read_text(encoding="utf-8"))
            self.assertEqual(0, exit_code)
            self.assertEqual(2, document["source"]["span_count"])
            self.assertFalse(document["redaction"]["raw_content_included"])
            self.assertIn("Collected 2 span(s)", stdout.getvalue())
            self.assertNotIn("alice@example.com", output.read_text(encoding="utf-8"))

    def test_collect_rejects_colliding_input_and_output(self) -> None:
        traces = PROJECT_ROOT / "examples" / "traces" / "refund-openinference-otlp.json"
        stderr = io.StringIO()
        with contextlib.redirect_stderr(stderr):
            exit_code = main(
                [
                    "collect",
                    str(traces),
                    "--source-id",
                    "refund-openinference-fixture",
                    "--output",
                    str(traces),
                ]
            )

        self.assertEqual(2, exit_code)
        self.assertIn("different paths", stderr.getvalue())

    def test_team_service_schema_commands_return_json(self) -> None:
        expected_titles = {
            "entra-refresh-config": "Causure Entra refresh configuration",
            "entra-trust-store": "Causure Entra trust store",
            "team-access-policy": "Causure Team access policy",
            "team-authorization": "Causure Team authorization decision",
            "team-audit-event": "Causure Team audit event",
            "team-audit-export": "Causure Team audit export",
            "team-audit-verification": "Causure Team audit verification",
            "team-http-action-request": "Causure Team HTTP action request",
            "team-case-record": "Causure Team dashboard case record",
            "team-http-case-detail": "Causure Team HTTP case detail",
            "team-http-case-page": "Causure Team HTTP case page",
            "team-http-case-publication-request": ("Causure Team HTTP case-publication request"),
            "team-http-event-page": "Causure Team HTTP event page",
            "team-investigation-record": "Causure Team investigation record",
            "team-http-investigation-attach-request": (
                "Causure Team HTTP investigation-observation request"
            ),
            "team-http-investigation-detail": ("Causure Team HTTP investigation detail"),
            "team-http-investigation-open-request": (
                "Causure Team HTTP investigation-open request"
            ),
            "team-http-investigation-page": ("Causure Team HTTP investigation page"),
            "team-http-investigation-transition-request": (
                "Causure Team HTTP investigation-transition request"
            ),
            "team-host-config": "Causure Team service host configuration",
        }

        for name, title in expected_titles.items():
            with self.subTest(name=name):
                stdout = io.StringIO()
                with contextlib.redirect_stdout(stdout):
                    exit_code = main(["schema", name])
                self.assertEqual(0, exit_code)
                self.assertEqual(title, json.loads(stdout.getvalue())["title"])

    def test_entra_trust_refresh_uses_closed_config_and_explicit_network_command(
        self,
    ) -> None:
        configuration = {
            "schema_version": "1.0",
            "store_id": "entra-production",
            "snapshot_ttl_seconds": 43200,
            "tenants": [
                {
                    "entra_tenant_id": "11111111-1111-4111-8111-111111111111",
                    "team_tenant_id": "tenant-acme",
                    "issuer": (
                        "https://login.microsoftonline.com/"
                        "11111111-1111-4111-8111-111111111111/v2.0"
                    ),
                    "jwks_uri": (
                        "https://login.microsoftonline.com/"
                        "11111111-1111-4111-8111-111111111111/discovery/v2.0/keys"
                    ),
                    "audience": "33333333-3333-4333-8333-333333333333",
                    "allowed_client_ids": ["44444444-4444-4444-8444-444444444444"],
                    "accepted_delegated_scopes": ["Causure.Access"],
                    "accepted_application_roles": [],
                    "max_token_lifetime_seconds": 7200,
                }
            ],
        }
        with tempfile.TemporaryDirectory() as directory:
            config_path = Path(directory) / "refresh.json"
            output_path = Path(directory) / "trust.json"
            config_path.write_text(json.dumps(configuration), encoding="utf-8")
            result = SimpleNamespace(
                tenants=(object(),),
                store_id="entra-production",
            )
            stdout = io.StringIO()
            with (
                patch(
                    "causure.cli.refresh_entra_trust_file",
                    return_value=result,
                ) as refresh,
                contextlib.redirect_stdout(stdout),
            ):
                exit_code = main(
                    [
                        "entra-trust-refresh",
                        str(config_path),
                        str(output_path),
                        "--timeout-seconds",
                        "7",
                    ]
                )

        self.assertEqual(0, exit_code)
        parsed_configuration = refresh.call_args.args[0]
        self.assertEqual("entra-production", parsed_configuration.store_id)
        self.assertEqual(output_path, Path(refresh.call_args.args[1]))
        self.assertEqual(7.0, refresh.call_args.kwargs["timeout_seconds"])
        self.assertIn("Refreshed 1 Entra tenant(s)", stdout.getvalue())

    def test_team_serve_loads_closed_configuration_and_starts_host(self) -> None:
        configuration = SimpleNamespace(
            server=SimpleNamespace(listen_host="127.0.0.1", listen_port=8080)
        )
        stdout = io.StringIO()
        with (
            patch(
                "causure.cli.load_team_host_configuration",
                return_value=configuration,
            ) as load,
            patch("causure.cli.serve_team_host") as serve,
            contextlib.redirect_stdout(stdout),
        ):
            exit_code = main(["team-serve", "C:\\Protected\\team-host.json"])

        self.assertEqual(0, exit_code)
        load.assert_called_once_with("C:\\Protected\\team-host.json")
        serve.assert_called_once_with(configuration)
        self.assertIn("127.0.0.1:8080", stdout.getvalue())
        self.assertIn("trusted HTTPS edge", stdout.getvalue())

    def test_openai_quota_serve_loads_closed_configuration_and_starts_host(self) -> None:
        configuration = SimpleNamespace(
            server=SimpleNamespace(listen_host="0.0.0.0", listen_port=8080)
        )
        stdout = io.StringIO()
        with (
            patch(
                "causure.cli.load_openai_quota_host_configuration",
                return_value=configuration,
            ) as load,
            patch("causure.cli.serve_openai_quota_host") as serve,
            contextlib.redirect_stdout(stdout),
        ):
            exit_code = main(["openai-quota-serve", "/run/configs/quota-host.json"])

        self.assertEqual(0, exit_code)
        load.assert_called_once_with("/run/configs/quota-host.json")
        serve.assert_called_once_with(configuration)
        self.assertIn("0.0.0.0:8080", stdout.getvalue())
        self.assertIn("split trusted TLS edges", stdout.getvalue())

    def test_openai_quota_pilot_prepare_emits_only_public_state_metadata(self) -> None:
        state = SimpleNamespace(
            state_directory="C:\\Protected\\quota-pilot",
            ca_certificate_path="C:\\Protected\\quota-pilot\\trust\\pilot-ca.crt",
            certificate_not_after="2026-09-08T20:00:00Z",
        )
        stdout = io.StringIO()
        with (
            patch(
                "causure.cli.prepare_openai_quota_pilot_state",
                return_value=state,
            ) as prepare,
            contextlib.redirect_stdout(stdout),
        ):
            exit_code = main(
                [
                    "openai-quota-pilot-prepare",
                    "C:\\Protected\\quota.json",
                    "C:\\Protected\\provider-key",
                    "C:\\Protected\\quota-pilot",
                    "--certificate-days",
                    "7",
                ]
            )

        self.assertEqual(0, exit_code)
        prepare.assert_called_once_with(
            "C:\\Protected\\quota.json",
            "C:\\Protected\\provider-key",
            "C:\\Protected\\quota-pilot",
            valid_days=7,
        )
        self.assertIn(state.state_directory, stdout.getvalue())
        self.assertIn(state.ca_certificate_path, stdout.getvalue())
        self.assertNotIn("provider-key", stdout.getvalue())

    def test_trace_manifest_schema_command_returns_json(self) -> None:
        stdout = io.StringIO()

        with contextlib.redirect_stdout(stdout):
            exit_code = main(["schema", "trace-manifest"])

        self.assertEqual(0, exit_code)
        self.assertEqual(
            "Causure redacted trace manifest",
            json.loads(stdout.getvalue())["title"],
        )

    def test_fixture_command_writes_a_non_gate_eligible_draft(self) -> None:
        traces = PROJECT_ROOT / "examples" / "traces" / "refund-openinference-otlp.json"
        with tempfile.TemporaryDirectory() as directory:
            manifest = Path(directory) / "manifest.json"
            fixture = Path(directory) / "fixture.json"
            with contextlib.redirect_stdout(io.StringIO()):
                collect_exit = main(
                    [
                        "collect",
                        str(traces),
                        "--source-id",
                        "refund-openinference-fixture",
                        "--output",
                        str(manifest),
                        "--quiet",
                    ]
                )
                fixture_exit = main(
                    [
                        "fixture",
                        str(manifest),
                        "--fixture-id",
                        "refund-investigation-001",
                        "--output",
                        str(fixture),
                        "--quiet",
                    ]
                )

            document = json.loads(fixture.read_text(encoding="utf-8"))
            self.assertEqual(0, collect_exit)
            self.assertEqual(0, fixture_exit)
            self.assertTrue(document["draft_only"])
            self.assertFalse(document["gate_eligible"])
            self.assertEqual(1, len(document["candidate_clusters"]))

    def test_investigation_fixture_schema_command_returns_json(self) -> None:
        stdout = io.StringIO()

        with contextlib.redirect_stdout(stdout):
            exit_code = main(["schema", "investigation-fixture"])

        self.assertEqual(0, exit_code)
        self.assertEqual(
            "Causure draft investigation fixture",
            json.loads(stdout.getvalue())["title"],
        )

    def test_investigation_selection_schema_command_returns_json(self) -> None:
        stdout = io.StringIO()

        with contextlib.redirect_stdout(stdout):
            exit_code = main(["schema", "investigation-selection"])

        self.assertEqual(0, exit_code)
        self.assertEqual(
            "Causure investigation selection",
            json.loads(stdout.getvalue())["title"],
        )

    def test_attestation_schema_commands_return_json(self) -> None:
        expected_titles = {
            "artifact-attestation": "Causure artifact attestation",
            "attestation-revocations": ("Causure attestation revocation list"),
            "attestation-trust-store": "Causure attestation trust store",
            "attestation-verification": ("Causure attestation verification"),
        }

        for name, title in expected_titles.items():
            with self.subTest(name=name):
                stdout = io.StringIO()
                with contextlib.redirect_stdout(stdout):
                    exit_code = main(["schema", name])
                document = json.loads(stdout.getvalue())
                self.assertEqual(0, exit_code)
                self.assertEqual(title, document["title"])

    def test_approval_schema_commands_return_json(self) -> None:
        expected_titles = {
            "approval-assertion": "Causure approval assertion",
            "approval-revocations": "Causure approval revocation list",
            "approval-trust-store": "Causure approval trust store",
            "approval-verification": "Causure approval verification",
        }

        for name, title in expected_titles.items():
            with self.subTest(name=name):
                stdout = io.StringIO()
                with contextlib.redirect_stdout(stdout):
                    exit_code = main(["schema", name])
                document = json.loads(stdout.getvalue())
                self.assertEqual(0, exit_code)
                self.assertEqual(title, document["title"])

    def test_sandbox_schema_commands_return_json(self) -> None:
        expected_titles = {
            "openai-quota-config": ("Causure OpenAI-compatible quota proxy configuration"),
            "openai-quota-host-config": (
                "Causure OpenAI-compatible quota service host configuration"
            ),
            "sandbox-policy": "Causure sandbox policy",
            "sandbox-worker-request": "Causure sandbox worker request",
            "sandbox-worker-response": "Causure sandbox worker response",
        }

        for name, title in expected_titles.items():
            with self.subTest(name=name):
                stdout = io.StringIO()
                with contextlib.redirect_stdout(stdout):
                    exit_code = main(["schema", name])
                document = json.loads(stdout.getvalue())
                self.assertEqual(0, exit_code)
                self.assertEqual(title, document["title"])

    def test_azure_review_schema_commands_return_json(self) -> None:
        expected_titles = {
            "azure-review-publication": "Causure Azure review publication",
            "azure-review-verification": "Causure Azure review verification",
            "github-check-run-receipt": "Causure GitHub Check Run receipt",
            "github-check-run-request": "Causure GitHub Check Run request",
            "github-review-publication": "Causure GitHub review publication",
            "github-review-verification": "Causure GitHub review verification",
        }

        for name, title in expected_titles.items():
            with self.subTest(name=name):
                stdout = io.StringIO()
                with contextlib.redirect_stdout(stdout):
                    exit_code = main(["schema", name])
                document = json.loads(stdout.getvalue())
                self.assertEqual(0, exit_code)
                self.assertEqual(title, document["title"])


if __name__ == "__main__":
    unittest.main()
