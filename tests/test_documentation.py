"""Documentation and source-control hygiene checks."""

from __future__ import annotations

import json
import re
import unittest
from urllib.parse import unquote

from tests.helpers import PROJECT_ROOT

_MARKDOWN_LINK = re.compile(r"\[[^\]]+\]\(([^)]+)\)")
_IGNORED_DOCUMENTATION_TREES = frozenset(
    {"$tf", ".git", ".ruff_cache", ".venv", "build", "dist", "htmlcov"}
)


class DocumentationTests(unittest.TestCase):
    def test_relative_markdown_links_resolve(self) -> None:
        broken: list[str] = []
        markdown_files = [
            path
            for path in PROJECT_ROOT.rglob("*.md")
            if _IGNORED_DOCUMENTATION_TREES.isdisjoint(path.parts)
        ]
        for markdown_file in markdown_files:
            content = markdown_file.read_text(encoding="utf-8")
            for target in _MARKDOWN_LINK.findall(content):
                if target.startswith(("http://", "https://", "mailto:", "#")):
                    continue
                target_path = unquote(target.split("#", maxsplit=1)[0])
                resolved = (markdown_file.parent / target_path).resolve()
                if not resolved.exists():
                    broken.append(f"{markdown_file.relative_to(PROJECT_ROOT)} -> {target}")

        self.assertEqual([], broken, "Broken Markdown links:\n" + "\n".join(broken))

    def test_tfignore_excludes_local_and_generated_state(self) -> None:
        contents = (PROJECT_ROOT / ".tfignore").read_text(encoding="utf-8")

        for required_pattern in (
            r"\.git",
            "__pycache__",
            r"\.ruff_cache",
            r"\build",
            r"\dist",
            "*.key",
            "*.pem",
            "*.clixml",
            "*.sqlite3",
            "*-wal",
            "*-shm",
            r"\pilot-state",
        ):
            with self.subTest(pattern=required_pattern):
                self.assertIn(required_pattern, contents)
        self.assertNotIn(r"**\__pycache__", contents)

    def test_gitignore_excludes_tfvc_secrets_and_generated_state(self) -> None:
        contents = (PROJECT_ROOT / ".gitignore").read_text(encoding="utf-8")

        for required_pattern in (
            "$tf/",
            ".env.*",
            "*.clixml",
            "*.key",
            "*.pem",
            "pilot-state/",
            "deploy/openai-quota-pilot/state/",
            "*.sqlite3",
        ):
            with self.subTest(pattern=required_pattern):
                self.assertIn(required_pattern, contents)

    def test_public_release_guide_preserves_authority_and_visibility_boundaries(self) -> None:
        guide = (PROJECT_ROOT / "docs" / "github-public-release.md").read_text(encoding="utf-8")
        decision = (
            PROJECT_ROOT / "docs" / "decisions" / "0026-publish-a-reviewed-github-mirror.md"
        ).read_text(encoding="utf-8")
        security = (PROJECT_ROOT / "SECURITY.md").read_text(encoding="utf-8")
        classic_ci = (PROJECT_ROOT / "scripts" / "classic_ci.ps1").read_text(encoding="utf-8")

        self.assertIn("TFVC remains authoritative", guide)
        self.assertIn("Apache-2.0", guide)
        self.assertRegex(guide, r"separate\s+owner-authorized action")
        self.assertIn("not authorization to make it public", guide)
        self.assertIn("never merge a GitHub-only change first", guide)
        self.assertIn("both capability-gated\n   security jobs are skipped", guide)
        self.assertIn("owner-authorized public mirror", guide)
        self.assertIn("public receipt", guide)
        self.assertIn("Protect main", guide)
        self.assertIn("GitHub then marked the advisory fixed", guide)
        self.assertIn("GitHub rejected\nthe private mirror's rulesets API", guide)
        self.assertIn("immediate post-visibility", guide)
        self.assertIn("manually dispatch CodeQL from the exact `main`", guide)
        self.assertIn("without printing matched secret", decision)
        self.assertIn("No license, Git commit, remote, repository", decision)
        self.assertIn("Report a vulnerability", security)
        self.assertIn("check_public_release.py", classic_ci)
        self.assertNotIn("--allow-missing-license", classic_ci)

    def test_private_github_qualification_preserves_exact_scope_and_outcomes(self) -> None:
        receipt = json.loads(
            (
                PROJECT_ROOT / "docs" / "qualifications" / "github-native-private-2026-08-11.json"
            ).read_text(encoding="utf-8")
        )

        self.assertEqual("passed", receipt["result"])
        self.assertEqual("private-same-repository-and-dependabot", receipt["scope"])
        self.assertEqual("TFVC", receipt["source"]["authoritative_system"])
        self.assertRegex(receipt["source"]["action_commit_sha"], r"\A[0-9a-f]{40}\Z")

        scenarios = {scenario["name"]: scenario for scenario in receipt["scenarios"]}
        self.assertEqual(
            {"approve", "abstain", "needs-evidence", "dependabot-no-match"},
            set(scenarios),
        )
        expected_reviews = {
            "approve": ("approve", "patch", "success"),
            "abstain": ("reject", "do_not_patch", "failure"),
            "needs-evidence": ("needs_evidence", "collect_evidence", "action_required"),
        }
        for name, (decision, action, conclusion) in expected_reviews.items():
            with self.subTest(scenario=name):
                scenario = scenarios[name]
                self.assertRegex(scenario["head_sha"], r"\A[0-9a-f]{40}\Z")
                self.assertEqual(decision, scenario["review"]["decision"])
                self.assertEqual(action, scenario["review"]["recommended_action"])
                self.assertEqual(conclusion, scenario["review"]["custom_check_conclusion"])
                self.assertEqual("verified", scenario["review"]["verification_status"])
                self.assertEqual("published", scenario["review"]["publication_status"])
                self.assertRegex(scenario["artifact"]["digest"], r"\Asha256:[0-9a-f]{64}\Z")
                self.assertTrue(scenario["artifact"]["generation_chain_present"])
                self.assertTrue(scenario["artifact"]["review_chain_present"])

        dependabot = scenarios["dependabot-no-match"]
        self.assertEqual("success", dependabot["stable_job"]["conclusion"])
        self.assertEqual("no_match", dependabot["selection_status"])
        self.assertFalse(dependabot["custom_check_present"])
        self.assertFalse(dependabot["artifact_present"])
        self.assertTrue(dependabot["fixed_action_sha_observed_in_head_workflow"])
        self.assertIn(
            "generator-backed fork",
            " ".join(receipt["remaining_required_scenarios"]),
        )

    def test_public_github_qualification_preserves_security_and_fork_outcomes(self) -> None:
        receipt = json.loads(
            (
                PROJECT_ROOT / "docs" / "qualifications" / "github-native-public-2026-08-11.json"
            ).read_text(encoding="utf-8")
        )

        self.assertEqual("passed", receipt["result"])
        self.assertEqual(
            "public-controls-codeql-and-generator-backed-fork",
            receipt["scope"],
        )
        self.assertEqual("TFVC", receipt["source"]["authoritative_system"])
        self.assertEqual("public", receipt["source"]["action_repository_visibility"])
        self.assertRegex(receipt["source"]["published_main_sha"], r"\A[0-9a-f]{40}\Z")
        self.assertRegex(receipt["source"]["invoked_action_sha"], r"\A[0-9a-f]{40}\Z")

        security = receipt["public_security"]
        self.assertEqual("enabled", security["controls"]["secret_scanning"])
        self.assertEqual("enabled", security["controls"]["secret_scanning_push_protection"])
        self.assertEqual("enabled", security["controls"]["private_vulnerability_reporting"])
        self.assertEqual("read", security["controls"]["default_workflow_permissions"])
        self.assertTrue(security["controls"]["full_action_sha_pins_required"])
        self.assertEqual("active", security["main_ruleset"]["enforcement"])
        self.assertIn("analyze (Python)", security["main_ruleset"]["required_status_checks"])
        self.assertFalse(security["main_ruleset"]["dependency_review_required"])
        self.assertEqual("success", security["codeql"]["conclusion"])
        self.assertEqual(0, security["alert_review"]["open_code_scanning_alerts"])
        self.assertEqual(0, security["alert_review"]["open_secret_scanning_alerts"])
        self.assertEqual(1, security["alert_review"]["open_dependabot_alerts"])

        fork = receipt["fork_scenario"]
        self.assertEqual("MusaShams/causure-examples", fork["base_repository"])
        self.assertEqual("causure-project/causure-examples", fork["head_repository"])
        self.assertRegex(fork["base_sha"], r"\A[0-9a-f]{40}\Z")
        self.assertRegex(fork["head_sha"], r"\A[0-9a-f]{40}\Z")
        self.assertEqual("failure", fork["stable_job"]["conclusion"])
        self.assertTrue(fork["stable_job"]["failure_expected"])
        self.assertEqual("success", fork["steps"]["protected_base_checkout"])
        self.assertEqual("success", fork["steps"]["candidate_head_checkout"])
        self.assertEqual("failure", fork["steps"]["trusted_generation"])
        self.assertEqual("skipped", fork["steps"]["ordinary_review"])
        self.assertIn("fails closed without executing the adapter", fork["guard_message"])
        self.assertFalse(fork["protected_adapter_executed"])
        self.assertFalse(fork["ordinary_review_executed"])
        self.assertFalse(fork["custom_check_present"])
        self.assertFalse(fork["artifact_present"])
        self.assertEqual("passed", fork["result"])
        self.assertEqual(
            "open_pending_tfvc_upgrade",
            receipt["security_follow_up"]["status"],
        )

    def test_public_github_remediation_preserves_merge_and_alert_outcomes(self) -> None:
        receipt = json.loads(
            (
                PROJECT_ROOT
                / "docs"
                / "qualifications"
                / "github-native-public-remediation-2026-08-11.json"
            ).read_text(encoding="utf-8")
        )

        self.assertEqual("passed", receipt["result"])
        self.assertEqual(
            "public-pr-dependency-review-ruleset-and-advisory-closure",
            receipt["scope"],
        )
        self.assertEqual("TFVC", receipt["source"]["authoritative_system"])
        self.assertEqual([171, 172], receipt["source"]["qualified_source_changesets"])
        self.assertRegex(receipt["source"]["head_sha"], r"\A[0-9a-f]{40}\Z")
        self.assertRegex(receipt["source"]["merge_sha"], r"\A[0-9a-f]{40}\Z")
        self.assertEqual("merged", receipt["pull_request_qualification"]["state"])
        self.assertEqual(
            "success",
            receipt["pull_request_qualification"]["dependency_review"]["conclusion"],
        )
        self.assertTrue(receipt["protected_main"]["dependency_review_required"])
        self.assertEqual(0, receipt["protected_main"]["bypass_actor_count"])
        self.assertIn(
            "dependency-review",
            receipt["protected_main"]["required_status_checks"],
        )
        self.assertEqual("success", receipt["post_merge"]["ci"]["conclusion"])
        self.assertEqual("success", receipt["post_merge"]["codeql"]["conclusion"])
        self.assertEqual("fixed", receipt["remediation"]["dependabot_alert"]["state"])
        self.assertEqual("50.0.0", receipt["remediation"]["patched_version"])
        self.assertEqual(0, receipt["alert_review"]["open_code_scanning_alerts"])
        self.assertEqual(0, receipt["alert_review"]["open_secret_scanning_alerts"])
        self.assertEqual(0, receipt["alert_review"]["open_dependabot_alerts"])
        self.assertEqual(
            ["fresh public same-repository approve, abstain, and needs-evidence example runs"],
            receipt["remaining_required_scenarios"],
        )

    def test_productization_roadmap_prioritizes_the_no_json_golden_path(self) -> None:
        contents = (PROJECT_ROOT / "docs" / "productization-roadmap.md").read_text(encoding="utf-8")

        self.assertIn("most of the original **assurance model**", contents)
        self.assertIn("implements the core **easy company workflow**", contents)
        self.assertIn("not yet a\nfinished self-serve company product", contents)
        self.assertIn("no manually authored JSON", contents)
        self.assertIn("Milestone P0-A: one-command local experience", contents)
        self.assertIn("Milestone P0-B: GitHub-native review", contents)
        self.assertIn("Milestone P1-A: bounded evaluation", contents)
        self.assertIn("Research track: PatchOrNotBench", contents)
        self.assertIn("Do not build next", contents)

    def test_portfolio_assets_preserve_the_bounded_public_claim(self) -> None:
        case_study = (PROJECT_ROOT / "docs" / "portfolio-case-study.md").read_text(encoding="utf-8")
        demo_script = (PROJECT_ROOT / "docs" / "portfolio-demo-script.md").read_text(
            encoding="utf-8"
        )

        self.assertIn("```mermaid", case_study)
        self.assertIn("Security and privacy boundary", case_study)
        self.assertIn("Explicit production limits", case_study)
        self.assertIn("functional evidence-gated agent change control", case_study)
        self.assertIn("unfamiliar terminal-capable participant", case_study)
        self.assertIn("under five minutes with zero assistance", case_study)
        self.assertIn("90-second portfolio demo", demo_script)
        self.assertIn("Do not show the TFVC PAT", demo_script)
        self.assertIn("final one-commit public repository", demo_script)

    def test_p0a_usability_protocol_requires_an_unassisted_unfamiliar_user(self) -> None:
        contents = (PROJECT_ROOT / "docs" / "p0a-usability-test.md").read_text(encoding="utf-8")

        self.assertIn("engineering audit, but that does not", contents)
        self.assertIn("count as the unfamiliar participant", contents)
        self.assertIn("assistance count is zero", contents)
        self.assertIn("less than ten minutes", contents)
        self.assertIn("filename, byte count, and SHA-256", contents)
        self.assertIn("personally identifying or customer information", contents)
        self.assertIn("repeat with a different unfamiliar", contents)

        audit = json.loads(
            (
                PROJECT_ROOT / "docs" / "qualifications" / "p0a-installed-wheel-2026-08-10.json"
            ).read_text(encoding="utf-8")
        )
        self.assertEqual("passed", audit["result"])
        self.assertRegex(audit["distribution"]["sha256"], r"\A[0-9a-f]{64}\Z")
        self.assertIn(
            "does not satisfy the final P0-A human exit criterion",
            audit["limitations"][-1],
        )

        human_receipt = json.loads(
            (
                PROJECT_ROOT / "docs" / "qualifications" / "p0a-unfamiliar-user-2026-08-11.json"
            ).read_text(encoding="utf-8")
        )
        self.assertEqual("passed", human_receipt["result"])
        self.assertFalse(human_receipt["participant"]["prior_product_exposure"])
        self.assertEqual(0, human_receipt["observations"]["assistance_count"])
        self.assertLessEqual(
            human_receipt["observations"]["elapsed_seconds_after_install_upper_bound"],
            300,
        )
        self.assertTrue(human_receipt["observations"]["opened_report"])
        self.assertEqual(
            [
                ("approve", "patch"),
                ("reject", "do_not_patch"),
            ],
            [
                (outcome["decision"], outcome["recommended_action"])
                for outcome in human_receipt["observations"]["outcomes"]
            ],
        )
        self.assertEqual(
            {
                "causal_support",
                "passing_controls",
                "wrong_component",
                "excessive_surface",
                "failed_negative_control",
            },
            set(human_receipt["observations"]["comprehension"]["criteria_met"]),
        )
        self.assertRegex(human_receipt["distribution"]["sha256"], r"\A[0-9a-f]{64}\Z")

    def test_github_review_guide_preserves_candidate_and_privilege_boundaries(self) -> None:
        contents = (PROJECT_ROOT / "docs" / "github-review-publication.md").read_text(
            encoding="utf-8"
        )

        self.assertIn("pull_request.head.sha", contents)
        self.assertIn("`pull_request_target` is deliberately unsupported", contents)
        self.assertIn("requires neither a token nor a secret", contents)
        self.assertIn("only its digest and byte count are retained", contents)
        self.assertIn("does **not** create a Check Run", contents)
        self.assertIn("not permission to merge", contents)
        self.assertIn("not digital signatures", contents)
        self.assertIn("same protected job", contents)

    def test_github_action_guide_preserves_fork_token_and_branch_boundaries(self) -> None:
        contents = (PROJECT_ROOT / "docs" / "github-action.md").read_text(encoding="utf-8")

        self.assertIn(
            "permissions:\n  contents: read\n  pull-requests: read\n  checks: write",
            contents,
        )
        self.assertIn("github-token: ${{ github.token }}", contents)
        self.assertIn("never replace it with `uses: ./`", contents)
        self.assertIn("Causure gate", contents)
        self.assertIn("A fork's token\nis read-only", contents)
        self.assertIn("Do not enable GitHub's setting", contents)
        self.assertIn("Do not change this workflow to `pull_request_target`", contents)
        self.assertIn("At most 50 decision-affecting findings", contents)
        self.assertIn("The token is read only", contents)
        self.assertIn("at most 500 changed", contents)
        self.assertIn("causure github-configure", contents)
        self.assertIn("--kind case_generator", contents)
        self.assertIn("repository-root", contents)
        self.assertIn("`dependabot[bot]`", contents)
        self.assertIn("trusted case-generation guide", contents)
        self.assertIn("not_applicable", contents)
        self.assertIn("GitHub Enterprise Server is not supported", contents)
        self.assertRegex(
            contents,
            r"actions/upload-artifact@[0-9a-f]{40} # v[0-9]+\.[0-9]+\.[0-9]+",
        )

    def test_trusted_case_generation_guide_preserves_execution_boundaries(self) -> None:
        contents = (PROJECT_ROOT / "docs" / "trusted-case-generation.md").read_text(
            encoding="utf-8"
        )
        decision = (
            PROJECT_ROOT
            / "docs"
            / "decisions"
            / "0029-run-case-generators-only-from-a-protected-base.md"
        ).read_text(encoding="utf-8")

        self.assertIn("protected base", contents)
        self.assertIn("candidate head", contents)
        self.assertIn("not an operating-system sandbox", contents)
        self.assertIn("does not import or execute candidate code", contents)
        self.assertIn("Generator-backed fork pull requests fail", contents)
        self.assertIn("repository-root: candidate", contents)
        self.assertIn("trusted-case-generation.json", contents)
        self.assertIn("it is not evidence that GitHub permissions", contents)
        self.assertIn("schema `3.0`", contents)
        self.assertIn("Never add the candidate root to Python's import path", decision)
        self.assertIn("Local synthetic qualification does not replace", decision)

    def test_tfvc_guide_preserves_interactive_first_sign_in(self) -> None:
        contents = (PROJECT_ROOT / "docs" / "tfvc-and-classic-pipeline.md").read_text(
            encoding="utf-8"
        )

        self.assertIn("Visual Studio 2026", contents)
        self.assertIn("Do **not** add `/noprompt` to this first command", contents)

    def test_tfvc_guide_distinguishes_validation_from_the_real_gate(self) -> None:
        contents = (PROJECT_ROOT / "docs" / "tfvc-and-classic-pipeline.md").read_text(
            encoding="utf-8"
        )

        self.assertIn("is not the production gate", contents)
        self.assertIn("azure_review_gate.ps1", contents)
        self.assertIn("triggering changeset or gated shelveset", contents)

    def test_approval_guide_preserves_identity_and_decision_boundaries(self) -> None:
        contents = (PROJECT_ROOT / "docs" / "approval-assertions.md").read_text(encoding="utf-8")

        self.assertIn("Do not put the authority private", contents)
        self.assertIn("not an approver", contents)
        self.assertIn("gate_effect: record_only", contents)
        self.assertIn("still returns the original", contents)
        self.assertIn("every decision-affecting finding", contents)

    def test_team_guide_preserves_identity_and_storage_boundaries(self) -> None:
        contents = (PROJECT_ROOT / "docs" / "team-service-foundation.md").read_text(
            encoding="utf-8"
        )

        self.assertIn("never accepted from a client request", contents)
        self.assertIn("compare-and-swap", contents)
        self.assertIn("--authoritative-head-sha256", contents)
        self.assertIn("does not make local files", contents)
        self.assertIn("immutable. A hosted service", contents)
        self.assertIn("full, contiguous sequence beginning at one", contents)
        self.assertIn("not a digital signature", contents)

        classic_ci = (PROJECT_ROOT / "scripts" / "classic_ci.ps1").read_text(encoding="utf-8")
        self.assertIn("team-authorize", classic_ci)
        self.assertIn("team-audit-append", classic_ci)
        self.assertIn("team-audit-export", classic_ci)
        self.assertIn("team-audit-verify", classic_ci)
        self.assertIn("team-store-init", classic_ci)
        self.assertIn("team-store-policy-put", classic_ci)
        self.assertIn("team-store-policy-get", classic_ci)
        self.assertIn("team-store-head", classic_ci)
        self.assertIn("team-store-append", classic_ci)
        self.assertIn("team-store-event-get", classic_ci)
        self.assertIn("team-store-export", classic_ci)
        self.assertIn("team-store-backup", classic_ci)

    def test_sqlite_store_guide_preserves_transaction_and_retention_boundaries(self) -> None:
        contents = (PROJECT_ROOT / "docs" / "team-sqlite-store.md").read_text(encoding="utf-8")

        self.assertIn("BEGIN IMMEDIATE", contents)
        self.assertIn("expected head", contents)
        self.assertIn("leaves no partial row or fork", contents)
        self.assertIn("not an immutable-retention claim", contents)
        self.assertIn("does not make the underlying", contents)
        self.assertIn("filesystem enforce a retention lock", contents)
        self.assertIn("Do not place a production database on an SMB/NFS share", contents)
        self.assertIn("refuses to overwrite an existing", contents)

    def test_team_http_guide_preserves_identity_and_side_effect_boundaries(self) -> None:
        contents = (PROJECT_ROOT / "docs" / "team-http-api.md").read_text(encoding="utf-8")

        self.assertIn("it never parses", contents)
        self.assertIn("`Authorization`, `REMOTE_USER`", contents)
        self.assertIn("AuthenticatedTeamIdentity", contents)
        self.assertIn("request_integrity_verified", contents)
        self.assertIn("never accepts a tenant, role, decision ID, event ID, or timestamp", contents)
        self.assertIn("does not perform or authorize", contents)
        self.assertIn("external side effect", contents)
        self.assertIn("single-host pilot", contents)
        self.assertIn("not a production HTTP server", contents)
        self.assertIn("TeamAdmissionControlMiddleware", contents)
        self.assertIn("until the WSGI response iterable finishes", contents)
        self.assertIn("ignores `Forwarded`, `X-Forwarded-For`", contents)
        self.assertIn("global bucket is the hard process-local", contents)
        self.assertIn("`/readyz` bypasses traffic capacity", contents)
        self.assertIn("independent buckets and concurrency slots", contents)

    def test_team_hosting_guide_preserves_edge_lifecycle_and_qualification_boundaries(
        self,
    ) -> None:
        contents = (PROJECT_ROOT / "docs" / "team-service-hosting.md").read_text(encoding="utf-8")

        self.assertIn("trusted same-host HTTPS reverse", contents)
        self.assertIn("Only the canonical loopback addresses", contents)
        self.assertIn("refresh_configuration_sha256", contents)
        self.assertIn("launcher intentionally ignores `Forwarded`", contents)
        self.assertIn("launcher trusts none of", contents)
        self.assertIn("Leave `per_source_requests_per_window` as `null`", contents)
        self.assertIn("one launcher process only", contents)
        self.assertIn("graceful stop window of at least 30 seconds", contents)
        self.assertIn("24 MiB application limit", contents)
        self.assertIn("It has not been qualified as a", contents)
        self.assertIn("production deployment merely", contents)

        classic_ci = (PROJECT_ROOT / "scripts" / "classic_ci.ps1").read_text(encoding="utf-8")
        self.assertIn("importlib.metadata.version('waitress') == '3.0.2'", classic_ci)

    def test_windows_service_guide_preserves_identity_config_and_readiness_boundaries(
        self,
    ) -> None:
        contents = (PROJECT_ROOT / "docs" / "team-windows-service.md").read_text(encoding="utf-8")

        self.assertIn("machine-wide CPython installation", contents)
        self.assertIn("register the service from a per-user Python", contents)
        self.assertIn("NT SERVICE\\CausureTeam", contents)
        self.assertIn("contains no token", contents)
        self.assertIn("deliberately leaves the service stopped", contents)
        self.assertIn("SCM `running` is process state, not application readiness", contents)
        self.assertIn("Editing `team-host.json` in place", contents)
        self.assertIn("refuses to run unless SCM reports the service stopped", contents)
        self.assertIn("never deletes operator", contents)
        self.assertIn("unit suite does not register a service", contents)
        self.assertIn("qualify_windows_service.ps1", contents)
        self.assertIn("not signed provenance or", contents)

        classic_ci = (PROJECT_ROOT / "scripts" / "classic_ci.ps1").read_text(encoding="utf-8")
        self.assertIn("importlib.metadata.version('pywin32') == '312'", classic_ci)
        self.assertIn("qualify_windows_service.ps1", classic_ci)

        qualifier = (PROJECT_ROOT / "scripts" / "qualify_windows_service.ps1").read_text(
            encoding="utf-8"
        )
        self.assertIn(r"C:\ProgramData\CausureQualification", qualifier)
        self.assertIn("the fixed qualification service already exists", qualifier)
        self.assertIn("serviceAbsentAfterCleanup", qualifier)
        self.assertIn("Remove-Item -LiteralPath $resolvedQualificationRoot", qualifier)
        self.assertNotIn("LocalSystem", qualifier)

        evidence = json.loads(
            (
                PROJECT_ROOT / "docs" / "qualifications" / "windows-service-2026-08-03.json"
            ).read_text(encoding="utf-8")
        )
        self.assertEqual("passed", evidence["result"])
        # The retained qualification predates ADR 0030 and must preserve the exact
        # service identity that was actually exercised.
        self.assertEqual("NT SERVICE\\ProofBeforePatchTeam", evidence["registration"]["account"])
        self.assertEqual(200, evidence["lifecycle"]["health_status"])
        self.assertEqual(200, evidence["lifecycle"]["readiness_status"])
        self.assertTrue(evidence["lifecycle"]["adapter_removed_service"])
        self.assertTrue(evidence["cleanup"]["service_absent"])
        self.assertTrue(evidence["cleanup"]["qualification_root_removed"])

    def test_evidence_console_guide_preserves_privacy_and_scope_boundaries(self) -> None:
        contents = (PROJECT_ROOT / "docs" / "team-evidence-console.md").read_text(encoding="utf-8")

        self.assertIn("initial operational evidence console", contents)
        self.assertIn("rather than the full", contents)
        self.assertIn("change-case dashboard guide", contents)
        self.assertIn("Payload bodies are never loaded", contents)
        self.assertIn("SQLite read transaction", contents)
        self.assertIn("before learning whether events exist", contents)
        self.assertIn("more than 100 event summaries", contents)
        self.assertIn("no JavaScript, no forms", contents)
        self.assertIn("not a signed artifact", contents)

    def test_change_case_dashboard_guide_preserves_minimization_and_live_check_boundaries(
        self,
    ) -> None:
        contents = (PROJECT_ROOT / "docs" / "team-change-case-dashboard.md").read_text(
            encoding="utf-8"
        )

        self.assertIn("without copying its raw evidence", contents)
        self.assertIn("canonical unpadded base64url", contents)
        self.assertIn("both roll back", contents)
        self.assertIn("point-in-time evidence", contents)
        self.assertIn("does not contact", contents)
        self.assertIn("approval justification", contents)
        self.assertIn("automatically migrates a valid version-1", contents)
        self.assertIn("not WORM retention", contents)

    def test_investigation_queue_guide_preserves_candidate_and_atomicity_boundaries(
        self,
    ) -> None:
        contents = (PROJECT_ROOT / "docs" / "team-investigation-queue.md").read_text(
            encoding="utf-8"
        )

        self.assertIn("queue never creates a", contents)
        self.assertIn("change case automatically", contents)
        self.assertIn("canonical unpadded base64url", contents)
        self.assertIn('"candidate_only": true', contents)
        self.assertIn('"causal_claims_inferred": false', contents)
        self.assertIn("does **not** retain the fixture body", contents)
        self.assertIn("appends exactly one immutable", contents)
        self.assertIn("closed item requires exactly one resolution", contents)
        self.assertIn("both the expected investigation revision and expected tenant", contents)
        self.assertIn("leaves no record, event, or head advance", contents)
        self.assertIn("not WORM retention", contents)

    def test_entra_guide_preserves_identity_and_rollover_boundaries(self) -> None:
        contents = (PROJECT_ROOT / "docs" / "team-entra-bearer-host.md").read_text(encoding="utf-8")

        self.assertIn("or contact Microsoft Entra", contents)
        self.assertIn("never follows a `jku`, `x5u`", contents)
        self.assertIn("no environment proxy, no redirects", contents)
        self.assertIn("refuses to overwrite an invalid existing snapshot", contents)
        self.assertIn("request that triggered refresh is not retried", contents)
        self.assertIn("CoordinatedEntraAccessTokenVerifier", contents)
        self.assertIn("after the WSGI worker process has forked", contents)
        self.assertIn("unowned fetch", contents)
        self.assertIn("not a distributed lease", contents)
        self.assertIn("Never delete, rotate, or replace a live owner-lock file", contents)
        self.assertIn("never extends that verifier's original", contents)
        self.assertIn("`expires_at`", contents)
        self.assertIn("maps only `(tid, oid)`", contents)
        self.assertIn("Current Team roles", contents)
        self.assertIn("intentionally ignores `X-Forwarded-Proto`", contents)
        self.assertIn("never echo a token", contents)
        self.assertIn("Do not call this adapter", contents)
        self.assertIn("TeamAdmissionControlMiddleware", contents)
        self.assertIn("before the Entra middleware can parse", contents)
        self.assertIn("ignores forwarding headers by default", contents)
        self.assertIn("independent in every WSGI process", contents)

    def test_canary_guide_preserves_prospective_and_deployment_boundaries(self) -> None:
        contents = (PROJECT_ROOT / "docs" / "canary-outcome-comparison.md").read_text(
            encoding="utf-8"
        )

        self.assertIn("does not deploy, route traffic, fetch telemetry", contents)
        self.assertIn("timestamp alone is not proof", contents)
        self.assertIn("Only an `approve` or `conditional_pass`", contents)
        self.assertIn("never dereferences", contents)
        self.assertIn("allocates the policy's total error probability", contents)
        self.assertIn("changes only the `continue` process exit", contents)
        self.assertIn("A new prospective policy is required", contents)
        self.assertIn("traffic assignment was actually", contents)
        self.assertIn("independent operational rollback controls", contents)

    def test_openai_quota_guide_preserves_cost_and_qualification_boundaries(self) -> None:
        contents = (PROJECT_ROOT / "docs" / "openai-compatible-quota-proxy.md").read_text(
            encoding="utf-8"
        )

        self.assertIn("full configured maximum billable", contents)
        self.assertIn("input, not a local tokenizer estimate", contents)
        self.assertIn("must never exist in the worker image", contents)
        self.assertIn("without redirects or an environment proxy", contents)
        self.assertIn("does not silently assign zero cost", contents)
        self.assertIn("threshold pricing, cache-write premiums", contents)
        self.assertIn("not a qualified hosted", contents)
        self.assertIn("digest-pinned, split-edge Docker pilot", contents)

    def test_openai_quota_pilot_guide_preserves_secret_and_qualification_boundaries(
        self,
    ) -> None:
        contents = (PROJECT_ROOT / "docs" / "openai-quota-pilot.md").read_text(encoding="utf-8")

        self.assertIn("never prints a secret", contents)
        self.assertIn("Never use an SMB/NFS path", contents)
        self.assertIn("The host ACL remains the enforcing boundary", contents)
        self.assertIn("no live provider API request", contents)
        self.assertIn("direct TCP connection", contents)
        self.assertIn("non-internal", contents)
        self.assertIn("not production hard-spend qualification", contents)
        self.assertIn("Adding `--volumes` deletes", contents)


if __name__ == "__main__":
    unittest.main()
