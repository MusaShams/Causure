"""Package metadata stays aligned across distribution surfaces."""

from __future__ import annotations

import hashlib
import tomllib
import unittest

from causure import (
    CanaryComparisonResult,
    CanaryPolicy,
    CoordinatedEntraAccessTokenVerifier,
    EntraCoordinatedRefreshStatus,
    EntraManagedRefreshStatus,
    GitHubActionRun,
    GitHubCheckRunRequest,
    GitHubReviewPublication,
    GitHubReviewVerification,
    LocalFileEntraRefreshCoordinator,
    ManagedEntraAccessTokenVerifier,
    OpenAIQuotaController,
    OpenAIQuotaHostConfiguration,
    OpenAIQuotaPilotState,
    OpenAIQuotaWSGIApplication,
    SQLiteOpenAIQuotaStore,
    TeamAdmissionControlMiddleware,
    TeamAdmissionStatus,
    TeamCaseRecord,
    TeamCaseRecordSnapshot,
    TeamHostConfiguration,
    TeamHostRuntime,
    TeamHostServer,
    TeamInvestigationRecord,
    TeamInvestigationRecordSnapshot,
    TeamWindowsServiceRecoveryPolicy,
    TeamWindowsServiceRegistration,
    __version__,
    create_github_check_run_request,
    create_team_host_server,
    get_team_windows_service_recovery_policy,
    github_context_from_environment,
    install_team_windows_service,
    parse_canary_result_bytes,
    parse_github_check_run_request_bytes,
    parse_github_review_publication_bytes,
    prepare_openai_quota_pilot_state,
    render_team_case_dashboard,
    render_team_investigation_dashboard,
    run_github_action,
    serve_openai_quota_host,
    serve_team_host,
    verify_github_check_run_receipt,
    verify_github_review_publication,
)
from causure.constants import ENGINE_VERSION, PACKAGE_VERSION
from tests.helpers import PROJECT_ROOT


class PackageMetadataTests(unittest.TestCase):
    def test_versions_are_aligned(self) -> None:
        pyproject = tomllib.loads((PROJECT_ROOT / "pyproject.toml").read_text(encoding="utf-8"))

        self.assertEqual(PACKAGE_VERSION, __version__)
        self.assertEqual(PACKAGE_VERSION, ENGINE_VERSION)
        self.assertEqual(PACKAGE_VERSION, pyproject["project"]["version"])

    def test_demo_cases_are_declared_as_package_data(self) -> None:
        pyproject = tomllib.loads((PROJECT_ROOT / "pyproject.toml").read_text(encoding="utf-8"))

        self.assertEqual(
            ["py.typed", "demo/*.json"],
            pyproject["tool"]["setuptools"]["package-data"]["causure"],
        )

    def test_apache_license_metadata_and_standard_text_are_aligned(self) -> None:
        pyproject = tomllib.loads((PROJECT_ROOT / "pyproject.toml").read_text(encoding="utf-8"))
        license_bytes = (PROJECT_ROOT / "LICENSE").read_bytes().replace(b"\r\n", b"\n")

        self.assertEqual("Apache-2.0", pyproject["project"]["license"])
        self.assertEqual(["LICENSE"], pyproject["project"]["license-files"])
        self.assertEqual(
            "cfc7749b96f63bd31c3c42b5c471bf756814053e847c10f3eb003417bc523d30",
            hashlib.sha256(license_bytes).hexdigest(),
        )

    def test_crypto_extras_are_pinned_and_included_for_development(self) -> None:
        pyproject = tomllib.loads((PROJECT_ROOT / "pyproject.toml").read_text(encoding="utf-8"))
        extras = pyproject["project"]["optional-dependencies"]

        self.assertEqual(["cryptography==50.0.0"], extras["approval"])
        self.assertEqual(["cryptography==50.0.0"], extras["attestation"])
        self.assertEqual(
            ["cryptography==50.0.0", "PyJWT==2.13.0"],
            extras["entra"],
        )
        self.assertEqual(
            ["cryptography==50.0.0", "PyJWT==2.13.0", "waitress==3.0.2"],
            extras["service"],
        )
        self.assertEqual(
            [
                "cryptography==50.0.0",
                "PyJWT==2.13.0",
                "pywin32==312; sys_platform == 'win32'",
                "waitress==3.0.2",
            ],
            extras["windows-service"],
        )
        self.assertIn("cryptography==50.0.0", extras["dev"])
        self.assertIn("PyJWT==2.13.0", extras["dev"])
        self.assertIn("pywin32==312; sys_platform == 'win32'", extras["dev"])
        self.assertIn("waitress==3.0.2", extras["dev"])
        self.assertEqual(["waitress==3.0.2"], extras["quota-service"])
        self.assertEqual(
            ["cryptography==50.0.0", "waitress==3.0.2"],
            extras["quota-pilot"],
        )

        self.assertEqual(
            "causure.team_windows_service_cli:main",
            pyproject["project"]["scripts"]["causure-windows-service"],
        )

    def test_managed_and_coordinated_entra_refresh_types_are_public(self) -> None:
        self.assertEqual(
            "ManagedEntraAccessTokenVerifier",
            ManagedEntraAccessTokenVerifier.__name__,
        )
        self.assertEqual("EntraManagedRefreshStatus", EntraManagedRefreshStatus.__name__)
        self.assertEqual(
            "CoordinatedEntraAccessTokenVerifier",
            CoordinatedEntraAccessTokenVerifier.__name__,
        )
        self.assertEqual(
            "EntraCoordinatedRefreshStatus",
            EntraCoordinatedRefreshStatus.__name__,
        )
        self.assertEqual(
            "LocalFileEntraRefreshCoordinator",
            LocalFileEntraRefreshCoordinator.__name__,
        )

    def test_team_admission_types_are_public(self) -> None:
        self.assertEqual(
            "TeamAdmissionControlMiddleware",
            TeamAdmissionControlMiddleware.__name__,
        )
        self.assertEqual("TeamAdmissionStatus", TeamAdmissionStatus.__name__)

    def test_openai_quota_types_are_public(self) -> None:
        self.assertEqual("OpenAIQuotaController", OpenAIQuotaController.__name__)
        self.assertEqual("OpenAIQuotaWSGIApplication", OpenAIQuotaWSGIApplication.__name__)
        self.assertEqual("SQLiteOpenAIQuotaStore", SQLiteOpenAIQuotaStore.__name__)
        self.assertEqual("OpenAIQuotaHostConfiguration", OpenAIQuotaHostConfiguration.__name__)
        self.assertEqual("OpenAIQuotaPilotState", OpenAIQuotaPilotState.__name__)
        self.assertEqual("serve_openai_quota_host", serve_openai_quota_host.__name__)
        self.assertEqual(
            "prepare_openai_quota_pilot_state",
            prepare_openai_quota_pilot_state.__name__,
        )

    def test_canary_types_are_public(self) -> None:
        self.assertEqual("CanaryPolicy", CanaryPolicy.__name__)
        self.assertEqual("CanaryComparisonResult", CanaryComparisonResult.__name__)
        self.assertEqual("parse_canary_result_bytes", parse_canary_result_bytes.__name__)

    def test_github_review_contract_is_public(self) -> None:
        self.assertEqual("GitHubActionRun", GitHubActionRun.__name__)
        self.assertEqual("GitHubCheckRunRequest", GitHubCheckRunRequest.__name__)
        self.assertEqual("GitHubReviewPublication", GitHubReviewPublication.__name__)
        self.assertEqual("GitHubReviewVerification", GitHubReviewVerification.__name__)
        self.assertEqual(
            "github_context_from_environment",
            github_context_from_environment.__name__,
        )
        self.assertEqual(
            "create_github_check_run_request",
            create_github_check_run_request.__name__,
        )
        self.assertEqual(
            "parse_github_check_run_request_bytes",
            parse_github_check_run_request_bytes.__name__,
        )
        self.assertEqual(
            "parse_github_review_publication_bytes",
            parse_github_review_publication_bytes.__name__,
        )
        self.assertEqual(
            "run_github_action",
            run_github_action.__name__,
        )
        self.assertEqual(
            "verify_github_check_run_receipt",
            verify_github_check_run_receipt.__name__,
        )
        self.assertEqual(
            "verify_github_review_publication",
            verify_github_review_publication.__name__,
        )

    def test_team_case_dashboard_types_are_public(self) -> None:
        self.assertEqual("TeamCaseRecord", TeamCaseRecord.__name__)
        self.assertEqual("TeamCaseRecordSnapshot", TeamCaseRecordSnapshot.__name__)
        self.assertEqual("render_team_case_dashboard", render_team_case_dashboard.__name__)

    def test_team_investigation_dashboard_types_are_public(self) -> None:
        self.assertEqual("TeamInvestigationRecord", TeamInvestigationRecord.__name__)
        self.assertEqual(
            "TeamInvestigationRecordSnapshot",
            TeamInvestigationRecordSnapshot.__name__,
        )
        self.assertEqual(
            "render_team_investigation_dashboard",
            render_team_investigation_dashboard.__name__,
        )

    def test_team_host_types_are_public(self) -> None:
        self.assertEqual("TeamHostConfiguration", TeamHostConfiguration.__name__)
        self.assertEqual("TeamHostRuntime", TeamHostRuntime.__name__)
        self.assertEqual("TeamHostServer", TeamHostServer.__name__)
        self.assertEqual("create_team_host_server", create_team_host_server.__name__)
        self.assertEqual("serve_team_host", serve_team_host.__name__)

    def test_team_windows_service_types_are_public(self) -> None:
        self.assertEqual(
            "TeamWindowsServiceRegistration",
            TeamWindowsServiceRegistration.__name__,
        )
        self.assertEqual(
            "install_team_windows_service",
            install_team_windows_service.__name__,
        )
        self.assertEqual(
            "TeamWindowsServiceRecoveryPolicy",
            TeamWindowsServiceRecoveryPolicy.__name__,
        )
        self.assertEqual(
            "get_team_windows_service_recovery_policy",
            get_team_windows_service_recovery_policy.__name__,
        )


if __name__ == "__main__":
    unittest.main()
