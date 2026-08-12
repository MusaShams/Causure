"""First-run demo, initialization, and diagnostic contracts."""

from __future__ import annotations

import contextlib
import io
import json
import tempfile
import unittest
from importlib import resources
from pathlib import Path

from causure.cli import main
from causure.onboarding import (
    DEMO_STORIES,
    inspect_environment,
    parse_project_configuration,
)
from causure.policy import parse_policy
from tests.helpers import PROJECT_ROOT


def _file_snapshot(root: Path) -> dict[str, bytes]:
    return {
        path.relative_to(root).as_posix(): path.read_bytes()
        for path in sorted(root.rglob("*"))
        if path.is_file()
    }


class OnboardingTests(unittest.TestCase):
    def test_empty_and_short_help_lead_with_the_golden_path(self) -> None:
        for arguments in ([], ["--help"]):
            with self.subTest(arguments=arguments):
                stdout = io.StringIO()
                with contextlib.redirect_stdout(stdout):
                    exit_code = main(arguments)

                help_text = stdout.getvalue()
                self.assertEqual(0, exit_code)
                self.assertIn("causure demo", help_text)
                self.assertIn("in three commands", help_text)
                self.assertIn("causure case create", help_text)
                self.assertIn("causure github-configure --help", help_text)
                self.assertIn("causure --help-all", help_text)
                self.assertNotIn("team-store-append", help_text)

    def test_full_help_retains_advanced_automation_commands(self) -> None:
        stdout = io.StringIO()
        with contextlib.redirect_stdout(stdout):
            exit_code = main(["--help-all"])

        self.assertEqual(0, exit_code)
        self.assertIn("team-store-append", stdout.getvalue())
        self.assertIn("azure-publish", stdout.getvalue())

    def test_demo_creates_both_expected_decisions_deterministically(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            first = root / "first"
            second = root / "second"

            for output in (first, second):
                stdout = io.StringIO()
                with contextlib.redirect_stdout(stdout):
                    exit_code = main(["demo", "--output", str(output)])
                self.assertEqual(0, exit_code)
                self.assertIn("PATCH: APPROVE", stdout.getvalue())
                self.assertIn("DO_NOT_PATCH: REJECT", stdout.getvalue())
                self.assertIn("Why:", stdout.getvalue())
                self.assertIn("The gate approved the supported narrow change", stdout.getvalue())

            result = json.loads((first / "demo-result.json").read_text(encoding="utf-8"))
            self.assertTrue(result["synthetic"])
            self.assertEqual(
                [("approve", "patch"), ("reject", "do_not_patch")],
                [(story["decision"], story["recommended_action"]) for story in result["stories"]],
            )
            self.assertEqual(_file_snapshot(first), _file_snapshot(second))
            self.assertIn(
                "**APPROVE**", (first / "reports/01-justified-minimal-patch.md").read_text()
            )
            self.assertIn(
                "**REJECT**",
                (first / "reports/02-overbroad-change-rejected.md").read_text(),
            )

    def test_demo_refuses_to_overwrite_an_existing_directory(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            output = Path(directory) / "demo"
            output.mkdir()
            sentinel = output / "owned-by-user.txt"
            sentinel.write_text("keep", encoding="utf-8")
            stderr = io.StringIO()

            with contextlib.redirect_stderr(stderr):
                exit_code = main(["demo", "--output", str(output)])

            self.assertEqual(2, exit_code)
            self.assertIn("already exists", stderr.getvalue())
            self.assertEqual("keep", sentinel.read_text(encoding="utf-8"))
            self.assertEqual({"owned-by-user.txt"}, set(_file_snapshot(output)))

    def test_bundled_demo_cases_match_the_canonical_examples(self) -> None:
        package_root = resources.files("causure").joinpath("demo")
        for story in DEMO_STORIES:
            with self.subTest(story=story.story_id):
                bundled = json.loads(package_root.joinpath(story.resource_name).read_text())
                canonical = json.loads(
                    (PROJECT_ROOT / "examples" / "change-cases" / story.resource_name).read_text(
                        encoding="utf-8"
                    )
                )
                self.assertEqual(canonical, bundled)

    def test_init_creates_a_small_valid_project_without_overwriting(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            project = Path(directory) / "Refund Agent"
            stdout = io.StringIO()
            with contextlib.redirect_stdout(stdout):
                exit_code = main(["init", str(project)])

            self.assertEqual(0, exit_code)
            self.assertIn("Initialized Causure project", stdout.getvalue())
            control = project / ".causure"
            configuration = json.loads((control / "config.json").read_text())
            self.assertEqual("refund-agent", configuration["project_id"])
            self.assertEqual("disabled", configuration["raw_trace_storage"])
            self.assertEqual("3.0", configuration["schema_version"])
            self.assertEqual(30, configuration["github"]["artifact_retention_days"])
            self.assertEqual([], configuration["github"]["components"])
            self.assertEqual([], configuration["trusted_adapter_entry_points"])
            parse_project_configuration(configuration)
            parse_policy(json.loads((control / "policy.json").read_text()))
            self.assertTrue((control / "adapters/README.md").is_file())
            self.assertIn("artifacts/", (control / ".gitignore").read_text())
            self.assertIn("causure investigate", stdout.getvalue())
            project_readme = (control / "README.md").read_text(encoding="utf-8")
            self.assertIn("causure investigate", project_readme)
            self.assertIn("causure case create", project_readme)

            before = _file_snapshot(project)
            stderr = io.StringIO()
            with contextlib.redirect_stderr(stderr):
                repeated_exit = main(["init", str(project)])
            self.assertEqual(2, repeated_exit)
            self.assertIn("already exists", stderr.getvalue())
            self.assertEqual(before, _file_snapshot(project))

    def test_doctor_is_read_only_for_an_initialized_project(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            project = Path(directory) / "project"
            with contextlib.redirect_stdout(io.StringIO()):
                self.assertEqual(0, main(["init", str(project), "--project-id", "agent-one"]))
            before = _file_snapshot(project)
            stdout = io.StringIO()

            with contextlib.redirect_stdout(stdout):
                exit_code = main(["doctor", str(project), "--format", "json"])

            self.assertEqual(0, exit_code)
            document = json.loads(stdout.getvalue())
            self.assertIn(document["status"], {"ready", "ready_with_warnings"})
            self.assertNotIn("fail", {check["status"] for check in document["checks"]})
            self.assertEqual(before, _file_snapshot(project))

    def test_doctor_explains_how_to_initialize_an_unconfigured_directory(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            stdout = io.StringIO()
            with contextlib.redirect_stdout(stdout):
                exit_code = main(["doctor", directory])

            self.assertEqual(0, exit_code)
            self.assertIn("CAUSURE-DOCTOR-CONFIG", stdout.getvalue())
            self.assertIn("causure init", stdout.getvalue())

    def test_doctor_fails_closed_for_an_invalid_project_configuration(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            project = Path(directory) / "project"
            with contextlib.redirect_stdout(io.StringIO()):
                self.assertEqual(0, main(["init", str(project)]))
            configuration_path = project / ".causure/config.json"
            configuration = json.loads(configuration_path.read_text())
            configuration["adapter_directory"] = "../untrusted"
            configuration_path.write_text(json.dumps(configuration), encoding="utf-8")
            stdout = io.StringIO()

            with contextlib.redirect_stdout(stdout):
                exit_code = main(["doctor", str(project), "--format", "json"])

            self.assertEqual(2, exit_code)
            document = json.loads(stdout.getvalue())
            self.assertEqual("failed", document["status"])
            config_check = next(
                check for check in document["checks"] if check["code"] == "CAUSURE-DOCTOR-CONFIG"
            )
            self.assertEqual("fail", config_check["status"])

    def test_github_configure_adds_a_mapping_without_manual_json(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            project = Path(directory) / "project"
            with contextlib.redirect_stdout(io.StringIO()):
                self.assertEqual(0, main(["init", str(project)]))
            stdout = io.StringIO()

            with contextlib.redirect_stdout(stdout):
                exit_code = main(
                    [
                        "github-configure",
                        "--project",
                        str(project),
                        "--component-id",
                        "refund-tool",
                        "--component",
                        "tool_description",
                        "--path",
                        "agent/tools/**/*.py",
                        "--case",
                        "evidence/refund.case.json",
                        "--retention-days",
                        "21",
                    ]
                )

            self.assertEqual(0, exit_code)
            self.assertIn("Configured GitHub component refund-tool", stdout.getvalue())
            document = json.loads((project / ".causure/config.json").read_text(encoding="utf-8"))
            configuration = parse_project_configuration(document)
            self.assertEqual(21, configuration.github.artifact_retention_days)
            self.assertEqual("refund-tool", configuration.github.components[0].component_id)
            self.assertEqual(
                ("agent/tools/**/*.py",),
                configuration.github.components[0].paths,
            )
            self.assertIsNone(configuration.github.components[0].case_generator_adapter_id)

            before = _file_snapshot(project)
            stderr = io.StringIO()
            with contextlib.redirect_stderr(stderr):
                repeated = main(
                    [
                        "github-configure",
                        "--project",
                        str(project),
                        "--component-id",
                        "refund-tool",
                        "--component",
                        "tool_description",
                        "--path",
                        "agent/tools/refund.py",
                        "--case",
                        "evidence/refund.case.json",
                    ]
                )
            self.assertEqual(2, repeated)
            self.assertIn("already exists", stderr.getvalue())
            self.assertEqual(before, _file_snapshot(project))

    def test_legacy_project_configuration_remains_readable(self) -> None:
        configuration = parse_project_configuration(
            {
                "adapter_directory": "adapters",
                "artifact_directory": "artifacts",
                "policy_file": "policy.json",
                "project_id": "legacy-agent",
                "raw_trace_storage": "disabled",
                "schema_version": "1.0",
            }
        )

        self.assertEqual((), configuration.github.components)
        self.assertEqual(30, configuration.github.artifact_retention_days)

    def test_version_two_project_configuration_remains_readable(self) -> None:
        configuration = parse_project_configuration(
            {
                "adapter_directory": "adapters",
                "artifact_directory": "artifacts",
                "github": {
                    "artifact_retention_days": 30,
                    "components": [
                        {
                            "case_file": "evidence/refund.case.json",
                            "component": "tool_description",
                            "component_id": "refund-tool",
                            "paths": ["agent/tools/**/*.py"],
                        }
                    ],
                },
                "policy_file": "policy.json",
                "project_id": "legacy-agent",
                "raw_trace_storage": "disabled",
                "schema_version": "2.0",
                "trusted_adapter_entry_points": [
                    {
                        "adapter_id": "company-replay",
                        "entry_point": "company_agent.replay:run",
                        "kind": "replay",
                    }
                ],
            }
        )

        self.assertIsNone(configuration.github.components[0].case_generator_adapter_id)
        self.assertEqual("replay", configuration.trusted_adapter_entry_points[0].kind)

    def test_adapter_configure_registers_but_does_not_import_an_entry_point(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            project = Path(directory) / "project"
            with contextlib.redirect_stdout(io.StringIO()):
                self.assertEqual(0, main(["init", str(project)]))
            stdout = io.StringIO()

            with contextlib.redirect_stdout(stdout):
                exit_code = main(
                    [
                        "adapter-configure",
                        "--project",
                        str(project),
                        "--adapter-id",
                        "company-replay",
                        "--kind",
                        "replay",
                        "--entry-point",
                        "company_agent.replay:run",
                    ]
                )

            self.assertEqual(0, exit_code)
            self.assertIn("Registration does not execute", stdout.getvalue())
            configuration = parse_project_configuration(
                json.loads((project / ".causure/config.json").read_text(encoding="utf-8"))
            )
            self.assertEqual(1, len(configuration.trusted_adapter_entry_points))
            self.assertEqual(
                "company_agent.replay:run",
                configuration.trusted_adapter_entry_points[0].entry_point,
            )

    def test_case_generator_registration_can_bind_an_existing_component(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            project = Path(directory) / "project"
            with contextlib.redirect_stdout(io.StringIO()):
                self.assertEqual(0, main(["init", str(project)]))
                self.assertEqual(
                    0,
                    main(
                        [
                            "github-configure",
                            "--project",
                            str(project),
                            "--component-id",
                            "refund-tool",
                            "--component",
                            "tool_description",
                            "--path",
                            "agent/tools/**/*.py",
                            "--case",
                            "evidence/refund.case.json",
                        ]
                    ),
                )
            stdout = io.StringIO()

            with contextlib.redirect_stdout(stdout):
                exit_code = main(
                    [
                        "adapter-configure",
                        "--project",
                        str(project),
                        "--adapter-id",
                        "company-case-generator",
                        "--kind",
                        "case_generator",
                        "--entry-point",
                        "company_agent.generator:generate",
                        "--component-id",
                        "refund-tool",
                    ]
                )

            self.assertEqual(0, exit_code)
            self.assertIn("Bound GitHub component: refund-tool", stdout.getvalue())
            configuration = parse_project_configuration(
                json.loads((project / ".causure/config.json").read_text(encoding="utf-8"))
            )
            self.assertEqual(
                "company-case-generator",
                configuration.github.components[0].case_generator_adapter_id,
            )
            doctor = inspect_environment(project)
            github_check = next(
                check for check in doctor.checks if check.code == "CAUSURE-DOCTOR-GITHUB"
            )
            self.assertEqual("warn", github_check.status)
            self.assertIn("runtime case generation", github_check.message)


if __name__ == "__main__":
    unittest.main()
