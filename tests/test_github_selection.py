"""Configured GitHub pull-request file discovery and selection tests."""

from __future__ import annotations

import json
import tempfile
import unittest
from pathlib import Path

from causure.constants import Component
from causure.github_checks import GitHubHTTPResponse
from causure.github_review import github_context_from_environment
from causure.github_selection import (
    GitHubChangedFile,
    GitHubSelectionError,
    discover_github_pull_request_files,
    select_configured_github_change,
)
from causure.onboarding import (
    GitHubComponentConfiguration,
    GitHubProjectConfiguration,
    ProjectConfiguration,
)
from tests.test_github_checks import _environment, _event


class RecordingPullFilesTransport:
    def __init__(
        self,
        pull_request: dict[str, object],
        files: list[dict[str, object]],
        *,
        mutate_after_files: bool = False,
    ) -> None:
        self.pull_request = pull_request
        self.files = files
        self.mutate_after_files = mutate_after_files
        self.calls: list[str] = []
        self.headers: dict[str, str] = {}

    def get(self, url, *, headers, timeout_seconds):
        self.calls.append(url)
        self.headers = dict(headers)
        if "/files?" in url:
            page = int(url.rsplit("page=", 1)[1])
            start = (page - 1) * 100
            document: object = self.files[start : start + 100]
        else:
            document = json.loads(json.dumps(self.pull_request))
            if self.mutate_after_files and any("/files?" in call for call in self.calls):
                document["head"]["sha"] = "f" * 40
        return GitHubHTTPResponse(
            status_code=200,
            headers={"content-type": "application/json; charset=utf-8"},
            body=json.dumps(document).encode("utf-8"),
        )


def _configuration(
    *components: GitHubComponentConfiguration,
) -> ProjectConfiguration:
    return ProjectConfiguration(
        project_id="agent-one",
        policy_file="policy.json",
        adapter_directory="adapters",
        artifact_directory="artifacts",
        raw_trace_storage="disabled",
        trusted_adapter_entry_points=(),
        github=GitHubProjectConfiguration(
            artifact_retention_days=30,
            components=tuple(components),
        ),
    )


class GitHubSelectionTests(unittest.TestCase):
    def _context(self, root: Path):
        event_path = root / "event.json"
        event_document = json.loads(_event())
        event_path.write_text(json.dumps(event_document), encoding="utf-8")
        environment = _environment()
        environment["GITHUB_EVENT_PATH"] = str(event_path)
        return github_context_from_environment(environment)[0], event_document

    def test_discovery_is_bounded_read_only_and_rechecks_the_event_head(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            pull_request, event = self._context(Path(directory))
            api_pull_request = event["pull_request"]
            api_pull_request["changed_files"] = 2
            transport = RecordingPullFilesTransport(
                api_pull_request,
                [
                    {"filename": "agent/tools/refund.py", "status": "modified"},
                    {
                        "filename": "agent/prompts/refund.md",
                        "previous_filename": "agent/prompts/old-refund.md",
                        "status": "renamed",
                    },
                ],
            )

            files = discover_github_pull_request_files(
                pull_request,
                token="short-lived-token",
                transport=transport,
            )

        self.assertEqual(
            ("agent/prompts/refund.md", "agent/tools/refund.py"),
            tuple(item.path for item in files),
        )
        self.assertEqual("agent/prompts/old-refund.md", files[0].previous_path)
        self.assertEqual(3, len(transport.calls))
        self.assertEqual("Bearer short-lived-token", transport.headers["Authorization"])
        self.assertTrue(
            all(url.startswith("https://api.github.com/repos/") for url in transport.calls)
        )

    def test_discovery_fails_when_the_pull_request_moves_during_pagination(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            pull_request, event = self._context(Path(directory))
            api_pull_request = event["pull_request"]
            api_pull_request["changed_files"] = 1
            transport = RecordingPullFilesTransport(
                api_pull_request,
                [{"filename": "agent/tools/refund.py"}],
                mutate_after_files=True,
            )

            with self.assertRaisesRegex(GitHubSelectionError, "pull_request_changed"):
                discover_github_pull_request_files(
                    pull_request,
                    token="short-lived-token",
                    transport=transport,
                )

    def test_selection_supports_recursive_patterns_and_renames(self) -> None:
        configuration = _configuration(
            GitHubComponentConfiguration(
                component_id="refund-tools",
                component=Component.TOOL_DESCRIPTION,
                paths=("agent/tools/**/*.py",),
                case_file="evidence/refund.case.json",
            )
        )
        selection = select_configured_github_change(
            configuration,
            (
                GitHubChangedFile(
                    path="agent/new/refund.py",
                    previous_path="agent/tools/payments/refund.py",
                ),
            ),
            config_repository_path=".causure/config.json",
        )

        self.assertIsNotNone(selection)
        self.assertEqual("refund-tools", selection.component_id)
        self.assertEqual("agent/new/refund.py", selection.component_path)
        self.assertEqual(".causure/policy.json", selection.policy_file)

    def test_selection_rejects_changed_governance_and_ambiguous_components(self) -> None:
        first = GitHubComponentConfiguration(
            component_id="refund-tools",
            component=Component.TOOL_DESCRIPTION,
            paths=("agent/**",),
            case_file="evidence/refund.case.json",
        )
        second = GitHubComponentConfiguration(
            component_id="refund-policy",
            component=Component.RETRY_POLICY,
            paths=("agent/tools/**",),
            case_file="evidence/retry.case.json",
        )
        with self.assertRaisesRegex(GitHubSelectionError, "governance_changed"):
            select_configured_github_change(
                _configuration(first),
                (GitHubChangedFile(".Causure/Config.json", None),),
                config_repository_path=".causure/config.json",
            )
        with self.assertRaisesRegex(GitHubSelectionError, "ambiguous_components"):
            select_configured_github_change(
                _configuration(first, second),
                (GitHubChangedFile("agent/tools/refund.py", None),),
                config_repository_path=".causure/config.json",
            )


if __name__ == "__main__":
    unittest.main()
