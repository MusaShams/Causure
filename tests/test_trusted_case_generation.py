"""Separately trusted GitHub case-generator workflow tests."""

from __future__ import annotations

import hashlib
import json
import tempfile
import unittest
from datetime import UTC, datetime
from pathlib import Path

from causure.adapters import CaseGenerationBudget
from causure.constants import Decision
from causure.onboarding import (
    configure_github_component,
    configure_trusted_adapter,
    initialize_project,
)
from causure.runner import AdapterExecutionError, AdapterTimeoutError
from causure.trusted_case_generation import generate_configured_github_case
from tests.helpers import PROJECT_ROOT

BASE_SHA = "1" * 40
HEAD_SHA = "2" * 40


def _adapter_source(*, bind_change_ref: bool = True, sleep: bool = False) -> str:
    assignments = (
        '    document["proposed_change"]["change_ref"] = request.expected_change_ref\n'
        if bind_change_ref
        else ""
    )
    delay = "    time.sleep(2)\n" if sleep else ""
    time_import = "import time\n" if sleep else ""
    return (
        "import hashlib\n"
        "import json\n"
        f"{time_import}"
        "from pathlib import Path\n\n"
        "def generate(request):\n"
        "    component = Path(request.candidate_root).joinpath("
        "*request.component_path.split('/'))\n"
        "    contents = component.read_bytes()\n"
        "    if hashlib.sha256(contents).hexdigest() != request.component_sha256:\n"
        "        raise ValueError('candidate digest mismatch')\n"
        f"{delay}"
        "    document = json.loads(Path(__file__).with_name('template.json').read_text("
        "encoding='utf-8'))\n"
        "    document['case_id'] = f'generated-{request.head_sha[:12]}'\n"
        "    document['created_at'] = '2026-08-10T21:00:00Z'\n"
        f"{assignments}"
        "    return document\n"
    )


class TrustedCaseGenerationTests(unittest.TestCase):
    def _project(
        self,
        root: Path,
        *,
        bind_change_ref: bool = True,
        sleep: bool = False,
        write_adapter: bool = True,
    ) -> tuple[Path, Path]:
        trusted = root / "trusted"
        candidate = root / "candidate"
        initialize_project(trusted, project_id="agent-one")
        configure_github_component(
            trusted,
            component_id="refund-tool",
            component="tool_description",
            paths=("agent/tools/**/*.py",),
            case_file="evidence/generated-refund.case.json",
        )
        configure_trusted_adapter(
            trusted,
            adapter_id="company-case-generator",
            kind="case_generator",
            entry_point="company_generator:generate",
            component_id="refund-tool",
        )
        adapter_directory = trusted / ".causure/adapters"
        if write_adapter:
            (adapter_directory / "company_generator.py").write_text(
                _adapter_source(bind_change_ref=bind_change_ref, sleep=sleep),
                encoding="utf-8",
            )
        (adapter_directory / "template.json").write_bytes(
            (
                PROJECT_ROOT / "examples/change-cases/approve-refund-tool-description.json"
            ).read_bytes()
        )
        component = candidate / "agent/tools/payments/refund.py"
        component.parent.mkdir(parents=True)
        component.write_text(
            "raise SystemExit('candidate code must never execute')\n",
            encoding="utf-8",
        )
        return trusted, candidate

    def _generate(self, trusted: Path, candidate: Path, **values):
        return generate_configured_github_case(
            trusted,
            candidate,
            component_id="refund-tool",
            component_path="agent/tools/payments/refund.py",
            repository="acme/support-agent",
            pull_request_number=42,
            base_sha=BASE_SHA,
            head_sha=HEAD_SHA,
            output_directory=candidate / "causure-generation",
            generated_at=datetime(2026, 8, 10, 22, 0, tzinfo=UTC),
            **values,
        )

    def test_generates_a_bound_case_without_executing_candidate_code(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            trusted, candidate = self._project(root)

            generated = self._generate(trusted, candidate)

            self.assertEqual(Decision.APPROVE, generated.result.decision)
            self.assertEqual(
                candidate.resolve(strict=True) / "evidence/generated-refund.case.json",
                generated.configured_case_path,
            )
            self.assertEqual(
                generated.generated_case_path.read_bytes(),
                generated.configured_case_path.read_bytes(),
            )
            receipt = json.loads(generated.receipt_path.read_text(encoding="utf-8"))
            component_bytes = (candidate / "agent/tools/payments/refund.py").read_bytes()
            self.assertEqual(
                hashlib.sha256(component_bytes).hexdigest(),
                receipt["component"]["sha256"],
            )
            self.assertEqual("company_generator.py", receipt["adapter"]["entry_module_path"])
            self.assertFalse(receipt["execution"]["candidate_code_executed"])
            self.assertFalse(receipt["execution"]["candidate_root_stored"])
            self.assertEqual(
                (
                    "github://acme/support-agent/pull/42/head/"
                    f"{HEAD_SHA}/agent/tools/payments/refund.py"
                ),
                generated.case.proposed_change.change_ref,
            )
            combined = b"".join(
                path.read_bytes() for path in generated.output_directory.iterdir() if path.is_file()
            )
            self.assertNotIn(str(candidate).encode(), combined)

    def test_rejects_a_generator_resolved_only_from_candidate_code(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            trusted, candidate = self._project(root, write_adapter=False)
            (candidate / "company_generator.py").write_text(
                _adapter_source(),
                encoding="utf-8",
            )

            with self.assertRaises(AdapterExecutionError):
                self._generate(trusted, candidate)

            self.assertFalse((candidate / "causure-generation").exists())
            self.assertFalse((candidate / "evidence/generated-refund.case.json").exists())

    def test_rejects_an_unbound_generated_case_without_partial_output(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            trusted, candidate = self._project(root, bind_change_ref=False)

            with self.assertRaisesRegex(ValueError, "change_ref"):
                self._generate(trusted, candidate)

            self.assertFalse((candidate / "causure-generation").exists())
            self.assertFalse((candidate / "evidence/generated-refund.case.json").exists())

    def test_terminates_a_slow_case_generator_without_writing(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            trusted, candidate = self._project(root, sleep=True)

            with self.assertRaises(AdapterTimeoutError):
                self._generate(
                    trusted,
                    candidate,
                    budget=CaseGenerationBudget(timeout_seconds=0.05),
                )

            self.assertFalse((candidate / "causure-generation").exists())
            self.assertFalse((candidate / "evidence/generated-refund.case.json").exists())


if __name__ == "__main__":
    unittest.main()
