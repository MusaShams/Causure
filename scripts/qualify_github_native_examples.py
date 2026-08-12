"""Qualify the three credential-free GitHub-native synthetic stories locally."""

from __future__ import annotations

import argparse
import json
import shutil
import tempfile
from datetime import UTC, datetime, timedelta
from pathlib import Path

from causure.constants import Decision
from causure.io import atomic_write_text
from causure.trusted_case_generation import generate_configured_github_case

PROJECT_ROOT = Path(__file__).resolve().parents[1]
EXAMPLE_ROOT = PROJECT_ROOT / "examples" / "github-native"
BASE_SHA = "b" * 40

SCENARIOS = (
    (
        "approve",
        "agent/tools/refund-policy.txt",
        Decision.APPROVE,
        "a" * 40,
    ),
    (
        "abstain",
        "agent/prompts/refund-policy.md",
        Decision.REJECT,
        "c" * 40,
    ),
    (
        "needs-evidence",
        "agent/tools/refund-policy.txt",
        Decision.NEEDS_EVIDENCE,
        "d" * 40,
    ),
)


def qualify() -> dict[str, object]:
    results: list[dict[str, object]] = []
    with tempfile.TemporaryDirectory(prefix="causure-github-example-") as directory:
        root = Path(directory)
        for index, (scenario, component_path, expected, head_sha) in enumerate(SCENARIOS):
            scenario_root = root / scenario
            trusted = scenario_root / "trusted-control"
            candidate = scenario_root / "candidate"
            shutil.copytree(EXAMPLE_ROOT / "template", trusted)
            shutil.copytree(EXAMPLE_ROOT / "template", candidate)
            source = EXAMPLE_ROOT / "scenarios" / scenario / component_path
            destination = candidate.joinpath(*component_path.split("/"))
            destination.parent.mkdir(parents=True, exist_ok=True)
            shutil.copy2(source, destination)
            generated = generate_configured_github_case(
                trusted,
                candidate,
                component_id=("refund-prompt" if scenario == "abstain" else "refund-tool"),
                component_path=component_path,
                repository="causure/example-agent",
                pull_request_number=100 + index,
                base_sha=BASE_SHA,
                head_sha=head_sha,
                output_directory=candidate / ".causure/trusted-generation",
                generated_at=datetime(2026, 8, 10, 22, 0, tzinfo=UTC) + timedelta(minutes=index),
            )
            if generated.result.decision is not expected:
                raise RuntimeError(
                    f"{scenario} produced {generated.result.decision.value}, "
                    f"expected {expected.value}"
                )
            results.append(
                {
                    "case_id": generated.case.case_id,
                    "component_path": component_path,
                    "decision": generated.result.decision.value,
                    "expected_decision": expected.value,
                    "receipt_sha256": generated.receipt["change_case"]["sha256"],
                    "scenario": scenario,
                    "status": "passed",
                }
            )
    return {
        "credentialed_services_used": False,
        "candidate_code_executed": False,
        "result": "passed",
        "scenarios": results,
        "schema_version": "1.0",
        "scope": "local engineering qualification; not remote GitHub evidence",
    }


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--output", help="optional new or replaceable JSON receipt path")
    args = parser.parse_args()
    document = qualify()
    content = json.dumps(document, indent=2, sort_keys=True) + "\n"
    if args.output:
        atomic_write_text(args.output, content)
    else:
        print(content, end="")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
