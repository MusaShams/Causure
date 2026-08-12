"""Deterministic synthetic generator for the public GitHub-native example."""

from __future__ import annotations

import hashlib
import json
from importlib import resources
from pathlib import Path

_SCENARIOS = frozenset({"approve", "abstain", "needs_evidence"})


def _demo_case(name: str) -> dict[str, object]:
    resource = resources.files("causure").joinpath("demo", name)
    return json.loads(resource.read_text(encoding="utf-8"))


def generate(request):
    """Return one fixed synthetic story bound to the exact candidate identity."""

    component_path = Path(request.candidate_root).joinpath(*request.component_path.split("/"))
    component_bytes = component_path.read_bytes()
    if len(component_bytes) != request.component_byte_count:
        raise ValueError("candidate component byte count changed")
    if hashlib.sha256(component_bytes).hexdigest() != request.component_sha256:
        raise ValueError("candidate component digest changed")
    try:
        marker = component_bytes.decode("utf-8").strip()
    except UnicodeDecodeError as exc:
        raise ValueError("synthetic component must be UTF-8") from exc
    prefix = "synthetic_scenario="
    if not marker.startswith(prefix) or marker[len(prefix) :] not in _SCENARIOS:
        raise ValueError("synthetic component must select a documented scenario")
    scenario = marker[len(prefix) :]

    if scenario == "abstain":
        document = _demo_case("reject-overbroad-prompt.json")
    else:
        document = _demo_case("approve-refund-tool-description.json")
    if scenario == "needs_evidence":
        document["verification"]["reproduction_trials"] = []
        document["attribution"]["hypotheses"] = []
        document["null_hypothesis"]["evidence_against"] = []
        document["validation"] = {"cases": []}

    document["case_id"] = f"synthetic-{scenario}-{request.head_sha[:12]}"
    document["created_at"] = "2026-08-10T22:00:00Z"
    document["proposed_change"]["change_ref"] = request.expected_change_ref
    return document
