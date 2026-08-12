"""Shared test fixtures."""

from __future__ import annotations

import copy
import json
from pathlib import Path
from typing import Any

PROJECT_ROOT = Path(__file__).resolve().parents[1]


def load_example(name: str = "approve-refund-tool-description.json") -> dict[str, Any]:
    path = PROJECT_ROOT / "examples" / "change-cases" / name
    return copy.deepcopy(json.loads(path.read_text(encoding="utf-8")))


def load_needs_evidence_example() -> dict[str, Any]:
    document = load_example()
    document["verification"]["reproduction_trials"] = []
    document["attribution"]["hypotheses"] = []
    document["null_hypothesis"]["evidence_against"] = []
    document["validation"] = {"cases": []}
    return document
