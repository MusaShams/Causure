"""Isolated bootstrap for the repository-pinned trusted generator Action."""

from __future__ import annotations

import sys
from pathlib import Path

ACTION_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ACTION_ROOT / "src"))

from causure.trusted_case_action_runner import main  # noqa: E402

if __name__ == "__main__":
    raise SystemExit(main())
