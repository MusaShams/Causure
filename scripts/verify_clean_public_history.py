"""Verify that a candidate public Git repository exposes one clean root commit."""

from __future__ import annotations

import argparse
import json
import subprocess
from collections.abc import Sequence
from pathlib import Path
from typing import Any

DEFAULT_COMMIT_MESSAGE = "Creation of Causure"
DEFAULT_BRANCH = "main"


def _git(root: Path, *arguments: str) -> str:
    completed = subprocess.run(
        ["git", *arguments],
        cwd=root,
        check=False,
        capture_output=True,
        text=True,
        encoding="utf-8",
        errors="replace",
    )
    if completed.returncode != 0:
        detail = completed.stderr.strip() or completed.stdout.strip() or "unknown Git failure"
        raise RuntimeError(f"git {' '.join(arguments)} failed: {detail}")
    return completed.stdout.strip()


def inspect_history(
    root: Path,
    *,
    expected_branch: str = DEFAULT_BRANCH,
    expected_message: str = DEFAULT_COMMIT_MESSAGE,
) -> dict[str, Any]:
    """Return a minimized pass/fail report for the clean public-history boundary."""

    resolved_root = root.resolve()
    errors: list[dict[str, str]] = []
    observations: dict[str, Any] = {}

    try:
        branch = _git(resolved_root, "symbolic-ref", "--quiet", "--short", "HEAD")
        head = _git(resolved_root, "rev-parse", "HEAD^{commit}")
        commit_count = int(_git(resolved_root, "rev-list", "--all", "--count"))
        roots = tuple(
            line
            for line in _git(resolved_root, "rev-list", "--all", "--max-parents=0").splitlines()
            if line
        )
        subject = _git(resolved_root, "log", "-1", "--format=%s", "HEAD")
        head_with_parents = _git(resolved_root, "rev-list", "--parents", "-n", "1", "HEAD").split()
        status = _git(resolved_root, "status", "--porcelain=v1", "--untracked-files=all")
    except (OSError, RuntimeError, ValueError) as exc:
        errors.append({"code": "git_inspection_failed", "message": str(exc)})
    else:
        observations = {
            "branch": branch,
            "commit_count_all_refs": commit_count,
            "commit_message": subject,
            "head": head,
            "root_commits": list(roots),
            "working_tree_clean": not status,
        }
        if branch != expected_branch:
            errors.append(
                {
                    "code": "unexpected_branch",
                    "message": f"expected {expected_branch!r}, observed {branch!r}",
                }
            )
        if commit_count != 1:
            errors.append(
                {
                    "code": "unexpected_commit_count",
                    "message": f"expected one commit across all refs, observed {commit_count}",
                }
            )
        if roots != (head,):
            errors.append(
                {
                    "code": "unexpected_root_set",
                    "message": "the only root commit must be the checked-out HEAD",
                }
            )
        if len(head_with_parents) != 1:
            errors.append(
                {
                    "code": "head_has_parent",
                    "message": "the public HEAD must be a parentless root commit",
                }
            )
        if subject != expected_message:
            errors.append(
                {
                    "code": "unexpected_commit_message",
                    "message": f"expected {expected_message!r}, observed {subject!r}",
                }
            )
        if status:
            errors.append(
                {
                    "code": "dirty_working_tree",
                    "message": "tracked or untracked candidate files remain outside the commit",
                }
            )

    return {
        "schema_version": 1,
        "status": "ready" if not errors else "failed",
        "ready": not errors,
        "expected_branch": expected_branch,
        "expected_commit_message": expected_message,
        "observations": observations,
        "errors": errors,
    }


def _build_argument_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--root", type=Path, default=Path.cwd(), help="Git repository to inspect")
    parser.add_argument("--branch", default=DEFAULT_BRANCH, help="required checked-out branch")
    parser.add_argument(
        "--commit-message",
        default=DEFAULT_COMMIT_MESSAGE,
        help="required root-commit subject",
    )
    return parser


def main(argv: Sequence[str] | None = None) -> int:
    args = _build_argument_parser().parse_args(argv)
    result = inspect_history(
        args.root,
        expected_branch=args.branch,
        expected_message=args.commit_message,
    )
    print(json.dumps(result, indent=2, sort_keys=True))
    return 0 if result["ready"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
