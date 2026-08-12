"""Tests for the clean public Git-history boundary."""

from __future__ import annotations

import subprocess
import tempfile
import unittest
from pathlib import Path

from scripts.verify_clean_public_history import DEFAULT_COMMIT_MESSAGE, inspect_history


def _git(root: Path, *arguments: str) -> None:
    subprocess.run(
        ["git", *arguments],
        cwd=root,
        check=True,
        capture_output=True,
        text=True,
        encoding="utf-8",
    )


def _commit(root: Path, message: str, contents: str) -> None:
    (root / "README.md").write_text(contents, encoding="utf-8")
    _git(root, "add", "README.md")
    _git(root, "commit", "-m", message)


class CleanPublicHistoryTests(unittest.TestCase):
    def _repository(self, *, branch: str = "main") -> tuple[tempfile.TemporaryDirectory[str], Path]:
        temporary = tempfile.TemporaryDirectory()
        root = Path(temporary.name)
        _git(root, "init", "-b", branch)
        _git(root, "config", "user.name", "Causure Test")
        _git(root, "config", "user.email", "causure-test@example.invalid")
        return temporary, root

    def test_one_clean_root_commit_is_ready(self) -> None:
        temporary, root = self._repository()
        self.addCleanup(temporary.cleanup)
        _commit(root, DEFAULT_COMMIT_MESSAGE, "# Causure\n")

        result = inspect_history(root)

        self.assertTrue(result["ready"])
        self.assertEqual("ready", result["status"])
        self.assertEqual(1, result["observations"]["commit_count_all_refs"])

    def test_second_commit_is_rejected(self) -> None:
        temporary, root = self._repository()
        self.addCleanup(temporary.cleanup)
        _commit(root, DEFAULT_COMMIT_MESSAGE, "# Causure\n")
        _commit(root, "Another public commit", "# Causure\n\nSecond revision.\n")

        result = inspect_history(root)

        self.assertFalse(result["ready"])
        self.assertIn("unexpected_commit_count", {error["code"] for error in result["errors"]})
        self.assertIn("head_has_parent", {error["code"] for error in result["errors"]})

    def test_wrong_branch_message_and_dirty_tree_are_rejected(self) -> None:
        temporary, root = self._repository(branch="release")
        self.addCleanup(temporary.cleanup)
        _commit(root, "Initial commit", "# Causure\n")
        (root / "untracked.txt").write_text("not committed\n", encoding="utf-8")

        result = inspect_history(root)
        codes = {error["code"] for error in result["errors"]}

        self.assertFalse(result["ready"])
        self.assertTrue(
            {"unexpected_branch", "unexpected_commit_message", "dirty_working_tree"}.issubset(codes)
        )


if __name__ == "__main__":
    unittest.main()
