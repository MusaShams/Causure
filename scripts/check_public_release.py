"""Fail closed when a candidate public snapshot contains unsafe or incomplete files."""

from __future__ import annotations

import argparse
import json
import re
import subprocess
from collections.abc import Iterable, Sequence
from pathlib import Path, PurePosixPath
from typing import Any

PROJECT_ROOT = Path(__file__).resolve().parents[1]

REQUIRED_FILES = frozenset(
    {
        ".gitattributes",
        ".github/CODEOWNERS",
        ".github/ISSUE_TEMPLATE/bug_report.yml",
        ".github/ISSUE_TEMPLATE/config.yml",
        ".github/ISSUE_TEMPLATE/research_or_feature.yml",
        ".github/dependabot.yml",
        ".github/pull_request_template.md",
        ".github/workflows/ci.yml",
        ".github/workflows/codeql.yml",
        ".github/workflows/dependency-review.yml",
        ".gitignore",
        "action.yml",
        "CHANGELOG.md",
        "CONTRIBUTING.md",
        "README.md",
        "SECURITY.md",
        "SUPPORT.md",
        "docs/decisions/0026-publish-a-reviewed-github-mirror.md",
        "docs/decisions/0027-license-public-distribution-under-apache-2.0.md",
        "docs/decisions/0028-reuse-the-canonical-project-config-for-github-selection.md",
        "docs/decisions/0029-run-case-generators-only-from-a-protected-base.md",
        "docs/decisions/0030-rebrand-as-causure.md",
        "docs/decisions/0031-publish-a-clean-public-history.md",
        "docs/clean-history-publication.md",
        "docs/github-action.md",
        "docs/github-public-release.md",
        "docs/portfolio-case-study.md",
        "docs/portfolio-demo-script.md",
        "docs/qualifications/causure-installed-wheel-2026-08-11.json",
        "docs/qualifications/p0a-unfamiliar-user-2026-08-11.json",
        "docs/tfvc-and-classic-pipeline.md",
        "docs/trusted-case-generation.md",
        "examples/github-native/README.md",
        "examples/github-native/causure.template.yml",
        "examples/github-native/scenarios/abstain/agent/prompts/refund-policy.md",
        "examples/github-native/scenarios/approve/agent/tools/refund-policy.txt",
        "examples/github-native/scenarios/needs-evidence/agent/tools/refund-policy.txt",
        "examples/github-native/template/.causure/.gitignore",
        "examples/github-native/template/.causure/adapters/README.md",
        "examples/github-native/template/.causure/adapters/synthetic_case_generator.py",
        "examples/github-native/template/.causure/config.json",
        "examples/github-native/template/.causure/policy.json",
        "examples/github-native/template/README.md",
        "examples/github-native/template/agent/prompts/refund-policy.md",
        "examples/github-native/template/agent/tools/refund-policy.txt",
        "pyproject.toml",
        "schemas/trusted-case-generation.schema.json",
        "scripts/qualify_github_native_examples.py",
        "scripts/run_trusted_case_generator_action.py",
        "scripts/verify_clean_public_history.py",
        "trusted-case-generator/action.yml",
    }
)
LICENSE_FILES = frozenset({"LICENSE", "LICENSE.md", "LICENSE.txt"})

FORBIDDEN_PREFIXES = (
    ".git/",
    "$tf/",
    "build/",
    "dist/",
    "htmlcov/",
    "pilot-state/",
    "deploy/openai-quota-pilot/state/",
)
FORBIDDEN_DIRECTORY_NAMES = frozenset(
    {
        ".git",
        ".mypy_cache",
        ".pytest_cache",
        ".ruff_cache",
        ".venv",
        "$tf",
        "__pycache__",
        "build",
        "dist",
        "htmlcov",
        "pilot-state",
    }
)
SENSITIVE_SUFFIXES = frozenset({".clixml", ".key", ".p12", ".pem", ".pfx"})
SENSITIVE_NAMES = frozenset({".env", "credentials.json", "secrets.json"})
MAX_SCANNED_BYTES = 2_000_000

REQUIRED_GITIGNORE_PATTERNS = (
    "$tf/",
    ".env",
    ".env.*",
    "*.clixml",
    "*.key",
    "*.pem",
    "build/",
    "dist/",
    "pilot-state/",
    "deploy/openai-quota-pilot/state/",
)
GITIGNORE_PROBES = (
    "$tf/workspace.db",
    ".env",
    ".env.local",
    "operator.clixml",
    "signing.pem",
    "build/candidate.whl",
    "dist/candidate.whl",
    "pilot-state/manifest.json",
    "deploy/openai-quota-pilot/state/provider-key",
)

SECRET_PATTERNS = (
    (
        "private_key",
        re.compile(rb"-----BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY-----"),
    ),
    ("github_token", re.compile(rb"\bgh[pousr]_[A-Za-z0-9]{36,}\b")),
    ("github_fine_grained_token", re.compile(rb"\bgithub_pat_[A-Za-z0-9_]{40,}\b")),
    ("aws_access_key", re.compile(rb"\bAKIA[0-9A-Z]{16}\b")),
    ("openai_api_key", re.compile(rb"\bsk-[A-Za-z0-9_-]{20,}\b")),
    (
        "basic_auth_url",
        re.compile(rb"https?://[^/\s:@]+:[^/\s@]+@[^/\s]+"),
    ),
)

LOCAL_USER_PATH_PATTERNS = (
    (
        "windows_user_home",
        re.compile(rb"(?i)\b[A-Z]:\\Users\\[^\\\r\n\"']+\\"),
    ),
    (
        "unix_user_home",
        re.compile(rb"(?<![A-Za-z0-9])/(?:home|Users)/[^/\s\"']+/"),
    ),
)

_SYNTHETIC_OPENAI_TOKEN = b"sk-test-" + b"not-a-real-secret"
_SYNTHETIC_BASIC_AUTH_PREFIX = b"https://" + b"user:password@"
SECRET_ALLOWLIST = frozenset(
    {
        ("examples/traces/refund-openinference-otlp.json", _SYNTHETIC_OPENAI_TOKEN),
        ("tests/test_collector.py", _SYNTHETIC_OPENAI_TOKEN),
        (
            "tests/test_azure_devops.py",
            _SYNTHETIC_BASIC_AUTH_PREFIX + b"dev.azure.com",
        ),
        (
            "tests/test_sandbox_protocol.py",
            _SYNTHETIC_BASIC_AUTH_PREFIX + b"quota-proxy",
        ),
    }
)


def _finding(code: str, message: str, path: str | None = None) -> dict[str, str]:
    result = {"code": code, "message": message}
    if path is not None:
        result["path"] = path
    return result


def _normalize_candidate_path(raw_path: str) -> str:
    normalized = raw_path.replace("\\", "/")
    while normalized.startswith("./"):
        normalized = normalized[2:]
    path = PurePosixPath(normalized)
    if not normalized or path.is_absolute() or ".." in path.parts:
        raise ValueError(f"candidate path is not a safe project-relative path: {raw_path!r}")
    return path.as_posix()


def _collect_git_candidate_paths(root: Path) -> list[str]:
    process = subprocess.run(
        [
            "git",
            "-C",
            str(root),
            "ls-files",
            "--cached",
            "--others",
            "--exclude-standard",
            "-z",
        ],
        check=False,
        capture_output=True,
    )
    if process.returncode != 0:
        detail = process.stderr.decode("utf-8", errors="replace").strip()
        raise RuntimeError(f"git candidate enumeration failed: {detail or process.returncode}")
    return [item.decode("utf-8") for item in process.stdout.split(b"\0") if item]


def _collect_filesystem_candidate_paths(root: Path) -> list[str]:
    candidates: list[str] = []
    for path in root.rglob("*"):
        if not path.is_file():
            continue
        relative = path.relative_to(root)
        if any(part in FORBIDDEN_DIRECTORY_NAMES for part in relative.parts[:-1]):
            continue
        candidates.append(relative.as_posix())
    return candidates


def collect_candidate_paths(root: Path, source: str = "auto") -> tuple[list[str], str]:
    """Return the files that would form the reviewed public snapshot."""

    if source not in {"auto", "filesystem", "git"}:
        raise ValueError(f"unsupported candidate source: {source}")
    if source == "git" or (source == "auto" and (root / ".git").exists()):
        return _collect_git_candidate_paths(root), "git"
    return _collect_filesystem_candidate_paths(root), "filesystem"


def _scan_workflow(path: str, contents: str) -> list[dict[str, str]]:
    findings: list[dict[str, str]] = []
    if re.search(r"(?m)^\s*pull_request_target\s*:", contents):
        findings.append(
            _finding(
                "workflow_unsafe_trigger",
                "pull_request_target is forbidden for the public candidate",
                path,
            )
        )
    if "${{ secrets." in contents:
        findings.append(
            _finding(
                "workflow_secret_context",
                "candidate workflows must not consume repository secrets",
                path,
            )
        )
    if re.search(r"(?m)^\s*permissions\s*:\s*write-all\s*(?:#.*)?$", contents):
        findings.append(
            _finding(
                "workflow_write_all",
                "workflow permissions must be explicitly least-privileged",
                path,
            )
        )
    if not re.search(r"(?m)^permissions\s*:", contents):
        findings.append(
            _finding(
                "workflow_permissions_missing",
                "workflow must declare top-level permissions",
                path,
            )
        )

    for match in re.finditer(r"(?m)^\s*(?:-\s*)?uses\s*:\s*([^\s#]+)", contents):
        action = match.group(1)
        if action.startswith(("./", "docker://")):
            continue
        if "@" not in action:
            findings.append(
                _finding("workflow_action_unpinned", f"action has no ref: {action}", path)
            )
            continue
        ref = action.rsplit("@", maxsplit=1)[1]
        if re.fullmatch(r"[0-9a-fA-F]{40}", ref) is None:
            findings.append(
                _finding(
                    "workflow_action_unpinned",
                    f"action is not pinned to a full commit SHA: {action}",
                    path,
                )
            )
    return findings


def _scan_action_metadata(path: str, contents: str) -> list[dict[str, str]]:
    findings: list[dict[str, str]] = []
    if not re.search(r"(?m)^\s*using\s*:\s*composite\s*(?:#.*)?$", contents):
        findings.append(
            _finding(
                "action_not_composite",
                "the public Action must use the reviewed composite boundary",
                path,
            )
        )
    if "${{ secrets." in contents:
        findings.append(
            _finding(
                "action_secret_context",
                "the composite Action must not consume repository secrets implicitly",
                path,
            )
        )
    if "CAUSURE_GITHUB_TOKEN: ${{ inputs.github-token }}" not in contents:
        findings.append(
            _finding(
                "action_token_boundary",
                (
                    "the short-lived GitHub token must cross only the explicit "
                    "input/environment boundary"
                ),
                path,
            )
        )
    if path in {"action.yml", "action.yaml"}:
        if "CAUSURE_CONFIG: ${{ inputs.config }}" not in contents:
            findings.append(
                _finding(
                    "action_config_boundary",
                    "automatic selection must receive only the explicit project-config input",
                    path,
                )
            )
        if "CAUSURE_REPOSITORY_ROOT: ${{ inputs.repository-root }}" not in contents:
            findings.append(
                _finding(
                    "action_repository_boundary",
                    "the reviewed repository root must cross only the explicit input boundary",
                    path,
                )
            )
    elif path in {
        "trusted-case-generator/action.yml",
        "trusted-case-generator/action.yaml",
    }:
        required_boundaries = (
            "CAUSURE_TRUSTED_PROJECT: ${{ inputs.trusted-project }}",
            "CAUSURE_CANDIDATE_ROOT: ${{ inputs.candidate-root }}",
            "CAUSURE_TRUSTED_OUTPUT_DIRECTORY: ${{ inputs.output-directory }}",
        )
        if any(boundary not in contents for boundary in required_boundaries):
            findings.append(
                _finding(
                    "action_trusted_generation_boundary",
                    "trusted and candidate roots must cross only explicit Action inputs",
                    path,
                )
            )
    if "python -I $runner" not in contents:
        findings.append(
            _finding(
                "action_python_not_isolated",
                "the Action runner must use Python isolated mode",
                path,
            )
        )
    for match in re.finditer(r"(?m)^\s*(?:-\s*)?uses\s*:\s*([^\s#]+)", contents):
        action = match.group(1)
        if action.startswith(("./", "docker://")):
            findings.append(
                _finding(
                    "action_local_dependency",
                    "the composite Action must not execute caller-workspace action code",
                    path,
                )
            )
            continue
        if (
            "@" not in action
            or re.fullmatch(r"[0-9a-fA-F]{40}", action.rsplit("@", maxsplit=1)[1]) is None
        ):
            findings.append(
                _finding(
                    "action_dependency_unpinned",
                    f"Action dependency is not pinned to a full commit SHA: {action}",
                    path,
                )
            )
    return findings


def _scan_file_for_secrets(path: str, contents: bytes) -> list[dict[str, str]]:
    findings: list[dict[str, str]] = []
    seen_codes: set[str] = set()
    for code, pattern in SECRET_PATTERNS:
        for match in pattern.finditer(contents):
            if (path, match.group(0)) in SECRET_ALLOWLIST:
                continue
            if code not in seen_codes:
                findings.append(
                    _finding(
                        "secret_pattern",
                        f"candidate contains a possible {code.replace('_', ' ')}",
                        path,
                    )
                )
                seen_codes.add(code)
    return findings


def _scan_file_for_local_user_paths(path: str, contents: bytes) -> list[dict[str, str]]:
    findings: list[dict[str, str]] = []
    for path_kind, pattern in LOCAL_USER_PATH_PATTERNS:
        if pattern.search(contents) is not None:
            findings.append(
                _finding(
                    "local_user_path",
                    f"candidate contains a machine-specific {path_kind.replace('_', ' ')}",
                    path,
                )
            )
    return findings


def _finalize_result(result: dict[str, Any]) -> dict[str, Any]:
    result["errors"] = sorted(
        result["errors"], key=lambda item: (item.get("path", ""), item["code"])
    )
    result["blockers"] = sorted(
        result["blockers"], key=lambda item: (item.get("path", ""), item["code"])
    )
    result["warnings"] = sorted(
        result["warnings"], key=lambda item: (item.get("path", ""), item["code"])
    )
    if result["errors"]:
        result["status"] = "failed"
    elif result["blockers"]:
        result["status"] = "blocked_license"
    else:
        result["status"] = "ready"
    result["ready"] = result["status"] == "ready"
    return result


def evaluate_candidate(
    root: Path,
    candidate_paths: Iterable[str],
    *,
    candidate_source: str = "provided",
) -> dict[str, Any]:
    """Evaluate an explicit candidate list without requiring Git or TFVC."""

    errors: list[dict[str, str]] = []
    blockers: list[dict[str, str]] = []
    warnings: list[dict[str, str]] = []
    normalized_paths: set[str] = set()

    for raw_path in candidate_paths:
        try:
            normalized_paths.add(_normalize_candidate_path(raw_path))
        except ValueError as exc:
            errors.append(_finding("invalid_candidate_path", str(exc)))

    for required_path in sorted(REQUIRED_FILES - normalized_paths):
        errors.append(
            _finding(
                "required_file_missing",
                "required public-release file is absent from the candidate",
                required_path,
            )
        )

    if not (LICENSE_FILES & normalized_paths):
        blockers.append(
            _finding(
                "license_missing",
                "select an owner-approved license before making the repository public",
                "LICENSE",
            )
        )

    for path in sorted(normalized_paths):
        lower_path = path.lower()
        if any(path == prefix[:-1] or path.startswith(prefix) for prefix in FORBIDDEN_PREFIXES):
            errors.append(
                _finding(
                    "forbidden_path",
                    "local metadata, generated output, or pilot state is in the candidate",
                    path,
                )
            )

        filename = PurePosixPath(path).name
        lower_filename = filename.lower()
        if (
            lower_filename in SENSITIVE_NAMES
            or lower_filename.startswith(".env.")
            or PurePosixPath(lower_path).suffix in SENSITIVE_SUFFIXES
        ):
            errors.append(
                _finding(
                    "sensitive_file",
                    "credential or private-key file type is in the candidate",
                    path,
                )
            )

        disk_path = root.joinpath(*PurePosixPath(path).parts)
        if not disk_path.exists():
            errors.append(
                _finding("candidate_file_missing", "candidate file is absent on disk", path)
            )
            continue
        if disk_path.is_symlink():
            errors.append(
                _finding(
                    "candidate_symlink",
                    "public snapshot symlinks require separate review and are not accepted",
                    path,
                )
            )
            continue
        if not disk_path.is_file():
            continue

        size = disk_path.stat().st_size
        if size > MAX_SCANNED_BYTES:
            warnings.append(
                _finding(
                    "content_scan_skipped",
                    f"file exceeds the {MAX_SCANNED_BYTES}-byte content-scan limit",
                    path,
                )
            )
            continue
        contents = disk_path.read_bytes()
        errors.extend(_scan_file_for_secrets(path, contents))
        errors.extend(_scan_file_for_local_user_paths(path, contents))

        if path.startswith(".github/workflows/") and path.endswith((".yml", ".yaml")):
            try:
                workflow_contents = contents.decode("utf-8")
            except UnicodeDecodeError:
                errors.append(_finding("workflow_not_utf8", "workflow is not valid UTF-8", path))
            else:
                errors.extend(_scan_workflow(path, workflow_contents))
        if path in {
            "action.yml",
            "action.yaml",
            "trusted-case-generator/action.yml",
            "trusted-case-generator/action.yaml",
        }:
            try:
                action_contents = contents.decode("utf-8")
            except UnicodeDecodeError:
                errors.append(_finding("action_not_utf8", "action metadata is not UTF-8", path))
            else:
                errors.extend(_scan_action_metadata(path, action_contents))

    gitignore_path = root / ".gitignore"
    if ".gitignore" in normalized_paths and gitignore_path.is_file():
        gitignore_contents = gitignore_path.read_text(encoding="utf-8")
        for pattern in REQUIRED_GITIGNORE_PATTERNS:
            if pattern not in gitignore_contents:
                errors.append(
                    _finding(
                        "gitignore_pattern_missing",
                        f"required public-boundary ignore pattern is missing: {pattern}",
                        ".gitignore",
                    )
                )

    result: dict[str, Any] = {
        "schema_version": 1,
        "candidate_source": candidate_source,
        "candidate_file_count": len(normalized_paths),
        "status": "failed",
        "ready": False,
        "errors": errors,
        "blockers": blockers,
        "warnings": warnings,
    }
    return _finalize_result(result)


def _check_git_ignore_behavior(root: Path) -> list[dict[str, str]]:
    payload = b"\0".join(probe.encode("utf-8") for probe in GITIGNORE_PROBES) + b"\0"
    process = subprocess.run(
        ["git", "-C", str(root), "check-ignore", "--no-index", "-z", "--stdin"],
        input=payload,
        check=False,
        capture_output=True,
    )
    if process.returncode not in {0, 1}:
        detail = process.stderr.decode("utf-8", errors="replace").strip()
        return [
            _finding(
                "gitignore_check_failed",
                f"git check-ignore failed: {detail or process.returncode}",
                ".gitignore",
            )
        ]

    ignored = {item.decode("utf-8") for item in process.stdout.split(b"\0") if item}
    return [
        _finding(
            "gitignore_probe_not_ignored",
            "public-boundary probe is not ignored by Git",
            probe,
        )
        for probe in GITIGNORE_PROBES
        if probe not in ignored
    ]


def _build_argument_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--root",
        type=Path,
        default=PROJECT_ROOT,
        help="project root to inspect (default: repository containing this script)",
    )
    parser.add_argument(
        "--candidate-source",
        choices=("auto", "filesystem", "git"),
        default="auto",
        help="enumerate Git candidates when available, otherwise use a TFVC-friendly scan",
    )
    parser.add_argument(
        "--allow-missing-license",
        action="store_true",
        help="return success for the preparation phase while still reporting the license blocker",
    )
    return parser


def main(argv: Sequence[str] | None = None) -> int:
    args = _build_argument_parser().parse_args(argv)
    root = args.root.resolve()
    try:
        candidate_paths, source = collect_candidate_paths(root, args.candidate_source)
        result = evaluate_candidate(root, candidate_paths, candidate_source=source)
        if source == "git":
            result["errors"].extend(_check_git_ignore_behavior(root))
            _finalize_result(result)
    except (OSError, RuntimeError, ValueError) as exc:
        result = _finalize_result(
            {
                "schema_version": 1,
                "candidate_source": args.candidate_source,
                "candidate_file_count": 0,
                "status": "failed",
                "ready": False,
                "errors": [_finding("candidate_enumeration_failed", str(exc))],
                "blockers": [],
                "warnings": [],
            }
        )

    print(json.dumps(result, indent=2, sort_keys=True))
    if result["status"] == "failed":
        return 1
    if result["status"] == "blocked_license" and not args.allow_missing_license:
        return 2
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
