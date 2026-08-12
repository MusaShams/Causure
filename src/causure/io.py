"""Safe JSON input and atomic report output."""

from __future__ import annotations

import json
import math
import os
import tempfile
from pathlib import Path
from typing import Any, TextIO

from causure.errors import DocumentValidationError, ValidationIssue
from causure.models import ChangeCase, parse_change_case
from causure.policy import GatePolicy, parse_policy

MAX_DOCUMENT_BYTES = 5 * 1024 * 1024
MAX_TRACE_DOCUMENT_BYTES = 16 * 1024 * 1024


class InputDocumentError(ValueError):
    """Raised when an input document cannot be decoded safely."""


def _reject_duplicate_keys(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise InputDocumentError(f"duplicate JSON key: {key!r}")
        result[key] = value
    return result


def _reject_nonfinite_number(value: str) -> None:
    raise InputDocumentError(f"non-finite JSON number is not allowed: {value}")


def _parse_finite_float(value: str) -> float:
    converted = float(value)
    if not math.isfinite(converted):
        raise InputDocumentError(f"non-finite JSON number is not allowed: {value}")
    return converted


def parse_json_text(
    text: str,
    *,
    source: str,
    max_bytes: int = MAX_DOCUMENT_BYTES,
) -> Any:
    """Parse JSON while rejecting duplicate keys."""

    if len(text.encode("utf-8")) > max_bytes:
        raise InputDocumentError(f"{source} exceeds the {max_bytes}-byte input limit")
    try:
        return json.loads(
            text,
            object_pairs_hook=_reject_duplicate_keys,
            parse_constant=_reject_nonfinite_number,
            parse_float=_parse_finite_float,
        )
    except InputDocumentError:
        raise
    except json.JSONDecodeError as exc:
        raise InputDocumentError(
            f"{source}:{exc.lineno}:{exc.colno}: invalid JSON: {exc.msg}"
        ) from exc
    except (RecursionError, ValueError) as exc:
        raise InputDocumentError(f"{source}: invalid JSON: {exc}") from exc


def read_json_with_bytes(
    path: str | Path,
    *,
    stdin: TextIO | None = None,
    max_bytes: int = MAX_DOCUMENT_BYTES,
) -> tuple[Any, bytes]:
    """Read bounded UTF-8 JSON and return its parsed document and exact bytes."""

    if str(path) == "-":
        if stdin is None:
            raise InputDocumentError("standard input was requested but is unavailable")
        text = stdin.read(max_bytes + 1)
        raw_bytes = text.encode("utf-8")
        return (
            parse_json_text(text, source="<stdin>", max_bytes=max_bytes),
            raw_bytes,
        )

    resolved = Path(path)
    try:
        size = resolved.stat().st_size
        if size > max_bytes:
            raise InputDocumentError(f"{resolved} exceeds the {max_bytes}-byte input limit")
        raw_bytes = resolved.read_bytes()
        if len(raw_bytes) > max_bytes:
            raise InputDocumentError(f"{resolved} exceeds the {max_bytes}-byte input limit")
        text = raw_bytes.decode("utf-8")
    except OSError as exc:
        raise InputDocumentError(f"could not read {resolved}: {exc}") from exc
    except UnicodeDecodeError as exc:
        raise InputDocumentError(f"{resolved} is not valid UTF-8") from exc
    return (
        parse_json_text(text, source=str(resolved), max_bytes=max_bytes),
        raw_bytes,
    )


def read_json(path: str | Path, *, stdin: TextIO | None = None) -> Any:
    """Read a bounded UTF-8 JSON document from disk or standard input."""

    document, _ = read_json_with_bytes(path, stdin=stdin)
    return document


def load_change_case(path: str | Path, *, stdin: TextIO | None = None) -> ChangeCase:
    """Load and structurally validate a change case."""

    return parse_change_case(read_json(path, stdin=stdin))


def load_policy(path: str | Path | None, *, stdin: TextIO | None = None) -> GatePolicy:
    """Load a sparse policy override or return the defaults."""

    if path is None:
        return GatePolicy()
    if str(path) == "-":
        raise DocumentValidationError(
            "gate policy",
            [
                ValidationIssue(
                    "$",
                    "a policy cannot use standard input when the evidence case may also use it",
                )
            ],
        )
    return parse_policy(read_json(path, stdin=stdin))


def atomic_write_text(path: str | Path, content: str) -> None:
    """Write a UTF-8 text file atomically in its destination directory."""

    destination = Path(path)
    destination.parent.mkdir(parents=True, exist_ok=True)
    temporary_name: str | None = None
    try:
        with tempfile.NamedTemporaryFile(
            mode="w",
            encoding="utf-8",
            newline="\n",
            dir=destination.parent,
            prefix=f".{destination.name}.",
            suffix=".tmp",
            delete=False,
        ) as temporary:
            temporary.write(content)
            temporary.flush()
            os.fsync(temporary.fileno())
            temporary_name = temporary.name
        os.replace(temporary_name, destination)
    finally:
        if temporary_name and os.path.exists(temporary_name):
            os.unlink(temporary_name)


def atomic_write_bytes(path: str | Path, content: bytes) -> None:
    """Write exact bytes atomically in their destination directory."""

    destination = Path(path)
    destination.parent.mkdir(parents=True, exist_ok=True)
    temporary_name: str | None = None
    try:
        with tempfile.NamedTemporaryFile(
            mode="wb",
            dir=destination.parent,
            prefix=f".{destination.name}.",
            suffix=".tmp",
            delete=False,
        ) as temporary:
            temporary.write(content)
            temporary.flush()
            os.fsync(temporary.fileno())
            temporary_name = temporary.name
        os.replace(temporary_name, destination)
    finally:
        if temporary_name and os.path.exists(temporary_name):
            os.unlink(temporary_name)
