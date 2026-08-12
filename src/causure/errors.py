"""Domain-specific exceptions."""

from dataclasses import dataclass


@dataclass(frozen=True, slots=True)
class ValidationIssue:
    """One structural problem in an input document."""

    path: str
    message: str

    def __str__(self) -> str:
        return f"{self.path}: {self.message}"


class DocumentValidationError(ValueError):
    """Raised when an evidence case or policy is structurally invalid."""

    def __init__(self, document_name: str, issues: list[ValidationIssue]) -> None:
        self.document_name = document_name
        self.issues = tuple(issues)
        details = "\n".join(f"- {issue}" for issue in self.issues)
        super().__init__(f"Invalid {document_name}:\n{details}")


class TraceCollectionError(ValueError):
    """Raised when an untrusted trace export cannot be collected safely."""

    def __init__(self, path: str, message: str) -> None:
        self.path = path
        self.message = message
        super().__init__(f"Invalid OTLP trace export at {path}: {message}")
