"""Core data model: findings, severity, confidence, and taint flow steps.

A Finding is the single currency of the tool. Every detector, whether written
in Python or loaded from a YAML rule, produces Findings in this exact shape so
the reporters (CLI, JSON, SARIF) never need to know which detector fired.
"""

from __future__ import annotations

import enum
from dataclasses import dataclass, field


class Severity(enum.IntEnum):
    """Ordered so thresholds compare numerically (INFO < ... < CRITICAL)."""

    INFO = 0
    LOW = 1
    MEDIUM = 2
    HIGH = 3
    CRITICAL = 4

    @classmethod
    def parse(cls, value: str) -> Severity:
        return cls[value.strip().upper()]

    def __str__(self) -> str:  # pragma: no cover - trivial
        return self.name


class Confidence(enum.IntEnum):
    LOW = 0
    MEDIUM = 1
    HIGH = 2

    def __str__(self) -> str:  # pragma: no cover - trivial
        return self.name


@dataclass(frozen=True)
class FlowStep:
    """One node in a source -> ... -> sink taint path, for explainable output."""

    line: int
    column: int
    label: str  # e.g. "source: req.getParameter", "propagated via +", "sink: executeQuery"
    snippet: str = ""


@dataclass
class Finding:
    rule_id: str
    name: str
    message: str
    severity: Severity
    confidence: Confidence
    file: str
    line: int
    column: int = 0
    snippet: str = ""
    cwe: list[str] = field(default_factory=list)  # e.g. ["CWE-89"]
    owasp: str | None = None  # e.g. "A03:2021-Injection"
    remediation: str = ""
    references: list[str] = field(default_factory=list)
    flow: list[FlowStep] = field(default_factory=list)

    def key(self) -> tuple:
        """Stable identity for dedup, baselines, and suppression matching.

        Deliberately excludes the line number so a finding survives unrelated
        edits above it; uses the code snippet instead. See engine baseline docs.
        """
        return (self.rule_id, self.file, self.snippet.strip())

    def sort_key(self) -> tuple:
        return (-int(self.severity), -int(self.confidence), self.file, self.line, self.rule_id)
