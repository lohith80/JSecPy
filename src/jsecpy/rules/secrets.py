"""Hardcoded secrets: credentials and keys baked into source.

Two signals: (1) a suspiciously named field/variable assigned a string literal,
and (2) string literals matching known credential formats (AWS keys, private
key blocks, JDBC passwords). Values are masked in the finding snippet.
"""

from __future__ import annotations

import re

from javalang.tree import FieldDeclaration, Literal, LocalVariableDeclaration

from ..java_ast import ParsedUnit, node_position
from ..model import Confidence, Finding, Severity
from . import register
from .base import Rule, TaintCache

_SECRET_NAME = re.compile(
    r"(?i)(pass(word|wd)?|pwd|secret|api[_-]?key|access[_-]?key|token|credential|"
    r"private[_-]?key|client[_-]?secret)"
)

_KNOWN_FORMATS = [
    ("AWS access key ID", re.compile(r"\b(AKIA|ASIA|ABIA|ACCA)[0-9A-Z]{16}\b")),
    ("Private key block", re.compile(r"-----BEGIN [A-Z ]*PRIVATE KEY-----")),
    ("Google API key", re.compile(r"\bAIza[0-9A-Za-z_\-]{35}\b")),
    ("Slack token", re.compile(r"\bxox[baprs]-[0-9A-Za-z\-]{10,}\b")),
    ("JDBC password in URL", re.compile(r"jdbc:[^\"']*password=[^\"'&;\s]+", re.IGNORECASE)),
]

# Values that look like a secret slot but are clearly not a real secret.
_PLACEHOLDERS = {"", "changeme", "password", "example", "test", "xxx", "todo", "null", "none"}


def _mask(value: str) -> str:
    if len(value) <= 4:
        return "*" * len(value)
    return value[:2] + "*" * min(len(value) - 2, 12)


@register
class HardcodedSecret(Rule):
    id = "JSEC-SECRET"
    name = "Hardcoded Secret"
    severity = Severity.HIGH
    confidence = Confidence.MEDIUM
    cwe = ["CWE-798", "CWE-259"]
    owasp = "A07:2021-Identification and Authentication Failures"
    remediation = (
        "Never commit secrets. Load them from environment variables or a secrets "
        "manager (Vault, AWS Secrets Manager) at runtime, and rotate any secret "
        "that has been in source control."
    )
    references = ["https://cwe.mitre.org/data/definitions/798.html"]

    def analyze(self, unit: ParsedUnit, taint: TaintCache) -> list[Finding]:
        findings: list[Finding] = []
        seen: set[tuple[int, str]] = set()

        # (1) suspiciously named declarators with a string literal initializer
        for node_type in (LocalVariableDeclaration, FieldDeclaration):
            for _, decl in unit.tree.filter(node_type):
                for declarator in decl.declarators:
                    init = declarator.initializer
                    if not isinstance(init, Literal) or not isinstance(init.value, str):
                        continue
                    raw = init.value.strip('"')
                    if not raw or raw.lower() in _PLACEHOLDERS:
                        continue
                    if _SECRET_NAME.search(declarator.name) and _looks_secretish(raw):
                        line, col = node_position(init)
                        if (line, declarator.name) in seen:
                            continue
                        seen.add((line, declarator.name))
                        findings.append(self.make_finding(
                            unit, init,
                            f"Hardcoded secret assigned to '{declarator.name}' "
                            f"(value '{_mask(raw)}')."
                        ))

        # (2) known credential formats anywhere in string literals
        for _, lit in unit.tree.filter(Literal):
            if not isinstance(lit.value, str):
                continue
            raw = lit.value.strip('"')
            for label, pattern in _KNOWN_FORMATS:
                m = pattern.search(raw)
                if m:
                    line, _c = node_position(lit)
                    if (line, label) in seen:
                        continue
                    seen.add((line, label))
                    findings.append(self.make_finding(
                        unit, lit, f"{label} hardcoded in source (value '{_mask(m.group(0))}').",
                        confidence=Confidence.HIGH,
                    ))
        return findings


def _looks_secretish(value: str) -> bool:
    """Filter obvious non-secrets: must be reasonably long and not a template."""
    if len(value) < 6:
        return False
    if value.startswith("${") or value.startswith("{{"):  # config interpolation
        return False
    return True
