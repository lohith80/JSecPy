"""SARIF 2.1.0 output.

SARIF is the lingua franca of code scanning: upload this to GitHub Advanced
Security (github/codeql-action/upload-sarif) and every finding shows up as an
annotation on the PR, with the CWE and OWASP tags attached to each rule.
"""

from __future__ import annotations

import json

from .. import __version__
from ..engine import ScanResult
from ..model import Finding, Severity

_SARIF_LEVEL = {
    Severity.CRITICAL: "error",
    Severity.HIGH: "error",
    Severity.MEDIUM: "warning",
    Severity.LOW: "note",
    Severity.INFO: "note",
}

# SARIF security-severity is a 0.0-10.0 string; GitHub uses it to bucket alerts.
_SECURITY_SEVERITY = {
    Severity.CRITICAL: "9.5",
    Severity.HIGH: "8.0",
    Severity.MEDIUM: "5.5",
    Severity.LOW: "3.0",
    Severity.INFO: "1.0",
}


def render_sarif(result: ScanResult) -> str:
    rules_seen: dict[str, dict] = {}
    results: list[dict] = []

    for f in result.findings:
        if f.rule_id not in rules_seen:
            rules_seen[f.rule_id] = _rule_descriptor(f)
        results.append(_result(f))

    sarif = {
        "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
        "version": "2.1.0",
        "runs": [
            {
                "tool": {
                    "driver": {
                        "name": "JSecPy",
                        "informationUri": "https://github.com/lohith80/JSecPy",
                        "version": __version__,
                        "rules": list(rules_seen.values()),
                    }
                },
                "results": results,
            }
        ],
    }
    return json.dumps(sarif, indent=2)


def _rule_descriptor(f: Finding) -> dict:
    tags = ["security"] + list(f.cwe)
    if f.owasp:
        tags.append(f.owasp)
    return {
        "id": f.rule_id,
        "name": f.name.replace(" ", ""),
        "shortDescription": {"text": f.name},
        "fullDescription": {"text": f.remediation or f.name},
        "helpUri": f.references[0] if f.references else "https://github.com/lohith80/JSecPy",
        "properties": {
            "tags": tags,
            "security-severity": _SECURITY_SEVERITY[f.severity],
            "cwe": f.cwe,
            "owasp": f.owasp,
        },
    }


def _result(f: Finding) -> dict:
    location = {
        "physicalLocation": {
            "artifactLocation": {"uri": _uri(f.file)},
            "region": {
                "startLine": max(f.line, 1),
                "startColumn": max(f.column, 1),
                "snippet": {"text": f.snippet},
            },
        }
    }
    result = {
        "ruleId": f.rule_id,
        "level": _SARIF_LEVEL[f.severity],
        "message": {"text": f.message},
        "locations": [location],
        "properties": {"confidence": str(f.confidence), "cwe": f.cwe, "owasp": f.owasp},
    }
    if f.flow:
        result["codeFlows"] = [
            {
                "threadFlows": [
                    {
                        "locations": [
                            {
                                "location": {
                                    "physicalLocation": {
                                        "artifactLocation": {"uri": _uri(f.file)},
                                        "region": {"startLine": max(step.line, 1)},
                                    },
                                    "message": {"text": step.label},
                                }
                            }
                            for step in f.flow
                        ]
                    }
                ]
            }
        ]
    return result


def _uri(path: str) -> str:
    return path.replace("\\", "/")
