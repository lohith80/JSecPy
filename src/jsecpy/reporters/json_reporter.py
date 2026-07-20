"""Machine-readable JSON output for pipelines and dashboards."""

from __future__ import annotations

import json

from ..engine import ScanResult
from ..model import Finding


def _finding_dict(f: Finding) -> dict:
    return {
        "rule_id": f.rule_id,
        "name": f.name,
        "message": f.message,
        "severity": str(f.severity),
        "confidence": str(f.confidence),
        "file": f.file.replace("\\", "/"),
        "line": f.line,
        "column": f.column,
        "snippet": f.snippet,
        "cwe": f.cwe,
        "owasp": f.owasp,
        "remediation": f.remediation,
        "references": f.references,
        "flow": [
            {"line": s.line, "column": s.column, "label": s.label, "snippet": s.snippet}
            for s in f.flow
        ],
    }


def render_json(result: ScanResult) -> str:
    counts: dict[str, int] = {}
    for f in result.findings:
        counts[str(f.severity)] = counts.get(str(f.severity), 0) + 1
    payload = {
        "tool": "JSecPy",
        "summary": {
            "files_scanned": result.files_scanned,
            "total_findings": len(result.findings),
            "by_severity": counts,
            "suppressed": result.suppressed,
            "parse_errors": len(result.parse_errors),
        },
        "findings": [_finding_dict(f) for f in result.findings],
        "parse_errors": result.parse_errors,
    }
    return json.dumps(payload, indent=2)
