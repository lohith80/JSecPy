"""User-extensible YAML rules.

Security teams can add detections without writing Python. Each rule matches
method-invocation sinks by member name (and optional receiver types) and can
require taint on the arguments. This covers the long tail of org-specific
banned APIs and framework sinks. Example: config/rules_yaml/example.yml.

Schema (per rule):
    id: JSEC-Y-XXX            # required, must start with JSEC-Y-
    name: Human name          # required
    severity: HIGH            # CRITICAL|HIGH|MEDIUM|LOW|INFO
    confidence: MEDIUM        # HIGH|MEDIUM|LOW
    cwe: [CWE-000]
    owasp: "A03:2021-Injection"
    remediation: "..."
    sinks:                    # required, list of member[:Type1|Type2]
      - executeQuery:Statement
      - exec:Runtime
    require_taint: true       # if true, only flag when an argument is tainted
    arg_indices: [0]          # optional; default = any argument
    references: ["..."]
"""

from __future__ import annotations

from pathlib import Path

import yaml

from .model import Confidence, Severity
from .rules.base import TaintSinkRule
from .sources_sinks import Signature


class YamlRuleError(ValueError):
    pass


def _parse_sink(spec: str) -> Signature:
    if ":" in spec:
        member, types = spec.split(":", 1)
        receiver_types = frozenset(t.strip() for t in types.split("|") if t.strip())
        return Signature(member=member.strip(), receiver_types=receiver_types)
    return Signature(member=spec.strip())


def _build_rule(data: dict) -> TaintSinkRule:
    for required in ("id", "name", "sinks"):
        if required not in data:
            raise YamlRuleError(f"YAML rule missing required field '{required}': {data!r}")
    rule_id = str(data["id"])
    if not rule_id.startswith("JSEC-Y-"):
        raise YamlRuleError(f"YAML rule id must start with 'JSEC-Y-': {rule_id}")

    arg_indices = data.get("arg_indices")
    sinks = tuple(_parse_sink(s) for s in data["sinks"])

    attrs = {
        "id": rule_id,
        "name": str(data["name"]),
        "severity": Severity.parse(str(data.get("severity", "MEDIUM"))),
        "confidence": Confidence[str(data.get("confidence", "MEDIUM")).upper()],
        "cwe": list(data.get("cwe", [])),
        "owasp": data.get("owasp"),
        "remediation": str(data.get("remediation", "")),
        "references": list(data.get("references", [])),
        "SINKS": sinks,
        "TAINTED_ARG_INDICES": tuple(arg_indices) if arg_indices is not None else None,
        "FLAG_CONCAT": not bool(data.get("require_taint", False)),
    }
    return type(f"YamlRule_{rule_id.replace('-', '_')}", (TaintSinkRule,), attrs)()


def load_yaml_rules(paths: list[Path]) -> list[TaintSinkRule]:
    rules: list[TaintSinkRule] = []
    for path in paths:
        for yaml_file in _iter_yaml_files(path):
            documents = yaml.safe_load(yaml_file.read_text(encoding="utf-8")) or []
            if isinstance(documents, dict):
                documents = documents.get("rules", [documents])
            for doc in documents:
                rules.append(_build_rule(doc))
    return rules


def _iter_yaml_files(path: Path):
    if path.is_dir():
        yield from sorted(path.glob("**/*.yml"))
        yield from sorted(path.glob("**/*.yaml"))
    elif path.exists():
        yield path
