"""Scan orchestration: discover -> parse -> run rules -> suppress/baseline/filter."""

from __future__ import annotations

import fnmatch
import json
import re
from dataclasses import dataclass, field
from pathlib import Path

from .config import Config
from .java_ast import JavaParseError, parse_unit
from .model import Finding, Severity
from .rules import load_builtin_rules
from .rules.base import Rule, TaintCache
from .yaml_rules import load_yaml_rules

_SUPPRESS = re.compile(r"//\s*jsecpy:ignore(?:\[([^\]]+)\])?")


@dataclass
class ScanResult:
    findings: list[Finding] = field(default_factory=list)
    files_scanned: int = 0
    parse_errors: list[str] = field(default_factory=list)
    suppressed: int = 0

    def max_severity(self) -> Severity | None:
        return max((f.severity for f in self.findings), default=None)


class Engine:
    def __init__(self, config: Config | None = None):
        self.config = config or Config()
        self.rules: list[Rule] = [
            r for r in load_builtin_rules() if self.config.rule_enabled(r.id)
        ]
        if self.config.yaml_rule_paths:
            self.rules += [
                r for r in load_yaml_rules(list(self.config.yaml_rule_paths))
                if self.config.rule_enabled(r.id)
            ]
        self._baseline = self._load_baseline()

    def scan_paths(self, paths: list[str | Path]) -> ScanResult:
        result = ScanResult()
        for java_file in self._discover(paths):
            self._scan_file(java_file, result)
        result.findings = self._postprocess(result.findings)
        return result

    def scan_source(self, path: str, code: str) -> list[Finding]:
        """Scan a single in-memory unit (used by tests and stdin)."""
        result = ScanResult()
        self._run_rules(path, code, result)
        return self._postprocess(result.findings)

    # -- internals -------------------------------------------------------------------

    def _discover(self, paths: list[str | Path]) -> list[Path]:
        found: list[Path] = []
        for raw in paths:
            p = Path(raw)
            candidates = [p] if p.is_file() else sorted(p.rglob("*.java"))
            for c in candidates:
                if c.suffix != ".java":
                    continue
                if self._excluded(c):
                    continue
                found.append(c)
        return found

    def _excluded(self, path: Path) -> bool:
        posix = path.as_posix()
        for pattern in self.config.excludes:
            if self.config.scan_tests and ("Test" in pattern or "test" in pattern):
                continue
            if fnmatch.fnmatch(posix, pattern):
                return True
        return False

    def _scan_file(self, path: Path, result: ScanResult) -> None:
        try:
            code = path.read_text(encoding="utf-8", errors="replace")
        except OSError as exc:
            result.parse_errors.append(f"{path}: {exc}")
            return
        self._run_rules(str(path), code, result)

    def _run_rules(self, path: str, code: str, result: ScanResult) -> None:
        try:
            unit = parse_unit(path, code)
        except JavaParseError as exc:
            result.parse_errors.append(str(exc))
            return
        result.files_scanned += 1
        taint = TaintCache()
        for rule in self.rules:
            try:
                for finding in rule.analyze(unit, taint):
                    if self._suppressed(finding, unit.lines):
                        result.suppressed += 1
                        continue
                    result.findings.append(finding)
            except Exception as exc:  # a buggy rule must not abort the whole scan
                result.parse_errors.append(f"{path}: rule {rule.id} error: {exc}")

    def _suppressed(self, finding: Finding, lines: list[str]) -> bool:
        for line_no in (finding.line, finding.line - 1):
            if 1 <= line_no <= len(lines):
                m = _SUPPRESS.search(lines[line_no - 1])
                if m:
                    ids = m.group(1)
                    if ids is None or finding.rule_id in {i.strip() for i in ids.split(",")}:
                        return True
        return False

    def _postprocess(self, findings: list[Finding]) -> list[Finding]:
        deduped: dict[tuple, Finding] = {}
        for f in findings:
            deduped.setdefault(f.key(), f)
        kept = [
            f for f in deduped.values()
            if f.severity >= self.config.min_severity and f.key() not in self._baseline
        ]
        kept.sort(key=lambda f: f.sort_key())
        return kept

    def _load_baseline(self) -> set[tuple]:
        if not self.config.baseline_path or not self.config.baseline_path.exists():
            return set()
        data = json.loads(self.config.baseline_path.read_text(encoding="utf-8"))
        return {tuple(entry) for entry in data.get("findings", [])}


def write_baseline(result: ScanResult, path: Path) -> None:
    payload = {"findings": [list(f.key()) for f in result.findings]}
    path.write_text(json.dumps(payload, indent=2), encoding="utf-8")
