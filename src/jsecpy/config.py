"""Scan configuration, from CLI flags and/or a .jsecpy.yml file."""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path

import yaml

from .model import Severity

DEFAULT_EXCLUDES = (
    "**/target/**",
    "**/build/**",
    "**/.git/**",
    "**/generated/**",
    "**/*Test.java",
    "**/test/**",
)


@dataclass
class Config:
    min_severity: Severity = Severity.LOW
    fail_on: Severity = Severity.HIGH
    excludes: tuple[str, ...] = DEFAULT_EXCLUDES
    disabled_rules: frozenset[str] = frozenset()
    enabled_rules: frozenset[str] | None = None  # None = all
    yaml_rule_paths: tuple[Path, ...] = ()
    baseline_path: Path | None = None
    scan_tests: bool = False

    def rule_enabled(self, rule_id: str) -> bool:
        if rule_id in self.disabled_rules:
            return False
        if self.enabled_rules is not None:
            return rule_id in self.enabled_rules
        return True

    @classmethod
    def from_file(cls, path: Path) -> Config:
        data = yaml.safe_load(path.read_text(encoding="utf-8")) or {}
        kwargs: dict = {}
        if "min_severity" in data:
            kwargs["min_severity"] = Severity.parse(str(data["min_severity"]))
        if "fail_on" in data:
            kwargs["fail_on"] = Severity.parse(str(data["fail_on"]))
        if "excludes" in data:
            kwargs["excludes"] = tuple(data["excludes"])
        if "disabled_rules" in data:
            kwargs["disabled_rules"] = frozenset(data["disabled_rules"])
        if "enabled_rules" in data:
            kwargs["enabled_rules"] = frozenset(data["enabled_rules"])
        if "yaml_rule_paths" in data:
            kwargs["yaml_rule_paths"] = tuple(Path(p) for p in data["yaml_rule_paths"])
        if "baseline" in data:
            kwargs["baseline_path"] = Path(data["baseline"])
        if "scan_tests" in data:
            kwargs["scan_tests"] = bool(data["scan_tests"])
        return cls(**kwargs)
