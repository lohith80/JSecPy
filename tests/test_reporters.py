"""Reporter output must be valid and machine-consumable, especially SARIF."""

import json
from pathlib import Path

from jsecpy.config import Config
from jsecpy.engine import Engine
from jsecpy.model import Severity
from jsecpy.reporters import render_cli, render_json, render_sarif

VULN = Path(__file__).parent / "fixtures" / "vulnerable"


def _result():
    return Engine(Config(min_severity=Severity.INFO)).scan_paths([str(VULN)])


def test_json_is_valid_and_structured():
    payload = json.loads(render_json(_result()))
    assert payload["tool"] == "JSecPy"
    assert payload["summary"]["total_findings"] > 0
    assert all("cwe" in f for f in payload["findings"])


def test_sarif_is_valid_2_1_0():
    doc = json.loads(render_sarif(_result()))
    assert doc["version"] == "2.1.0"
    run = doc["runs"][0]
    assert run["tool"]["driver"]["name"] == "JSecPy"
    assert run["tool"]["driver"]["rules"], "rules array must not be empty"
    for r in run["results"]:
        assert r["ruleId"]
        assert r["level"] in {"error", "warning", "note"}
        assert r["locations"][0]["physicalLocation"]["region"]["startLine"] >= 1
    # security-severity is what GitHub uses to bucket alerts
    for rule in run["tool"]["driver"]["rules"]:
        assert "security-severity" in rule["properties"]


def test_sarif_has_codeflows_for_taint():
    doc = json.loads(render_sarif(_result()))
    results = doc["runs"][0]["results"]
    assert any("codeFlows" in r for r in results), "taint findings should carry a codeFlow"


def test_cli_renders_without_color():
    text = render_cli(_result(), color=False)
    assert "JSecPy summary" in text
    assert "\033[" not in text  # no ANSI escapes when color disabled
