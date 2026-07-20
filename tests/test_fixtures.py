"""Corpus tests: every vulnerable fixture must fire its rule; every safe
fixture must stay clean. The safe set is the anti-false-positive contract."""

from pathlib import Path

import pytest

from jsecpy.config import Config
from jsecpy.engine import Engine
from jsecpy.model import Severity

VULN = Path(__file__).parent / "fixtures" / "vulnerable"
SAFE = Path(__file__).parent / "fixtures" / "safe"

# Each vulnerable fixture -> the rule ID(s) it must trigger.
EXPECTED = {
    "SqlInjection.java": {"JSEC-SQLI"},
    "CommandInjection.java": {"JSEC-CMDI"},
    "PathTraversal.java": {"JSEC-PATH"},
    "Ssrf.java": {"JSEC-SSRF"},
    "WeakCrypto.java": {"JSEC-HASH", "JSEC-CIPHER"},
    "InsecureRandom.java": {"JSEC-RANDOM"},
    "Xxe.java": {"JSEC-XXE"},
    "Deserialization.java": {"JSEC-DESER"},
    "TrustAllTls.java": {"JSEC-TLS"},
    "InsecureCookie.java": {"JSEC-COOKIE"},
    "HardcodedSecret.java": {"JSEC-SECRET"},
    "LdapXpath.java": {"JSEC-LDAP", "JSEC-XPATH"},
}


def _scan(path: Path):
    engine = Engine(Config(min_severity=Severity.INFO))
    return engine.scan_source(str(path), path.read_text(encoding="utf-8"))


@pytest.mark.parametrize("filename,expected", EXPECTED.items())
def test_vulnerable_fixture_detected(filename, expected):
    findings = _scan(VULN / filename)
    fired = {f.rule_id for f in findings}
    assert expected <= fired, f"{filename}: expected {expected}, got {fired}"


@pytest.mark.parametrize("path", sorted(SAFE.glob("*.java")), ids=lambda p: p.name)
def test_safe_fixture_is_clean(path):
    findings = _scan(path)
    assert not findings, f"{path.name} false-positived: {[(f.rule_id, f.line) for f in findings]}"


def test_directory_scan_counts_files():
    engine = Engine(Config(min_severity=Severity.INFO, scan_tests=True))
    result = engine.scan_paths([str(VULN)])
    assert result.files_scanned == len(list(VULN.glob("*.java")))
    assert not result.parse_errors, result.parse_errors
    assert len(result.findings) >= len(EXPECTED)
