"""Engine behaviour: taint vs concat confidence, suppression, baseline,
severity gating, YAML rules, and graceful handling of unparseable input."""

from pathlib import Path

from jsecpy.config import Config
from jsecpy.engine import Engine, write_baseline
from jsecpy.model import Confidence, Severity


def scan(code, config=None):
    engine = Engine(config or Config(min_severity=Severity.INFO))
    return engine.scan_source("Test.java", code)


SQLI_TAINTED = """
import javax.servlet.http.HttpServletRequest;
import java.sql.*;
public class T {
  void m(HttpServletRequest req, Connection c) throws Exception {
    String n = req.getParameter("n");
    Statement s = c.createStatement();
    s.executeQuery("select * from t where n='" + n + "'");
  }
}
"""

SQLI_CONCAT_ONLY = """
import java.sql.*;
public class T {
  void m(Connection c, String n) throws Exception {
    Statement s = c.createStatement();
    s.executeQuery("select * from t where n='" + n + "'");
  }
}
"""


def test_tainted_is_high_confidence():
    findings = [f for f in scan(SQLI_TAINTED) if f.rule_id == "JSEC-SQLI"]
    assert findings and findings[0].confidence == Confidence.HIGH
    assert findings[0].severity == Severity.CRITICAL
    assert any("source" in s.label for s in findings[0].flow)


def test_concat_without_proven_taint_is_medium():
    findings = [f for f in scan(SQLI_CONCAT_ONLY) if f.rule_id == "JSEC-SQLI"]
    assert findings and findings[0].confidence == Confidence.MEDIUM


def test_inline_suppression():
    code2 = """
import javax.servlet.http.HttpServletRequest;
import java.sql.*;
public class T {
  void m(HttpServletRequest req, Connection c) throws Exception {
    String n = req.getParameter("n");
    Statement s = c.createStatement();
    s.executeQuery("select * from t where n='" + n + "'"); // jsecpy:ignore[JSEC-SQLI]
  }
}
"""
    assert not [f for f in scan(code2) if f.rule_id == "JSEC-SQLI"]


def test_bare_suppression_ignores_all_rules_on_line():
    code = """
import javax.servlet.http.HttpServletRequest;
public class T {
  void m(HttpServletRequest req) throws Exception {
    String c = req.getParameter("c");
    Runtime.getRuntime().exec(c); // jsecpy:ignore
  }
}
"""
    assert not scan(code)


def test_severity_gating():
    # WeakHash is MEDIUM; with min HIGH it is filtered out.
    code = """
import java.security.MessageDigest;
public class T { void m() throws Exception { MessageDigest.getInstance("MD5"); } }
"""
    assert scan(code, Config(min_severity=Severity.INFO))
    assert not scan(code, Config(min_severity=Severity.HIGH))


def test_disable_rule():
    config = Config(min_severity=Severity.INFO, disabled_rules=frozenset({"JSEC-SQLI"}))
    assert not [f for f in scan(SQLI_TAINTED, config) if f.rule_id == "JSEC-SQLI"]


def test_unparseable_file_is_recorded_not_crashed():
    engine = Engine(Config(min_severity=Severity.INFO))
    result = engine.scan_paths([])  # empty
    assert result.files_scanned == 0
    # Now feed junk directly
    from jsecpy.engine import ScanResult
    r = ScanResult()
    engine._run_rules("Bad.java", "this is not java @@@", r)
    assert r.parse_errors and r.files_scanned == 0


def test_baseline_roundtrip(tmp_path):
    engine = Engine(Config(min_severity=Severity.INFO))
    result = engine.scan_paths([str(Path(__file__).parent / "fixtures" / "vulnerable")])
    baseline = tmp_path / "baseline.json"
    write_baseline(result, baseline)
    # Re-scan with baseline: everything known is suppressed.
    engine2 = Engine(Config(min_severity=Severity.INFO, baseline_path=baseline))
    result2 = engine2.scan_paths([str(Path(__file__).parent / "fixtures" / "vulnerable")])
    assert not result2.findings


def test_yaml_rules_load(tmp_path):
    rule_file = tmp_path / "r.yml"
    rule_file.write_text(
        "rules:\n"
        "  - id: JSEC-Y-TEST\n"
        "    name: Test Sink\n"
        "    severity: HIGH\n"
        "    sinks: [dangerous:Widget]\n"
        "    require_taint: false\n",
        encoding="utf-8",
    )
    code = """
public class T {
  void m(Widget w, String s) { w.dangerous("x" + s); }
}
"""
    config = Config(min_severity=Severity.INFO, yaml_rule_paths=(rule_file,))
    findings = [f for f in Engine(config).scan_source("T.java", code) if f.rule_id == "JSEC-Y-TEST"]
    assert findings
