"""Human-readable terminal output with optional ANSI colour."""

from __future__ import annotations

from ..engine import ScanResult
from ..model import Severity

_COLORS = {
    Severity.CRITICAL: "\033[1;35m",
    Severity.HIGH: "\033[1;31m",
    Severity.MEDIUM: "\033[1;33m",
    Severity.LOW: "\033[1;36m",
    Severity.INFO: "\033[1;37m",
}
_RESET = "\033[0m"
_DIM = "\033[2m"
_BOLD = "\033[1m"


def _c(text: str, code: str, color: bool) -> str:
    return f"{code}{text}{_RESET}" if color else text


def render_cli(result: ScanResult, color: bool = True) -> str:
    out: list[str] = []

    if not result.findings:
        out.append(_c("No security findings.", _BOLD, color))
    for f in result.findings:
        sev = _c(f"{f.severity}", _COLORS[f.severity], color)
        conf = _c(f"{f.confidence.name.lower()} confidence", _DIM, color)
        cwe = ", ".join(f.cwe) if f.cwe else "-"
        loc = _c(f"{_uri(f.file)}:{f.line}", _BOLD, color)
        out.append(f"[{sev}] {_c(f.name, _BOLD, color)}  ({f.rule_id}, {conf})")
        out.append(f"  {loc}")
        if f.snippet:
            out.append(f"  {_c('> ' + f.snippet, _DIM, color)}")
        out.append(f"  {f.message}")
        out.append(f"  {_c('CWE:', _DIM, color)} {cwe}    {_c('OWASP:', _DIM, color)} {f.owasp or '-'}")
        for step in f.flow:
            out.append(f"    {_c('flow:', _DIM, color)} line {step.line} {step.label}")
        if f.remediation:
            out.append(f"  {_c('Fix:', _DIM, color)} {f.remediation}")
        out.append("")

    out.append(_summary(result, color))
    return "\n".join(out)


def _summary(result: ScanResult, color: bool) -> str:
    counts: dict[Severity, int] = {}
    for f in result.findings:
        counts[f.severity] = counts.get(f.severity, 0) + 1
    parts = [
        f"{counts.get(sev, 0)} {sev}"
        for sev in (Severity.CRITICAL, Severity.HIGH, Severity.MEDIUM, Severity.LOW)
        if counts.get(sev, 0)
    ]
    breakdown = ", ".join(parts) if parts else "0 findings"
    header = _c("JSecPy summary", _BOLD, color)
    line = (
        f"{header}: {len(result.findings)} findings ({breakdown}) "
        f"across {result.files_scanned} file(s)"
    )
    if result.suppressed:
        line += f"; {result.suppressed} suppressed"
    if result.parse_errors:
        line += f"; {len(result.parse_errors)} file(s) failed to parse"
    return line


def _uri(path: str) -> str:
    return path.replace("\\", "/")
