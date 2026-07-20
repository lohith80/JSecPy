# Writing custom rules

JSecPy ships two ways to add detections: **YAML rules** (no code, covers most
sink-based cases) and **Python rules** (full AST access for anything else).

## YAML rules (recommended for banned/dangerous APIs)

A YAML rule declares a dangerous method invocation ("sink") and, optionally,
that its arguments must be attacker-controlled. This covers the long tail of
org-specific banned APIs and framework sinks.

Create a file, e.g. `security/jsecpy-rules.yml`:

```yaml
rules:
  - id: JSEC-Y-INTERNALHTTP        # must start with JSEC-Y-
    name: Unvetted internal HTTP client
    severity: HIGH                 # CRITICAL|HIGH|MEDIUM|LOW|INFO
    confidence: MEDIUM             # HIGH|MEDIUM|LOW
    cwe: [CWE-918]
    owasp: "A10:2021-Server-Side Request Forgery"
    remediation: "Route outbound calls through the vetted HttpGateway wrapper."
    sinks:
      - fetch:InternalHttpClient   # member:ReceiverType (type is optional)
      - get:InternalHttpClient
    require_taint: true            # only flag attacker-controlled arguments
    arg_indices: [0]              # which args to check (omit = all)
    references: ["https://internal.wiki/ssrf"]
```

Run it:

```bash
jsecpy src/ --rules security/jsecpy-rules.yml
# or set yaml_rule_paths in .jsecpy.yml
```

Notes:
- `sinks` entries are `member` or `member:Type1|Type2`. With a type, the rule
  only fires when the receiver's declared type matches, cutting false positives.
- `require_taint: true` reports only when the taint engine proves the argument
  is attacker-controlled. Omit it to also flag string-concatenation arguments
  at reduced confidence.

## Python rules (full AST)

For configuration/crypto checks or anything needing structural analysis,
subclass `Rule` (free-form) or `TaintSinkRule` (sink + taint). Drop a module
in `src/jsecpy/rules/` and decorate the class with `@register`.

```python
from javalang.tree import MethodInvocation
from ..model import Severity
from . import register
from .base import Rule, TaintCache
from ..java_ast import ParsedUnit

@register
class DebugEndpoint(Rule):
    id = "JSEC-DEBUG"
    name = "Debug Endpoint Left Enabled"
    severity = Severity.MEDIUM
    cwe = ["CWE-489"]
    owasp = "A05:2021-Security Misconfiguration"
    remediation = "Remove or guard debug endpoints in production builds."

    def analyze(self, unit: ParsedUnit, taint: TaintCache):
        findings = []
        for _, inv in unit.tree.filter(MethodInvocation):
            if inv.member == "enableDebug":
                findings.append(self.make_finding(unit, inv, "Debug mode enabled."))
        return findings
```

For a taint-based sink rule, subclass `TaintSinkRule` and just declare `SINKS`
and `TAINTED_ARG_INDICES` - the base class handles taint checking, concat
fallback, flow reporting, and constructor (`new X(...)`) sinks. See
`src/jsecpy/rules/injection.py` for worked examples.

## Testing your rule

Add a vulnerable fixture under `tests/fixtures/vulnerable/` and a safe one
under `tests/fixtures/safe/`, then wire the expectation into
`tests/test_fixtures.py`. The safe fixture is your false-positive contract.
