"""Rule base classes and the taint-cache the engine hands to every rule.

Two rule shapes cover almost everything:

* ``TaintSinkRule`` - a dangerous call (SQL, exec, file open, ...) that is only
  a vulnerability when attacker-controlled data reaches it. Subclass, declare
  ``SINKS`` and which argument indices are dangerous, done.
* ``Rule`` - free-form AST inspection for configuration/crypto issues that are
  bugs regardless of taint (weak hash, disabled TLS validation, XXE parser
  built without hardening, hardcoded secret, ...).
"""

from __future__ import annotations

from javalang.tree import ClassCreator, MethodInvocation

from ..java_ast import ParsedUnit, iter_methods, local_types, node_position
from ..model import Confidence, Finding, FlowStep, Severity
from ..sources_sinks import Signature
from ..taint import TaintResult, analyze_method


class TaintCache:
    """Lazily computes and memoises taint per method within one unit."""

    def __init__(self) -> None:
        self._cache: dict[int, TaintResult] = {}

    def get(self, method) -> TaintResult:
        key = id(method)
        if key not in self._cache:
            self._cache[key] = analyze_method(method)
        return self._cache[key]


class Rule:
    id: str = ""
    name: str = ""
    severity: Severity = Severity.MEDIUM
    confidence: Confidence = Confidence.MEDIUM
    cwe: list[str] = []
    owasp: str | None = None
    remediation: str = ""
    references: list[str] = []

    def analyze(self, unit: ParsedUnit, taint: TaintCache) -> list[Finding]:  # pragma: no cover
        raise NotImplementedError

    # -- helpers shared by all rules -------------------------------------------------

    def make_finding(
        self,
        unit: ParsedUnit,
        node,
        message: str,
        *,
        severity: Severity | None = None,
        confidence: Confidence | None = None,
        flow: list[FlowStep] | None = None,
    ) -> Finding:
        line, col = node_position(node)
        return Finding(
            rule_id=self.id,
            name=self.name,
            message=message,
            severity=severity or self.severity,
            confidence=confidence or self.confidence,
            file=unit.path,
            line=line,
            column=col,
            snippet=unit.line_text(line),
            cwe=list(self.cwe),
            owasp=self.owasp,
            remediation=self.remediation,
            references=list(self.references),
            flow=flow or [],
        )


class TaintSinkRule(Rule):
    # Signatures that identify the dangerous call.
    SINKS: tuple[Signature, ...] = ()
    # Argument indices to inspect for taint; None means "any argument".
    TAINTED_ARG_INDICES: tuple[int, ...] | None = None
    # If True, a string-concatenation argument (built with +) that we cannot
    # prove tainted is still reported at reduced confidence. On for injection
    # rules where "built a query with +" is a strong smell on its own.
    FLAG_CONCAT: bool = True

    def analyze(self, unit: ParsedUnit, taint: TaintCache) -> list[Finding]:
        findings: list[Finding] = []
        for method in iter_methods(unit.tree):
            types = local_types(method)
            result = taint.get(method)
            for _, inv in method.filter(MethodInvocation):
                if self._is_sink(inv, types):
                    finding = self._check_invocation(unit, inv, result)
                    if finding is not None:
                        findings.append(finding)
            for _, creator in method.filter(ClassCreator):
                if self._is_constructor_sink(creator):
                    finding = self._check_invocation(unit, creator, result)
                    if finding is not None:
                        findings.append(finding)
        return findings

    def _is_sink(self, inv: MethodInvocation, types: dict[str, str]) -> bool:
        return any(sig.matches(inv, types) for sig in self.SINKS)

    def _is_constructor_sink(self, creator: ClassCreator) -> bool:
        created = getattr(creator.type, "name", "")
        for sig in self.SINKS:
            if sig.member == "<init>" and (not sig.receiver_types or created in sig.receiver_types):
                return True
        return False

    def _args_to_check(self, inv: MethodInvocation):
        args = inv.arguments or []
        if self.TAINTED_ARG_INDICES is None:
            return list(enumerate(args))
        return [(i, args[i]) for i in self.TAINTED_ARG_INDICES if i < len(args)]

    def _check_invocation(self, unit, inv, result) -> Finding | None:
        line, _ = node_position(inv)
        sink_step = FlowStep(line, 0, f"sink: {self._sink_label(inv)}", unit.line_text(line))

        for _, arg in self._args_to_check(inv):
            if result.is_expr_tainted(arg):
                source = result.source_for(arg)
                flow = [source, sink_step] if source else [sink_step]
                return self.make_finding(
                    unit,
                    inv,
                    self._message(inv, tainted=True),
                    confidence=Confidence.HIGH,
                    flow=flow,
                )

        if self.FLAG_CONCAT:
            for _, arg in self._args_to_check(inv):
                if result.concat_has_variable(arg):
                    return self.make_finding(
                        unit,
                        inv,
                        self._message(inv, tainted=False),
                        confidence=Confidence.MEDIUM,
                        flow=[sink_step],
                    )
        return None

    def _sink_label(self, inv) -> str:
        if isinstance(inv, ClassCreator):
            return f"new {getattr(inv.type, 'name', '?')}"
        return f"{inv.qualifier + '.' if inv.qualifier else ''}{inv.member}"

    def _message(self, inv, *, tainted: bool) -> str:
        origin = "attacker-controlled input" if tainted else "a dynamically built string"
        return f"{self.name}: {origin} reaches {self._sink_label(inv)}()."
