"""Intra-procedural taint analysis.

Scope (documented honestly, see docs/THREAT_MODEL.md):
- Analysis is per-method and flow-insensitive: it computes, via a small
  fixed point, the set of local variables that can hold attacker-controlled
  data anywhere in the method. This favours recall (few false negatives) at
  the cost of some precision, which is the right trade for a security scanner.
- No cross-method / cross-field propagation. A tainted value stored in a
  field and read back in another method is not tracked (known limitation).
- No propagation through collections/maps (put/get). Also a known limitation.

Precision is preserved by threading each method's declared local/parameter
types through every source/sink/sanitizer decision, so ``request.getParameter``
is a source but ``config.getParameter`` (a different receiver type) is not.
"""

from __future__ import annotations

from dataclasses import dataclass, field

from javalang.tree import (
    Assignment,
    BinaryOperation,
    Cast,
    ClassCreator,
    Literal,
    LocalVariableDeclaration,
    MemberReference,
    MethodInvocation,
    Node,
    TernaryExpression,
)

from .java_ast import local_types, node_position
from .model import FlowStep
from .sources_sinks import (
    NUMERIC_BOX_TYPES,
    NUMERIC_SAFE_CONCAT_TYPES,
    PASSTHROUGH_MEMBERS,
    SANITIZERS,
    SOURCES,
    resolve_receiver_type,
)


@dataclass
class TaintResult:
    tainted: set[str]
    types: dict[str, str]
    # variable name -> the source FlowStep that first tainted it (for reporting)
    origin: dict[str, FlowStep]
    # variables that are safe to concatenate: numeric/boolean typed, or assigned
    # from a sanitizer call. Used to suppress the "built with +" concat smell.
    sanitized: set[str] = field(default_factory=set)

    def is_expr_tainted(self, node: Node) -> bool:
        return _expr_tainted(node, self.tainted, self.types)

    def concat_has_variable(self, node: Node) -> bool:
        """True if the expression is a string concatenation mixing a literal
        with a non-literal that is NOT provably safe (numeric-typed or
        sanitized). This is the classic 'built a query with +' smell used at
        reduced confidence when we cannot prove taint outright."""
        return _concat_has_variable(node, self.types, self.sanitized)

    def source_for(self, node: Node) -> FlowStep | None:
        for name in _referenced_names(node):
            if name in self.origin:
                return self.origin[name]
        # Inline source with no intervening variable, e.g.
        # stmt.executeQuery(req.getParameter("q")). Synthesize the source step
        # so the data-flow trace keeps both ends.
        for _, inv in _walk_invocations(node):
            if _is_source(inv, self.types):
                line, col = node_position(inv)
                return FlowStep(line, col, _source_label(inv))
        return None


def analyze_method(method) -> TaintResult:
    types = local_types(method)
    tainted: set[str] = set()
    origin: dict[str, FlowStep] = {}

    # main(String[] args): command-line arguments are attacker-controlled.
    if getattr(method, "name", None) == "main":
        for param in getattr(method, "parameters", None) or []:
            tainted.add(param.name)
            origin.setdefault(
                param.name, FlowStep(0, 0, f"source: command-line arg '{param.name}'")
            )

    assignments = _collect_assignments(method)

    # Variables safe to concatenate: numeric/boolean-typed values cannot carry
    # injection metacharacters, and values whose terminal call is a sanitizer
    # have been neutralised.
    sanitized: set[str] = {
        name for name, tname in types.items() if tname in NUMERIC_SAFE_CONCAT_TYPES
    }
    for target, rhs in assignments:
        if types.get(target) in NUMERIC_SAFE_CONCAT_TYPES or _is_sanitizing_expr(rhs):
            sanitized.add(target)

    # Fixed point: keep folding taint until the set stops growing. Bounded by
    # the number of assignments so it always terminates.
    for _ in range(len(assignments) + 1):
        changed = False
        for target, rhs in assignments:
            if target in tainted:
                continue
            if _expr_tainted(rhs, tainted, types):
                tainted.add(target)
                origin[target] = _origin_step(rhs, tainted, origin, types)
                changed = True
        if not changed:
            break

    return TaintResult(tainted=tainted, types=types, origin=origin, sanitized=sanitized)


def _collect_assignments(method) -> list[tuple[str, Node]]:
    pairs: list[tuple[str, Node]] = []
    for _, decl in method.filter(LocalVariableDeclaration):
        for declarator in decl.declarators:
            if declarator.initializer is not None:
                pairs.append((declarator.name, declarator.initializer))
    for _, assign in method.filter(Assignment):
        target = assign.expressionl
        if isinstance(target, MemberReference) and not target.qualifier:
            pairs.append((target.member, assign.value))
    return pairs


def _is_source(inv: MethodInvocation, types: dict[str, str]) -> bool:
    return any(sig.matches(inv, types) for sig in SOURCES if inv.member == sig.member)


def _source_label(inv: MethodInvocation) -> str:
    return f"source: {inv.qualifier + '.' if inv.qualifier else ''}{inv.member}"


def _expr_tainted(node: Node, tainted: set[str], types: dict[str, str]) -> bool:
    if node is None:
        return False
    if isinstance(node, Literal):
        return False
    if isinstance(node, MemberReference):
        base = node.member if not node.qualifier else node.qualifier.split(".")[0]
        return base in tainted or node.member in tainted
    if isinstance(node, Cast):
        return _expr_tainted(node.expression, tainted, types)
    if isinstance(node, TernaryExpression):
        # The result is one of the branches; taint if either can be tainted.
        return _expr_tainted(node.if_true, tainted, types) or _expr_tainted(
            node.if_false, tainted, types
        )
    if isinstance(node, BinaryOperation):
        return _expr_tainted(node.operandl, tainted, types) or _expr_tainted(
            node.operandr, tainted, types
        )
    if isinstance(node, MethodInvocation):
        member = node.member
        if member == "valueOf":
            # String.valueOf / Object.valueOf / Enum.valueOf preserve taint;
            # Integer/Long/... .valueOf parse into a numeric box (sanitising).
            if resolve_receiver_type(node, types) in NUMERIC_BOX_TYPES:
                return False
            if any(_expr_tainted(a, tainted, types) for a in (node.arguments or [])):
                return True
        elif member in SANITIZERS:
            return False
        elif _is_source(node, types):
            return True
        elif member in PASSTHROUGH_MEMBERS:
            qhead = node.qualifier.split(".")[0] if node.qualifier else ""
            if qhead in tainted:
                return True
            if any(_expr_tainted(a, tainted, types) for a in (node.arguments or [])):
                return True
        # Chained calls live in selectors: sb.append("x").append(t).toString().
        # Taint carried by any trailing call in the chain propagates.
        for sel in node.selectors or []:
            if isinstance(sel, Node) and _expr_tainted(sel, tainted, types):
                return True
        return False
    # Compound / other nodes (ClassCreator, etc.): taint if any child is tainted.
    for child in _child_expressions(node):
        if _expr_tainted(child, tainted, types):
            return True
    return False


def _is_sanitizing_expr(node: Node) -> bool:
    """True if the terminal (result-producing) call of an expression is a
    sanitizer, e.g. Integer.parseInt(x) or ESAPI.encoder().encodeForSQL(...)."""
    member = _terminal_member(node)
    return member in SANITIZERS if member else False


def _terminal_member(node: Node) -> str | None:
    if isinstance(node, (MethodInvocation, ClassCreator)):
        for sel in reversed(node.selectors or []):
            if isinstance(sel, MethodInvocation):
                return sel.member
        if isinstance(node, MethodInvocation):
            return node.member
    return None


def _concat_has_variable(node: Node, types: dict[str, str], sanitized: set[str]) -> bool:
    if not isinstance(node, BinaryOperation) or node.operator != "+":
        return False
    has_literal = False
    has_dangerous = False
    for part in _flatten_concat(node):
        if isinstance(part, Literal):
            has_literal = True
        elif _part_is_safe_to_concat(part, types, sanitized):
            continue
        else:
            has_dangerous = True
    return has_literal and has_dangerous


def _part_is_safe_to_concat(part: Node, types: dict[str, str], sanitized: set[str]) -> bool:
    if isinstance(part, MemberReference) and not part.qualifier:
        name = part.member
        return name in sanitized or types.get(name) in NUMERIC_SAFE_CONCAT_TYPES
    return False


def _flatten_concat(node: Node) -> list[Node]:
    if isinstance(node, BinaryOperation) and node.operator == "+":
        return _flatten_concat(node.operandl) + _flatten_concat(node.operandr)
    return [node]


def _referenced_names(node: Node) -> set[str]:
    names: set[str] = set()
    if node is None:
        return names
    if isinstance(node, MemberReference):
        names.add(node.member)
        if node.qualifier:
            names.add(node.qualifier.split(".")[0])
    for child in _child_expressions(node):
        names |= _referenced_names(child)
    if isinstance(node, MethodInvocation):
        qhead = node.qualifier.split(".")[0] if node.qualifier else ""
        if qhead:
            names.add(qhead)
    return names


def _child_expressions(node: Node):
    for attr in ("operandl", "operandr", "expression", "value", "qualifier",
                 "if_true", "if_false", "condition"):
        child = getattr(node, attr, None)
        if isinstance(child, Node):
            yield child
    for attr in ("arguments", "selectors"):
        seq = getattr(node, attr, None)
        if seq:
            for item in seq:
                if isinstance(item, Node):
                    yield item


def _origin_step(
    rhs: Node, tainted: set[str], origin: dict[str, FlowStep], types: dict[str, str]
) -> FlowStep:
    # Prefer a direct source invocation for a precise label.
    for _, inv in _walk_invocations(rhs):
        if _is_source(inv, types):
            line, col = node_position(inv)
            return FlowStep(line, col, _source_label(inv))
    # Otherwise inherit the origin of a referenced tainted variable.
    for name in _referenced_names(rhs):
        if name in origin:
            return origin[name]
    line, col = node_position(rhs) if isinstance(rhs, Node) else (0, 0)
    return FlowStep(line, col, "propagated taint")


def _walk_invocations(node: Node):
    if isinstance(node, MethodInvocation):
        yield None, node
    for child in _child_expressions(node):
        yield from _walk_invocations(child)
