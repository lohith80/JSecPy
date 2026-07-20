"""Thin helpers over javalang: parse a unit and resolve local symbol types.

javalang gives us position info on many nodes as a ``(line, column)`` tuple.
Not every node carries a position, so ``node_position`` degrades gracefully.
"""

from __future__ import annotations

from dataclasses import dataclass, field

import javalang
from javalang.tree import (
    CompilationUnit,
    FormalParameter,
    LocalVariableDeclaration,
    MethodDeclaration,
    Node,
)


class JavaParseError(Exception):
    pass


@dataclass
class ParsedUnit:
    path: str
    code: str
    tree: CompilationUnit
    lines: list[str] = field(default_factory=list)

    def line_text(self, line: int) -> str:
        if 1 <= line <= len(self.lines):
            return self.lines[line - 1].strip()
        return ""


def parse_unit(path: str, code: str) -> ParsedUnit:
    try:
        tree = javalang.parse.parse(code)
    except (javalang.parser.JavaSyntaxError, javalang.tokenizer.LexerError, Exception) as exc:
        raise JavaParseError(f"{path}: {exc}") from exc
    return ParsedUnit(path=path, code=code, tree=tree, lines=code.splitlines())


def node_position(node: Node) -> tuple[int, int]:
    pos = getattr(node, "position", None)
    if pos is not None:
        return (pos.line, pos.column)
    # Some nodes (notably ClassCreator) carry no position. Fall back to the
    # first descendant that does, so a finding never reports line 0.
    if isinstance(node, Node):
        for child in node.children:
            found = _first_child_position(child)
            if found != (0, 0):
                return found
    return (0, 0)


def _first_child_position(child) -> tuple[int, int]:
    if isinstance(child, Node):
        return node_position(child)
    if isinstance(child, (list, tuple, set)):
        for item in child:
            found = _first_child_position(item)
            if found != (0, 0):
                return found
    return (0, 0)


def local_types(method: MethodDeclaration) -> dict[str, str]:
    """Map local variable / parameter names to their declared type name.

    This is the single most important false-positive reducer: it lets a sink
    rule require that ``x.executeQuery(...)`` is called on a java.sql.Statement,
    not on some unrelated object that happens to expose an executeQuery method.
    """
    types: dict[str, str] = {}

    for param in getattr(method, "parameters", None) or []:
        if isinstance(param, FormalParameter):
            types[param.name] = _type_name(param.type)

    for _, decl in method.filter(LocalVariableDeclaration):
        type_name = _type_name(decl.type)
        for declarator in decl.declarators:
            types[declarator.name] = type_name

    return types


def _type_name(type_node) -> str:
    name = getattr(type_node, "name", None)
    if name:
        return name
    return type_node.__class__.__name__ if type_node is not None else ""


def iter_methods(tree: CompilationUnit):
    """Yield every method and constructor body in the unit."""
    from javalang.tree import ConstructorDeclaration

    for _, node in tree.filter(MethodDeclaration):
        yield node
    for _, node in tree.filter(ConstructorDeclaration):
        yield node
