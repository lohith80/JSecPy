"""Catalogs of taint sources, sanitizers, and propagators.

A Signature matches a method invocation by member name and, optionally, by the
declared type of its receiver. Requiring a receiver type is what keeps
``request.getParameter`` (a real source) from matching some unrelated
``config.getParameter`` (not a source).
"""

from __future__ import annotations

from dataclasses import dataclass, field

from javalang.tree import MethodInvocation


@dataclass(frozen=True)
class Signature:
    member: str
    receiver_types: frozenset[str] = field(default_factory=frozenset)
    # When True, match even if the receiver type cannot be resolved. Use for
    # highly distinctive member names (e.g. executeQuery) that are unambiguous.
    match_unknown_receiver: bool = True

    def matches(self, inv: MethodInvocation, types: dict[str, str]) -> bool:
        if inv.member != self.member:
            return False
        if not self.receiver_types:
            return True
        receiver = resolve_receiver_type(inv, types)
        if receiver is None:
            return self.match_unknown_receiver
        return receiver in self.receiver_types


def resolve_receiver_type(inv: MethodInvocation, types: dict[str, str]) -> str | None:
    """Best-effort receiver type of ``qualifier.member(...)``.

    Resolution order (declared type wins over the heuristic, so a local named
    like a type is never mistaken for a static call):

    - qualifier is a known local/param variable -> its declared type
    - ``this.x`` / ``super.x`` -> the declared type of field/var ``x`` if known
    - qualifier looks like a Type (starts uppercase) -> a static call on it
    - otherwise unknown (None)
    """
    qualifier = inv.qualifier
    if not qualifier:
        return None
    segments = qualifier.split(".")
    head = segments[0]
    # Peel a leading this./super. and resolve the next segment instead.
    if head in ("this", "super") and len(segments) > 1:
        head = segments[1]
    if head in types:
        return types[head]
    if head[:1].isupper():
        return head
    return None


# Servlet/HTTP request types whose accessors return attacker-controlled data.
REQUEST_TYPES = frozenset(
    {"HttpServletRequest", "ServletRequest", "HttpServletRequestWrapper", "WebRequest", "Request"}
)

# Members on a request object that yield tainted strings/streams.
_REQUEST_SOURCE_MEMBERS = frozenset(
    {
        "getParameter",
        "getParameterValues",
        "getParameterMap",
        "getParameterNames",
        "getHeader",
        "getHeaders",
        "getHeaderNames",
        "getQueryString",
        "getRequestURI",
        "getRequestURL",
        "getPathInfo",
        "getPathTranslated",
        "getCookies",
        "getInputStream",
        "getReader",
        "getRemoteUser",
        "getRemoteAddr",
        "getRemoteHost",
    }
)

SOURCES: tuple[Signature, ...] = tuple(
    Signature(member=m, receiver_types=REQUEST_TYPES) for m in _REQUEST_SOURCE_MEMBERS
) + (
    # stdin / stream readers
    Signature(member="readLine", receiver_types=frozenset({"BufferedReader", "Console"})),
    Signature(member="nextLine", receiver_types=frozenset({"Scanner"})),
    Signature(member="next", receiver_types=frozenset({"Scanner"})),
    # environment/config: attacker-influenced in many deployments (lower trust)
    Signature(member="getenv", receiver_types=frozenset({"System"})),
    Signature(member="getProperty", receiver_types=frozenset({"System"})),
)

# Boxed numeric/boolean wrapper types. Type.valueOf(...) on one of these parses
# into a number/boolean and neutralises taint; String/Object/Enum.valueOf do not
# (they preserve the taint of their argument) and are handled as pass-throughs.
NUMERIC_BOX_TYPES: frozenset[str] = frozenset(
    {
        "Integer", "Long", "Double", "Float", "Boolean",
        "Short", "Byte", "Character", "BigInteger", "BigDecimal",
    }
)

# Declared types whose values cannot carry injection metacharacters, so
# concatenating them into a query/command/path is safe (suppresses the
# "built with +" concat smell). Deliberately excludes char/Character: a single
# attacker-chosen character can still be a quote or separator.
NUMERIC_SAFE_CONCAT_TYPES: frozenset[str] = frozenset(
    {
        "int", "long", "short", "byte", "double", "float", "boolean",
        "Integer", "Long", "Short", "Byte", "Double", "Float", "Boolean",
        "BigInteger", "BigDecimal",
    }
)

# Calls that neutralise taint of their result (return value is considered safe).
# NOTE: ``valueOf`` is intentionally NOT here; it is receiver-aware in taint.py
# (only numeric/boolean boxes sanitise; String.valueOf preserves taint).
SANITIZERS: frozenset[str] = frozenset(
    {
        "parseInt",
        "parseLong",
        "parseDouble",
        "parseFloat",
        "parseBoolean",
        "encodeForHTML",
        "encodeForSQL",
        "encodeForOS",
        "encodeForLDAP",
        "encodeForXPath",
        "escapeHtml",
        "escapeHtml4",
        "escapeSql",
        "escapeJava",
        "stripToNull",
        "getCanonicalPath",  # for path traversal, canonicalisation is a partial sanitizer
    }
)

# Members that pass taint through from receiver/args to their result. Kept
# conservative: string transforms and builders, not arbitrary methods.
PASSTHROUGH_MEMBERS: frozenset[str] = frozenset(
    {
        "trim",
        "toString",
        "toLowerCase",
        "toUpperCase",
        "substring",
        "replace",
        "replaceAll",
        "concat",
        "append",
        "insert",
        "format",
        "join",
        "strip",
        "intern",
        "getBytes",
        "toCharArray",
        "readLine",
        "nextLine",
    }
)
