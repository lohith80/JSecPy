"""Injection family: taint-driven detectors where a dangerous call is only a
finding when attacker-controlled (or dynamically concatenated) data reaches it.
"""

from __future__ import annotations

from ..model import Confidence, Severity
from ..sources_sinks import Signature
from . import register
from .base import TaintSinkRule


@register
class SqlInjection(TaintSinkRule):
    id = "JSEC-SQLI"
    name = "SQL Injection"
    severity = Severity.CRITICAL
    confidence = Confidence.HIGH
    cwe = ["CWE-89"]
    owasp = "A03:2021-Injection"
    remediation = (
        "Use PreparedStatement with parameterized queries (bind '?' placeholders "
        "and setString/setInt), never string concatenation. For dynamic table or "
        "column names, validate against an allowlist."
    )
    references = ["https://owasp.org/www-community/attacks/SQL_Injection"]
    SINKS = (
        Signature(member="executeQuery", receiver_types=frozenset({"Statement", "Connection"})),
        Signature(member="executeUpdate", receiver_types=frozenset({"Statement", "Connection"})),
        Signature(member="execute", receiver_types=frozenset({"Statement"})),
        Signature(member="executeLargeUpdate", receiver_types=frozenset({"Statement"})),
        Signature(member="addBatch", receiver_types=frozenset({"Statement"})),
        Signature(member="prepareStatement", receiver_types=frozenset({"Connection"})),
        Signature(member="prepareCall", receiver_types=frozenset({"Connection"})),
        # Hibernate / JPA
        Signature(member="createQuery", receiver_types=frozenset({"Session", "EntityManager"})),
        Signature(member="createNativeQuery", receiver_types=frozenset({"EntityManager"})),
        Signature(member="createSQLQuery", receiver_types=frozenset({"Session"})),
    )
    TAINTED_ARG_INDICES = (0,)


@register
class CommandInjection(TaintSinkRule):
    id = "JSEC-CMDI"
    name = "OS Command Injection"
    severity = Severity.CRITICAL
    confidence = Confidence.HIGH
    cwe = ["CWE-78"]
    owasp = "A03:2021-Injection"
    remediation = (
        "Avoid the shell. Pass a fixed program and an argument array to "
        "ProcessBuilder, never a concatenated command line. Validate arguments "
        "against a strict allowlist."
    )
    references = ["https://owasp.org/www-community/attacks/Command_Injection"]
    SINKS = (
        Signature(member="exec", receiver_types=frozenset({"Runtime"})),
        Signature(member="command", receiver_types=frozenset({"ProcessBuilder"})),
        Signature(member="start", receiver_types=frozenset({"ProcessBuilder"}),
                  match_unknown_receiver=False),
    )
    TAINTED_ARG_INDICES = None  # any argument


@register
class PathTraversal(TaintSinkRule):
    id = "JSEC-PATH"
    name = "Path Traversal"
    severity = Severity.HIGH
    confidence = Confidence.HIGH
    cwe = ["CWE-22"]
    owasp = "A01:2021-Broken Access Control"
    remediation = (
        "Resolve the requested path, then verify getCanonicalPath() is still "
        "inside the intended base directory before opening. Reject inputs "
        "containing path separators or '..'."
    )
    references = ["https://owasp.org/www-community/attacks/Path_Traversal"]
    SINKS = (
        Signature(member="<init>", receiver_types=frozenset({"File", "FileInputStream",
                                                              "FileOutputStream", "FileReader",
                                                              "FileWriter", "RandomAccessFile"}),
                  match_unknown_receiver=False),
        Signature(member="get", receiver_types=frozenset({"Paths"})),
        Signature(member="newInputStream", receiver_types=frozenset({"Files"})),
        Signature(member="newOutputStream", receiver_types=frozenset({"Files"})),
        Signature(member="readAllBytes", receiver_types=frozenset({"Files"})),
        Signature(member="readString", receiver_types=frozenset({"Files"})),
        Signature(member="copy", receiver_types=frozenset({"Files"})),
    )
    TAINTED_ARG_INDICES = None
    FLAG_CONCAT = False  # file paths are often concatenated legitimately; require taint


@register
class LdapInjection(TaintSinkRule):
    id = "JSEC-LDAP"
    name = "LDAP Injection"
    severity = Severity.HIGH
    confidence = Confidence.HIGH
    cwe = ["CWE-90"]
    owasp = "A03:2021-Injection"
    remediation = (
        "Escape LDAP search filter metacharacters (use a vetted encoder such as "
        "OWASP ESAPI encodeForLDAP) or use parameterized filter templates."
    )
    references = ["https://owasp.org/www-community/attacks/LDAP_Injection"]
    SINKS = (
        Signature(member="search", receiver_types=frozenset({"DirContext", "InitialDirContext",
                                                              "LdapContext"})),
    )
    TAINTED_ARG_INDICES = None


@register
class XPathInjection(TaintSinkRule):
    id = "JSEC-XPATH"
    name = "XPath Injection"
    severity = Severity.HIGH
    confidence = Confidence.HIGH
    cwe = ["CWE-643"]
    owasp = "A03:2021-Injection"
    remediation = (
        "Use XPath variable binding (XPathVariableResolver) instead of "
        "concatenating user input into the expression string."
    )
    references = ["https://owasp.org/www-community/attacks/XPATH_Injection"]
    SINKS = (
        Signature(member="compile", receiver_types=frozenset({"XPath"})),
        Signature(member="evaluate", receiver_types=frozenset({"XPath", "XPathExpression"})),
    )
    TAINTED_ARG_INDICES = (0,)


@register
class OpenRedirect(TaintSinkRule):
    id = "JSEC-REDIR"
    name = "Open Redirect"
    severity = Severity.MEDIUM
    confidence = Confidence.MEDIUM
    cwe = ["CWE-601"]
    owasp = "A01:2021-Broken Access Control"
    remediation = (
        "Do not send a redirect to a user-supplied URL. Map the input to a fixed "
        "set of allowed destinations, or verify the target is a relative path on "
        "an allowlisted host."
    )
    references = ["https://owasp.org/www-community/attacks/Unvalidated_Redirects_and_Forwards"]
    SINKS = (
        Signature(member="sendRedirect", receiver_types=frozenset({"HttpServletResponse",
                                                                    "ServletResponse"})),
    )
    TAINTED_ARG_INDICES = (0,)
    FLAG_CONCAT = False
