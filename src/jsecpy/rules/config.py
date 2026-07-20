"""Dangerous configuration: XXE-prone parsers, unsafe deserialization,
disabled TLS validation, and insecure cookies. All AST-based, taint-independent.
"""

from __future__ import annotations

from javalang.tree import ClassCreator, Literal, MethodInvocation

from ..java_ast import ParsedUnit
from ..model import Confidence, Finding, Severity
from . import register
from .base import Rule, TaintCache

_XXE_FACTORIES = {
    "DocumentBuilderFactory",
    "SAXParserFactory",
    "XMLInputFactory",
    "TransformerFactory",
    "SchemaFactory",
    "XMLReaderFactory",
}


@register
class Xxe(Rule):
    id = "JSEC-XXE"
    name = "XML External Entity (XXE) Exposure"
    severity = Severity.HIGH
    confidence = Confidence.MEDIUM
    cwe = ["CWE-611"]
    owasp = "A05:2021-Security Misconfiguration"
    remediation = (
        "Harden the parser factory before use: "
        "setFeature(\"http://apache.org/xml/features/disallow-doctype-decl\", true) "
        "or disable external general/parameter entities. XXE lets an attacker read "
        "local files and reach internal services."
    )
    references = ["https://cheatsheetseries.owasp.org/cheatsheets/XML_External_Entity_Prevention_Cheat_Sheet.html"]

    def analyze(self, unit: ParsedUnit, taint: TaintCache) -> list[Finding]:
        creates_factory = False
        hardened = False
        anchor = None
        for _, inv in unit.tree.filter(MethodInvocation):
            if inv.member == "newInstance" and inv.qualifier in _XXE_FACTORIES:
                creates_factory = True
                anchor = anchor or inv
            if inv.member in {"setFeature", "setAttribute", "setExpandEntityReferences",
                              "setProperty"}:
                # Any explicit hardening call suppresses the finding (best-effort).
                hardened = True
        if creates_factory and not hardened and anchor is not None:
            return [self.make_finding(
                unit, anchor,
                "XML parser factory created without disabling DOCTYPE/external entities."
            )]
        return []


@register
class UnsafeDeserialization(Rule):
    id = "JSEC-DESER"
    name = "Unsafe Deserialization"
    severity = Severity.CRITICAL
    confidence = Confidence.MEDIUM
    cwe = ["CWE-502"]
    owasp = "A08:2021-Software and Data Integrity Failures"
    remediation = (
        "Do not deserialize untrusted data with ObjectInputStream. Prefer a data "
        "format without code-execution gadgets (JSON/protobuf) with a strict "
        "schema, or install an ObjectInputFilter allowlist."
    )
    references = ["https://cheatsheetseries.owasp.org/cheatsheets/Deserialization_Cheat_Sheet.html"]

    def analyze(self, unit: ParsedUnit, taint: TaintCache) -> list[Finding]:
        findings = []
        for _, creator in unit.tree.filter(ClassCreator):
            if getattr(creator.type, "name", "") == "ObjectInputStream":
                findings.append(self.make_finding(
                    unit, creator,
                    "ObjectInputStream deserializes data that may be attacker-controlled."
                ))
        return findings


@register
class TrustAllTls(Rule):
    id = "JSEC-TLS"
    name = "Disabled TLS Certificate Validation"
    severity = Severity.HIGH
    confidence = Confidence.MEDIUM
    cwe = ["CWE-295"]
    owasp = "A07:2021-Identification and Authentication Failures"
    remediation = (
        "Never trust all certificates or hostnames. Use the default trust store; "
        "for pinning, validate the certificate chain explicitly. A permissive "
        "TrustManager or HostnameVerifier defeats TLS entirely."
    )
    references = ["https://cwe.mitre.org/data/definitions/295.html"]

    def analyze(self, unit: ParsedUnit, taint: TaintCache) -> list[Finding]:
        findings = []
        # HostnameVerifier that returns true unconditionally.
        for _, verifier in unit.tree.filter(MethodInvocation):
            if verifier.member == "setDefaultHostnameVerifier":
                findings.append(self.make_finding(
                    unit, verifier,
                    "Custom HostnameVerifier installed; ensure it is not a trust-all verifier."
                ))
        # A 'return true;' inside a verify(...) method, or an empty
        # checkServerTrusted, is the classic trust-all pattern.
        from javalang.tree import MethodDeclaration, ReturnStatement
        for _, method in unit.tree.filter(MethodDeclaration):
            if method.name == "verify" and _returns_constant_true(method):
                findings.append(self.make_finding(
                    unit, method,
                    "HostnameVerifier.verify() unconditionally returns true (accepts any host)."
                ))
            if method.name in {"checkServerTrusted", "checkClientTrusted"} and _is_empty(method):
                findings.append(self.make_finding(
                    unit, method,
                    f"{method.name}() is empty; the TrustManager accepts any certificate.",
                    severity=Severity.HIGH,
                ))
        return findings


@register
class InsecureCookie(Rule):
    id = "JSEC-COOKIE"
    name = "Insecure Cookie Flags"
    severity = Severity.MEDIUM
    confidence = Confidence.MEDIUM
    cwe = ["CWE-614", "CWE-1004"]
    owasp = "A05:2021-Security Misconfiguration"
    remediation = (
        "Set cookie.setSecure(true) and cookie.setHttpOnly(true) on session and "
        "auth cookies so they are not sent over plaintext or readable from JS."
    )
    references = ["https://owasp.org/www-community/controls/SecureCookieAttribute"]

    def analyze(self, unit: ParsedUnit, taint: TaintCache) -> list[Finding]:
        findings = []
        # Explicit setSecure(false) / setHttpOnly(false) are the clear bugs.
        for _, inv in unit.tree.filter(MethodInvocation):
            if inv.member in {"setSecure", "setHttpOnly"} and inv.arguments:
                arg = inv.arguments[0]
                if isinstance(arg, Literal) and arg.value == "false":
                    flag = "Secure" if inv.member == "setSecure" else "HttpOnly"
                    findings.append(self.make_finding(
                        unit, inv, f"Cookie {flag} flag explicitly disabled ({inv.member}(false))."
                    ))
        return findings


def _returns_constant_true(method) -> bool:
    from javalang.tree import ReturnStatement
    for _, ret in method.filter(ReturnStatement):
        if isinstance(ret.expression, Literal) and ret.expression.value == "true":
            return True
    return False


def _is_empty(method) -> bool:
    body = getattr(method, "body", None)
    return body is not None and len(body) == 0
