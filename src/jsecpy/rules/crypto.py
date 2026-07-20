"""Cryptography and randomness weaknesses.

These are bugs by construction, independent of taint: a weak hash is weak no
matter where its input comes from. Detection is AST-based on the arguments to
the relevant factory methods.
"""

from __future__ import annotations

from javalang.tree import Literal, MethodInvocation

from ..java_ast import ParsedUnit, node_position
from ..model import Confidence, Finding, Severity
from . import register
from .base import Rule, TaintCache

_WEAK_HASHES = {"MD2", "MD4", "MD5", "SHA-1", "SHA1"}
_WEAK_CIPHERS = {"DES", "DESede", "3DES", "RC2", "RC4", "ARCFOUR", "Blowfish"}


def _literal_value(node) -> str | None:
    if isinstance(node, Literal) and isinstance(node.value, str):
        return node.value.strip('"')
    return None


@register
class WeakHash(Rule):
    id = "JSEC-HASH"
    name = "Weak Hashing Algorithm"
    severity = Severity.MEDIUM
    confidence = Confidence.HIGH
    cwe = ["CWE-328", "CWE-327"]
    owasp = "A02:2021-Cryptographic Failures"
    remediation = (
        "Use SHA-256 or SHA-3 for integrity, and a memory-hard password hash "
        "(bcrypt, scrypt, or Argon2) for credentials. MD5 and SHA-1 are broken."
    )
    references = ["https://owasp.org/Top10/A02_2021-Cryptographic_Failures/"]

    def analyze(self, unit: ParsedUnit, taint: TaintCache) -> list[Finding]:
        findings = []
        for _, inv in unit.tree.filter(MethodInvocation):
            if inv.member == "getInstance" and inv.arguments:
                algo = _literal_value(inv.arguments[0])
                if algo and algo.upper().replace("_", "-") in {h.upper() for h in _WEAK_HASHES}:
                    findings.append(
                        self.make_finding(unit, inv, f"Weak hash algorithm '{algo}' requested.")
                    )
        return findings


@register
class WeakCipher(Rule):
    id = "JSEC-CIPHER"
    name = "Weak or Insecure Cipher"
    severity = Severity.HIGH
    confidence = Confidence.HIGH
    cwe = ["CWE-327"]
    owasp = "A02:2021-Cryptographic Failures"
    remediation = (
        "Use AES in an authenticated mode (AES/GCM/NoPadding). Avoid DES/3DES/RC4, "
        "ECB mode (leaks plaintext structure), and never hardcode IVs."
    )
    references = ["https://owasp.org/Top10/A02_2021-Cryptographic_Failures/"]

    def analyze(self, unit: ParsedUnit, taint: TaintCache) -> list[Finding]:
        findings = []
        for _, inv in unit.tree.filter(MethodInvocation):
            if inv.member != "getInstance" or not inv.arguments:
                continue
            spec = _literal_value(inv.arguments[0])
            if spec is None:
                continue
            transformation = spec.upper()
            algo = transformation.split("/")[0]
            if algo in {c.upper() for c in _WEAK_CIPHERS}:
                findings.append(
                    self.make_finding(unit, inv, f"Weak cipher '{spec}' requested.")
                )
            elif "/ECB/" in transformation or transformation.endswith("/ECB"):
                findings.append(
                    self.make_finding(
                        unit, inv, f"ECB mode cipher '{spec}' leaks plaintext patterns.",
                        severity=Severity.MEDIUM,
                    )
                )


        return findings


@register
class InsecureRandom(Rule):
    id = "JSEC-RANDOM"
    name = "Insecure Randomness"
    severity = Severity.MEDIUM
    confidence = Confidence.MEDIUM
    cwe = ["CWE-330", "CWE-338"]
    owasp = "A02:2021-Cryptographic Failures"
    remediation = (
        "For security-sensitive values (tokens, keys, IVs, password reset codes) "
        "use java.security.SecureRandom, not java.util.Random or Math.random()."
    )
    references = ["https://cwe.mitre.org/data/definitions/330.html"]

    def analyze(self, unit: ParsedUnit, taint: TaintCache) -> list[Finding]:
        from javalang.tree import ClassCreator

        findings = []
        for _, creator in unit.tree.filter(ClassCreator):
            if getattr(creator.type, "name", "") == "Random":
                findings.append(
                    self.make_finding(
                        unit, creator, "java.util.Random is predictable; use SecureRandom."
                    )
                )
        for _, inv in unit.tree.filter(MethodInvocation):
            if inv.member == "random" and inv.qualifier == "Math":
                findings.append(
                    self.make_finding(
                        unit, inv, "Math.random() is not cryptographically secure."
                    )
                )
        return findings
