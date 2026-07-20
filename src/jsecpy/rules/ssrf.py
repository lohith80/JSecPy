"""Server-Side Request Forgery: attacker-controlled data used to open a URL."""

from __future__ import annotations

from ..model import Confidence, Severity
from ..sources_sinks import Signature
from . import register
from .base import TaintSinkRule


@register
class Ssrf(TaintSinkRule):
    id = "JSEC-SSRF"
    name = "Server-Side Request Forgery"
    severity = Severity.HIGH
    confidence = Confidence.HIGH
    cwe = ["CWE-918"]
    owasp = "A10:2021-Server-Side Request Forgery"
    remediation = (
        "Do not fetch a user-supplied URL directly. Resolve and validate the "
        "host against an allowlist, reject internal/link-local ranges, and "
        "disable following redirects."
    )
    references = ["https://owasp.org/www-community/attacks/Server_Side_Request_Forgery"]
    SINKS = (
        Signature(member="<init>", receiver_types=frozenset({"URL"}), match_unknown_receiver=False),
        Signature(member="openConnection", receiver_types=frozenset({"URL"})),
        Signature(member="openStream", receiver_types=frozenset({"URL"})),
        # Spring / Apache HttpClient style clients
        Signature(member="getForObject", receiver_types=frozenset({"RestTemplate"})),
        Signature(member="getForEntity", receiver_types=frozenset({"RestTemplate"})),
        Signature(member="exchange", receiver_types=frozenset({"RestTemplate"})),
        Signature(member="execute", receiver_types=frozenset({"HttpClient"})),
    )
    TAINTED_ARG_INDICES = None
    FLAG_CONCAT = False
