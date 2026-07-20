# Security Policy

## Supported Versions

| Version | Supported |
|---------|-----------|
| 2.0.x   | Yes       |
| < 2.0   | No (legacy keyword scanner) |

## Reporting a Vulnerability

Report vulnerabilities in JSecPy itself privately via **GitHub Security
Advisories** (Security tab -> "Report a vulnerability") or by email to
**indulohithnarisetty@gmail.com** with subject `[jsecpy security]`.

- Acknowledgment within 72 hours; target fix within 90 days.
- Please do not open public issues for security reports.

## Detection gaps vs. tool vulnerabilities

- A payload JSecPy **fails to detect**, or safe code it **wrongly flags**, is a
  *detection-gap report* - open a normal public issue with the Java snippet.
  These are the most useful contributions and are welcome.
- A vulnerability in the **scanner itself** (a crafted file that crashes it,
  causes code execution during analysis, or leaks secrets into output) is a
  security report and belongs in the private channel above.
