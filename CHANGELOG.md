# Changelog

Format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/);
versioning is [SemVer](https://semver.org/).

## [2.1.0] - 2026-07-19

Taint-engine hardening driven by an adversarial red-team pass (43 generated
Java cases plus an engine-correctness review). Net effect on the corpus: 0
missed detections and 0 false positives, with the remaining limitations
encoded as visible `xfail` tests.

### Added
- **Adversarial corpus** (`tests/test_redteam_corpus.py`, 43 cases): true
  positives that must fire, safe code that must stay silent, and documented
  intra-procedural gaps tracked as `xfail` (strict). Test count 32 -> 72.

### Fixed
- **Taint through chained builder/string calls** (false negative): taint
  carried by a trailing selector call such as
  `sb.append("...").append(source).toString()` is now propagated. `_expr_tainted`
  previously returned before inspecting `selectors`.
- **Receiver-aware source matching** (false positive): the declared local/param
  type map is now threaded into source detection, so `config.getParameter(...)`
  or `props.getProperty(...)` are no longer mistaken for
  `request.getParameter` / `System.getProperty` sources.
- **`String.valueOf` no longer treated as a sanitizer** (false negative):
  `valueOf` is receiver-aware; only numeric/boolean box types
  (`Integer.valueOf`, ...) neutralise taint, while `String.valueOf` preserves it.
- **Ternary data flow** (false negative): `x = cond ? tainted : safe` now taints
  `x`.
- **Concat smell precision** (false positives): the "built a query with +"
  heuristic no longer fires when every dynamic operand is numeric-typed or the
  result of a sanitizer (e.g. `"... " + Integer.parseInt(p)` or an
  ESAPI-encoded value).
- **Inline-source flow traces**: a sink whose argument is a source call with no
  intervening variable (e.g. `executeQuery(req.getParameter("q"))`) now reports
  the source end of the data-flow trace, not just the sink.
- **`this.`/`super.` receiver resolution** in `resolve_receiver_type`.

## [2.0.0] - 2026-07-19

A ground-up rewrite. v1 was a line-by-line keyword matcher that flagged any
line mentioning a sensitive class name. v2 is a real SAST engine.

### Added
- **AST-based analysis** using `javalang` instead of line regex.
- **Intra-procedural taint analysis**: tracks attacker-controlled data from
  sources (servlet request accessors, stdin, CLI args, env) to sinks through
  assignments, string concatenation, and pass-through string operations, with
  sanitizer awareness.
- **14 built-in rules** mapped to CWE and OWASP Top 10 (2021): SQL/command/LDAP/
  XPath injection, path traversal, SSRF, open redirect, weak hash/cipher,
  insecure randomness, XXE, unsafe deserialization, disabled TLS validation,
  insecure cookies, hardcoded secrets.
- **HIGH/MEDIUM confidence** distinction (proven taint vs. dynamic concatenation).
- **Explainable findings** with source-to-sink flow steps.
- **SARIF 2.1.0 output** with `security-severity` and code flows for GitHub code
  scanning; plus JSON and coloured CLI reporters.
- **YAML rule engine** (`JSEC-Y-*`) for custom sinks with no code, and a Python
  rule API (`@register`) for structural checks.
- **CI ergonomics**: severity thresholds, `--fail-on` exit codes, baselines,
  inline `// jsecpy:ignore` suppression, `.jsecpy.yml` config, glob excludes.
- **Packaging**: `jsecpy` console entry point, GitHub Action, Dockerfile,
  CI matrix (Python 3.10-3.12), self-scan dogfood job, threat model, rule docs.
- Test suite with vulnerable **and** safe fixtures (the false-positive contract).

### Changed
- Package renamed to `jsecpy` with a `src/` layout; the tool is now
  `pip install`-able and invoked as `jsecpy` rather than `python jsecpy.py`.

### Removed
- The v1 keyword-regex engine and its per-line class-name patterns.
