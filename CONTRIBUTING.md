# Contributing to JSecPy

Thanks for helping make JSecPy a sharper scanner. The most valuable
contribution is a **detection gap**: a Java snippet JSecPy misses, or safe
code it wrongly flags.

## Report a detection gap

Open an issue with:

1. A minimal Java snippet (the smaller the better).
2. What you expected: a rule to fire (`detect`) or stay silent (`clean`).
3. Which rule (`JSEC-SQLI`, `JSEC-CMDI`, ...) and why.

No working exploit needed, just the source that fools the analysis. Confirmed
gaps get added to the versioned corpus in `tests/`, and contributors are
credited in the changelog.

## Add or fix a rule

1. Fork, branch, `pip install -e ".[dev]"`.
2. Rules live in `src/jsecpy/rules/`. Injection-family rules subclass
   `TaintSinkRule` (declare `SINKS` + tainted arg indices); config/crypto
   rules subclass `Rule`. See `docs/WRITING_RULES.md`.
3. **Every rule change needs both a vulnerable and a safe fixture** in
   `tests/fixtures/` — the safe fixture is the anti-false-positive contract.
4. `ruff check src tests` and `pytest` must pass. The adversarial corpus
   (`tests/test_redteam_corpus.py`) enforces zero false negatives and zero
   false positives.

## Custom sinks without code

Team-specific sinks (an in-house DAO, a custom HTTP client) don't need a code
change — use the YAML rule engine (`JSEC-Y-*`). See `docs/WRITING_RULES.md`.

## Scope

Detection gaps in the rules are public — open a regular issue. A vulnerability
in the scanner *itself* (a crash, an unsafe dependency, code execution during
analysis) is a security report: follow [SECURITY.md](SECURITY.md).

## Honesty rule

JSecPy is intra-procedural by design. Don't paper over a documented limitation
(cross-method flow, taint through maps) with a hack that spikes false
positives. A visible `xfail` beats a noisy pass. See
[docs/THREAT_MODEL.md](docs/THREAT_MODEL.md).
