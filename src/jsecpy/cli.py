"""Command-line interface.

Exit codes (CI-friendly):
    0  no findings at or above --fail-on
    1  findings at or above --fail-on were reported
    2  usage / configuration error
"""

from __future__ import annotations

import argparse
import sys
from pathlib import Path

from . import __version__
from .config import Config
from .engine import Engine, write_baseline
from .model import Severity
from .reporters import render_cli, render_json, render_sarif
from .rules import load_builtin_rules

BANNER = r"""
     ██ ███████ ███████  ██████ ██████  ██    ██
     ██ ██      ██      ██      ██   ██  ██  ██
     ██ ███████ █████   ██      ██████    ████
██   ██      ██ ██      ██      ██         ██
 █████  ███████ ███████  ██████ ██         ██
        Java SAST - AST + taint analysis  v{version}
""".strip("\n")


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="jsecpy",
        description="Static application security testing for Java: AST + taint "
        "analysis mapped to CWE and the OWASP Top 10, with SARIF output.",
    )
    p.add_argument("paths", nargs="*", help="Java files or directories to scan.")
    p.add_argument("-f", "--format", choices=("cli", "json", "sarif"), default="cli",
                   help="Output format (default: cli).")
    p.add_argument("-o", "--output", help="Write output to a file instead of stdout.")
    p.add_argument("--min-severity", default=None,
                   help="Report findings at or above this severity "
                   "(INFO|LOW|MEDIUM|HIGH|CRITICAL).")
    p.add_argument("--fail-on", default=None,
                   help="Exit non-zero if any finding is at or above this severity "
                   "(default HIGH).")
    p.add_argument("--config", help="Path to a .jsecpy.yml config file.")
    p.add_argument("--disable", default="", help="Comma-separated rule IDs to disable.")
    p.add_argument("--enable", default="", help="Comma-separated rule IDs to enable exclusively.")
    p.add_argument("--rules", action="append", default=[],
                   help="Path to a YAML rule file or directory (repeatable).")
    p.add_argument("--baseline", help="Baseline JSON file; matching findings are ignored.")
    p.add_argument("--write-baseline", help="Write current findings to a baseline file and exit.")
    p.add_argument("--scan-tests", action="store_true", help="Include test files in the scan.")
    p.add_argument("--no-color", action="store_true", help="Disable ANSI colour.")
    p.add_argument("--no-banner", action="store_true", help="Suppress the banner.")
    p.add_argument("--list-rules", action="store_true", help="List built-in rules and exit.")
    p.add_argument("--version", action="version", version=f"JSecPy {__version__}")
    return p


def _build_config(args) -> Config:
    config = Config.from_file(Path(args.config)) if args.config else Config()
    if args.min_severity:
        config.min_severity = Severity.parse(args.min_severity)
    if args.fail_on:
        config.fail_on = Severity.parse(args.fail_on)
    if args.disable:
        config.disabled_rules = frozenset(x.strip() for x in args.disable.split(",") if x.strip())
    if args.enable:
        config.enabled_rules = frozenset(x.strip() for x in args.enable.split(",") if x.strip())
    if args.rules:
        config.yaml_rule_paths = tuple(Path(r) for r in args.rules)
    if args.baseline:
        config.baseline_path = Path(args.baseline)
    if args.scan_tests:
        config.scan_tests = True
    return config


def _list_rules() -> int:
    rows = sorted(load_builtin_rules(), key=lambda r: r.id)
    print(f"{'RULE ID':<16} {'SEVERITY':<9} {'CWE':<20} NAME")
    for r in rows:
        cwe = ",".join(r.cwe) if r.cwe else "-"
        print(f"{r.id:<16} {str(r.severity):<9} {cwe:<20} {r.name}")
    return 0


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)

    if args.list_rules:
        return _list_rules()

    if not args.paths:
        print("error: no paths given. See --help.", file=sys.stderr)
        return 2

    try:
        config = _build_config(args)
    except (KeyError, ValueError) as exc:
        print(f"error: invalid configuration: {exc}", file=sys.stderr)
        return 2

    use_color = not args.no_color and args.output is None and args.format == "cli"
    if not args.no_banner and args.format == "cli" and args.output is None:
        print(BANNER.format(version=__version__), file=sys.stderr)

    engine = Engine(config)
    result = engine.scan_paths(args.paths)

    if args.write_baseline:
        write_baseline(result, Path(args.write_baseline))
        print(f"Baseline written to {args.write_baseline} ({len(result.findings)} findings).")
        return 0

    if args.format == "json":
        rendered = render_json(result)
    elif args.format == "sarif":
        rendered = render_sarif(result)
    else:
        rendered = render_cli(result, color=use_color)

    if args.output:
        Path(args.output).write_text(rendered, encoding="utf-8")
        print(f"Results written to {args.output}", file=sys.stderr)
    else:
        print(rendered)

    max_sev = result.max_severity()
    if max_sev is not None and max_sev >= config.fail_on:
        return 1
    return 0
