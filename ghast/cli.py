"""Command line interface."""
from __future__ import annotations

import argparse
import os
import sys
from typing import List, Optional, Sequence, Set

from . import __version__
from .findings import CRITICAL, HIGH, INFO, LOW, MEDIUM, RULES, SEVERITY_ORDER
from .report import render_json, render_markdown, render_sarif, render_terminal
from .scan import ScanResult, filter_findings, scan_paths

SEVERITIES = [CRITICAL, HIGH, MEDIUM, LOW, INFO]


def _add_filter_args(parser: argparse.ArgumentParser) -> None:
    parser.add_argument("--min-severity", choices=SEVERITIES, default=LOW,
                        help="hide findings below this severity (default: low)")
    parser.add_argument("--only", action="append", default=[], metavar="RULE",
                        help="report only these rule ids (repeatable)")
    parser.add_argument("--skip", action="append", default=[], metavar="RULE",
                        help="suppress these rule ids (repeatable)")
    parser.add_argument("--format", dest="fmt", default="terminal",
                        choices=["terminal", "json", "sarif", "markdown"],
                        help="output format (default: terminal)")
    parser.add_argument("-o", "--output", metavar="FILE",
                        help="write the report to FILE instead of stdout")
    parser.add_argument("--explain", action="store_true",
                        help="show the reasoning behind each severity score")
    parser.add_argument("--no-flow", action="store_true",
                        help="omit data-flow traces from terminal output")
    parser.add_argument("--no-collapse", action="store_true",
                        help="list every occurrence instead of folding repeats of the "
                             "same finding within a file (terminal and markdown only)")
    parser.add_argument("--fail-on", choices=SEVERITIES + ["never"], default=HIGH,
                        help="exit non-zero when a finding at or above this "
                             "severity remains (default: high)")


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="ghast",
        description="Taint-analysis security scanner for GitHub Actions workflows.",
        epilog="Exit codes: 0 clean, 1 findings at or above --fail-on, 2 usage or runtime error.",
    )
    parser.add_argument("--version", action="version", version="ghast " + __version__)
    sub = parser.add_subparsers(dest="command")

    scan = sub.add_parser("scan", help="scan local workflow files")
    scan.add_argument("paths", nargs="*", default=["."],
                      help="files or directories to scan (default: the current directory)")
    scan.add_argument("--no-actions", action="store_true",
                      help="skip composite action.yml definitions")
    scan.add_argument("--exclude", action="append", default=[], metavar="GLOB",
                      help="skip paths matching GLOB, e.g. --exclude 'examples/*' "
                           "or --exclude fixtures (repeatable)")
    _add_filter_args(scan)

    hunt = sub.add_parser("hunt", help="scan workflows in remote GitHub repositories")
    hunt.add_argument("repos", nargs="*", metavar="OWNER/REPO",
                      help="repositories to scan")
    hunt.add_argument("--from-file", metavar="FILE",
                      help="read repositories from FILE, one per line")
    hunt.add_argument("--top", type=int, metavar="N",
                      help="scan the N most-starred public repositories. Note that the "
                           "most-starred repositories are largely awesome-lists and "
                           "tutorials with no CI at all; pair this with --language for a "
                           "corpus that actually builds software")
    hunt.add_argument("--language", metavar="LANG",
                      help="restrict --top to one language, e.g. go, python, rust")
    hunt.add_argument("--min-stars", type=int, default=5000,
                      help="star floor for --top (default: 5000)")
    hunt.add_argument("--max-stars", type=int, metavar="N",
                      help="star ceiling for --top. Pair with --min-stars to sweep the "
                           "long tail, where projects have the same CI complexity as the "
                           "top of the list and far less security attention")
    hunt.add_argument("--ref", help="git ref to read workflows from")
    hunt.add_argument("--workers", type=int, default=4,
                  help="parallel requests (default: 4). GitHub enforces a secondary "
                       "limit on burst concurrency separately from the hourly quota, "
                       "so raising this is often slower overall")
    _add_filter_args(hunt)

    rules = sub.add_parser("rules", help="list the rules this build knows about")
    rules.add_argument("--format", dest="fmt", default="terminal",
                       choices=["terminal", "json", "markdown"])

    explain = sub.add_parser("explain", help="print the full write-up for one rule")
    explain.add_argument("rule_id", metavar="RULE")
    return parser


def _render(result: ScanResult, args: argparse.Namespace) -> str:
    # JSON and SARIF keep every occurrence: those consumers de-duplicate
    # themselves and need a location per annotation.
    if args.fmt in ("terminal", "markdown") and not args.no_collapse:
        from .scan import collapse
        result.findings = collapse(result.findings)
    if args.fmt == "json":
        return render_json(result)
    if args.fmt == "sarif":
        return render_sarif(result)
    if args.fmt == "markdown":
        return render_markdown(result)
    return render_terminal(result, stream=sys.stdout,
                           show_flow=not args.no_flow, explain=args.explain)


def _emit(text: str, output: Optional[str]) -> None:
    if output:
        directory = os.path.dirname(os.path.abspath(output))
        if directory:
            os.makedirs(directory, exist_ok=True)
        with open(output, "w", encoding="utf-8") as handle:
            handle.write(text)
        print("wrote {}".format(output), file=sys.stderr)
    else:
        sys.stdout.write(text)


def _exit_code(result: ScanResult, fail_on: str) -> int:
    if fail_on == "never":
        return 0
    threshold = SEVERITY_ORDER[fail_on]
    return 1 if any(SEVERITY_ORDER[f.severity] <= threshold for f in result.findings) else 0


def _apply_filters(result: ScanResult, args: argparse.Namespace) -> ScanResult:
    result.findings = filter_findings(
        result.findings,
        min_severity=args.min_severity,
        only_rules=set(_split(args.only)) or None,
        skip_rules=set(_split(args.skip)) or None,
    )
    return result


def _split(values: Sequence[str]) -> List[str]:
    out: List[str] = []
    for value in values:
        out.extend(part.strip().upper() for part in value.split(",") if part.strip())
    return out


def cmd_scan(args: argparse.Namespace) -> int:
    paths = args.paths or ["."]
    for path in paths:
        if not os.path.exists(path):
            print("ghast: no such path: {}".format(path), file=sys.stderr)
            return 2
    root = paths[0] if os.path.isdir(paths[0]) else os.path.dirname(paths[0]) or "."
    result = scan_paths(paths, include_actions=not args.no_actions, relative_to=root,
                        exclude=args.exclude)
    if result.files_scanned == 0:
        print("ghast: no workflow files found under {}".format(", ".join(paths)),
              file=sys.stderr)
        return 0
    _apply_filters(result, args)
    _emit(_render(result, args), args.output)
    return _exit_code(result, args.fail_on)


def cmd_hunt(args: argparse.Namespace) -> int:
    from .hunt import GhError, hunt, summarise, to_scan_result, top_repos

    repos: List[str] = list(args.repos)
    if args.from_file:
        try:
            with open(args.from_file, "r", encoding="utf-8") as handle:
                repos.extend(
                    line.strip() for line in handle
                    if line.strip() and not line.startswith("#")
                )
        except OSError as exc:
            print("ghast: {}".format(exc), file=sys.stderr)
            return 2
    if args.top:
        try:
            repos.extend(top_repos(args.language, args.top, args.min_stars,
                                   args.max_stars))
        except GhError as exc:
            print("ghast: {}".format(exc), file=sys.stderr)
            return 2
    repos = list(dict.fromkeys(r.strip() for r in repos if r.strip()))
    if not repos:
        print("ghast: give at least one OWNER/REPO, --from-file or --top", file=sys.stderr)
        return 2

    done = [0]

    def progress(item) -> None:
        done[0] += 1
        print("[{}/{}] {} — {}".format(done[0], len(repos), item.repo, item.status),
              file=sys.stderr)

    try:
        results = hunt(repos, ref=args.ref, workers=args.workers, progress=progress)
    except GhError as exc:
        print("ghast: {}".format(exc), file=sys.stderr)
        return 2
    print(summarise(results), file=sys.stderr)
    result = to_scan_result(results)
    _apply_filters(result, args)
    _emit(_render(result, args), args.output)
    return _exit_code(result, args.fail_on)


def cmd_rules(args: argparse.Namespace) -> int:
    if args.fmt == "json":
        import json as _json
        print(_json.dumps(
            [{"id": m.id, "name": m.name, "summary": m.summary, "tags": list(m.tags)}
             for m in sorted(RULES.values(), key=lambda m: m.id)],
            indent=2))
        return 0
    if args.fmt == "markdown":
        print("| Rule | Name | What it finds |")
        print("|---|---|---|")
        for meta in sorted(RULES.values(), key=lambda m: m.id):
            print("| `{}` | {} | {} |".format(meta.id, meta.name, meta.summary))
        return 0
    width = max(len(m.name) for m in RULES.values())
    for meta in sorted(RULES.values(), key=lambda m: m.id):
        print("{}  {}  {}".format(meta.id, meta.name.ljust(width), meta.summary))
    return 0


def cmd_explain(args: argparse.Namespace) -> int:
    rule_id = args.rule_id.upper()
    meta = RULES.get(rule_id)
    if meta is None:
        matches = [m for m in RULES.values() if m.name == args.rule_id.lower()]
        meta = matches[0] if matches else None
    if meta is None:
        print("ghast: unknown rule {}".format(args.rule_id), file=sys.stderr)
        return 2
    print("{}  {}".format(meta.id, meta.name))
    print("=" * (len(meta.id) + len(meta.name) + 2))
    print()
    print(meta.summary)
    print()
    print(meta.description)
    print()
    print("Remediation")
    print("-----------")
    print(meta.remediation)
    if meta.references:
        print()
        print("References")
        print("----------")
        for reference in meta.references:
            print("  " + reference)
    return 0


def main(argv: Optional[Sequence[str]] = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    if args.command is None:
        parser.print_help()
        return 2
    handlers = {"scan": cmd_scan, "hunt": cmd_hunt, "rules": cmd_rules,
                "explain": cmd_explain}
    try:
        return handlers[args.command](args)
    except BrokenPipeError:
        return 0
    except KeyboardInterrupt:
        print("\nghast: interrupted", file=sys.stderr)
        return 130


if __name__ == "__main__":
    sys.exit(main())
