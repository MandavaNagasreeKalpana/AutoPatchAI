"""Command-line interface.

Exit codes:
  0  scan completed (with or without findings)
  1  scan completed with supported findings and --fail-on-findings was given
  2  operational error: bad arguments, missing project directory, Bandit
     missing or crashing, malformed results, or the report could not be written
"""

from __future__ import annotations

import argparse
import sys
from collections import Counter
from collections.abc import Sequence
from pathlib import Path

from autopatch.models import ScanResult
from autopatch.scanner import ScannerAgent, ScannerError
from autopatch.scanner.errors import safe_error_message

EXIT_OK = 0
EXIT_FINDINGS = 1
EXIT_ERROR = 2
MAX_LISTED_FINDINGS = 50


def _build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="autopatch",
        description="AutoPatch AI: AST-aware security vulnerability remediation for Python.",
    )
    sub = parser.add_subparsers(dest="command", required=True)
    scan = sub.add_parser(
        "scan",
        help="Scan a Python project for supported vulnerabilities (read-only).",
        description="Scan a Python project with Bandit + AST. Never modifies or runs the project.",
    )
    scan.add_argument("project_dir", help="Directory to scan.")
    scan.add_argument("-o", "--output", help="Write the full scan result as JSON to this file.")
    scan.add_argument(
        "-e",
        "--exclude",
        action="append",
        default=[],
        metavar="GLOB",
        help="Glob for paths or directory names to skip (repeatable), e.g. 'tests' or 'legacy/*'.",
    )
    scan.add_argument(
        "--ignore-nosec",
        action="store_true",
        help="Report issues even on lines marked '# nosec'.",
    )
    scan.add_argument(
        "--fail-on-findings",
        action="store_true",
        help="Exit with code 1 when supported findings are present.",
    )
    return parser


def _err(message: str) -> None:
    print(f"ERROR: {message}", file=sys.stderr)


def _check_output_path(output: Path, result: ScanResult) -> str | None:
    if output.suffix.lower() != ".json":
        return "output file must have a .json extension"
    root = Path(result.project_root)
    try:
        resolved = output.resolve()
    except OSError as exc:
        return f"invalid output path: {safe_error_message(exc)}"
    if resolved.is_relative_to(root):
        rel = resolved.relative_to(root).as_posix()
        if rel in set(result.files_scanned):
            return "output file would overwrite a scanned source file"
    if resolved.is_dir():
        return "output path is a directory"
    return None


def _print_summary(result: ScanResult) -> None:
    print(f"AutoPatch scan: {result.project_root}")
    print(
        f"Bandit {result.scanner_version} | files scanned: {len(result.files_scanned)} | "
        f"skipped: {len(result.skipped_files)} | {result.duration_seconds:.2f}s"
    )
    print(f"Supported findings: {len(result.findings)}")
    for category, count in result.counts_by_category().items():
        print(f"  {category.value:<26}{count}")
    for finding in result.findings[:MAX_LISTED_FINDINGS]:
        print(
            f"  - {finding.file_path}:{finding.line}  {finding.rule_id}  "
            f"{finding.severity.value:<8} {finding.category.value}"
        )
    if len(result.findings) > MAX_LISTED_FINDINGS:
        print(f"  ... {len(result.findings) - MAX_LISTED_FINDINGS} more (see JSON output)")

    related = Counter(f.rule_id for f in result.related_findings)
    ignored = Counter(i.rule_id for i in result.ignored_issues)
    print(
        f"Related (informational, not patched): {len(result.related_findings)}"
        + (f"  [{', '.join(f'{k} x{v}' for k, v in sorted(related.items()))}]" if related else "")
    )
    print(
        f"Ignored (unsupported Bandit rules): {len(result.ignored_issues)}"
        + (f"  [{', '.join(f'{k} x{v}' for k, v in sorted(ignored.items()))}]" if ignored else "")
    )
    for skipped in result.skipped_files:
        print(f"  skipped: {skipped.file_path} ({skipped.reason})")
    for error in result.errors:
        _err(error)


def _cmd_scan(args: argparse.Namespace) -> int:
    agent = ScannerAgent(exclude=args.exclude, ignore_nosec=args.ignore_nosec)
    try:
        result = agent.scan(args.project_dir)
    except ScannerError as exc:
        _err(f"scan failed: {exc}")
        return EXIT_ERROR

    _print_summary(result)

    if args.output:
        output = Path(args.output)
        problem = _check_output_path(output, result)
        if problem:
            _err(problem)
            return EXIT_ERROR
        try:
            output.parent.mkdir(parents=True, exist_ok=True)
            output.write_text(result.model_dump_json(indent=2) + "\n", encoding="utf-8")
        except OSError as exc:
            _err(f"could not write report: {safe_error_message(exc)}")
            return EXIT_ERROR
        print(f"Report written to {output}")

    if not result.ok:
        print("Result: scan finished with errors (see above); results may be incomplete.")
        return EXIT_ERROR
    if result.findings:
        print(f"Result: {len(result.findings)} supported finding(s).")
        return EXIT_FINDINGS if args.fail_on_findings else EXIT_OK
    print("Result: no supported vulnerabilities found. The scan completed successfully.")
    return EXIT_OK


def main(argv: Sequence[str] | None = None) -> int:
    args = _build_parser().parse_args(argv)
    if args.command == "scan":
        return _cmd_scan(args)
    return EXIT_ERROR  # pragma: no cover - argparse enforces a command


if __name__ == "__main__":  # pragma: no cover
    sys.exit(main())
