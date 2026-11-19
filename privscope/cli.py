"""privscope command line: analyze, diff and list rules."""
from __future__ import annotations

import argparse
import json
import os
import sys
from pathlib import Path

from . import __version__
from .engine import SEVERITIES, SEV_RANK, RuleError, analyze, diff_reports, load_rules
from .html_report import render_diff_html, render_html
from .report import render_diff_markdown, render_diff_text, render_markdown, render_text

EXIT_OK, EXIT_ERROR, EXIT_FAIL_ON = 0, 1, 3


class InputError(Exception):
    pass


def load_collection(path: str) -> dict:
    try:
        raw = Path(path).read_bytes()
    except OSError as e:
        raise InputError(f"can't read {path}: {e.strerror}") from None
    # PowerShell 5.1 writes UTF-8 with a BOM via Out-File, or UTF-16 when output is redirected.
    if raw.startswith((b"\xff\xfe", b"\xfe\xff")):
        text = raw.decode("utf-16")
    else:
        text = raw.decode("utf-8-sig", errors="replace")  # Linux file names needn't be UTF-8
    try:
        doc = json.loads(text)
    except json.JSONDecodeError as e:
        raise InputError(f"{path} is not valid JSON: {e}") from None
    meta = doc.get("privscope") if isinstance(doc, dict) else None
    if not isinstance(meta, dict) or meta.get("kind") != "collection":
        raise InputError(f"{path} is not a privscope collection (run the collector first)")
    return doc


def _use_color(choice: str, to_file: bool) -> bool:
    if choice == "always":
        return True
    if choice == "never" or to_file or os.environ.get("NO_COLOR"):
        return False
    if not sys.stdout.isatty():
        return False
    if os.name == "nt":
        _enable_windows_ansi()
    return True


def _enable_windows_ansi() -> None:
    """Turn on ANSI escape handling in the classic Windows console (no-op elsewhere)."""
    try:
        import ctypes

        kernel32 = ctypes.windll.kernel32
        handle = kernel32.GetStdHandle(-11)  # STD_OUTPUT_HANDLE
        mode = ctypes.c_uint32()
        if kernel32.GetConsoleMode(handle, ctypes.byref(mode)):
            kernel32.SetConsoleMode(handle, mode.value | 0x0004)  # ENABLE_VIRTUAL_TERMINAL_PROCESSING
    except (AttributeError, OSError):
        pass


def _emit(text: str, out: str = None) -> None:
    if out:
        Path(out).write_text(text, encoding="utf-8")
        print(f"[privscope] wrote {out}", file=sys.stderr)
    else:
        sys.stdout.write(text)


def _add_common(p: argparse.ArgumentParser) -> None:
    p.add_argument("--rules", metavar="DIR", help="rule folder (default: the bundled rules)")
    p.add_argument("--perspective", choices=["auto", "principal", "standard-user"], default="auto",
                   help="whose access counts: the collecting account, any standard user, or "
                        "auto (standard user when the collector ran elevated)")
    p.add_argument("--min-severity", choices=SEVERITIES, default="info",
                   help="leave out findings below this severity")
    p.add_argument("--format", choices=["text", "md", "html", "json"], default="text")
    p.add_argument("-o", "--output", metavar="FILE", help="write the report to FILE")
    p.add_argument("--color", choices=["auto", "always", "never"], default="auto")
    p.add_argument("--fail-on", choices=SEVERITIES, metavar="SEVERITY",
                   help=f"exit {EXIT_FAIL_ON} if any finding (diff: any new finding) is at least "
                        "this severe")


def build_parser() -> argparse.ArgumentParser:
    ap = argparse.ArgumentParser(
        prog="privscope",
        description="Offline analyzer for privscope collections: finds Windows local "
                    "privilege-escalation weaknesses and says how to fix them.")
    ap.add_argument("--version", action="version", version=f"privscope {__version__}")
    sub = ap.add_subparsers(dest="cmd", required=True)

    a = sub.add_parser("analyze", help="report findings for one collection")
    a.add_argument("collection", help="JSON file from Invoke-PrivscopeCollector.ps1")
    a.add_argument("--brief", action="store_true", help="text format: leave out why/fix/refs")
    _add_common(a)

    d = sub.add_parser("diff", help="compare two collections of the same host")
    d.add_argument("old", help="earlier collection")
    d.add_argument("new", help="later collection")
    _add_common(d)

    r = sub.add_parser("rules", help="list the rules")
    r.add_argument("--rules", metavar="DIR", help="rule folder (default: the bundled rules)")
    r.add_argument("--format", choices=["text", "json"], default="text")
    return ap


def _fails(findings, threshold) -> bool:
    return bool(threshold) and any(SEV_RANK[f["severity"]] >= SEV_RANK[threshold] for f in findings)


def main(argv=None) -> int:
    try:
        sys.stdout.reconfigure(errors="replace")
    except (AttributeError, ValueError):
        pass
    args = build_parser().parse_args(argv)
    try:
        rules = load_rules(args.rules)
        if args.cmd == "rules":
            if args.format == "json":
                print(json.dumps(rules, indent=2, ensure_ascii=False))
            else:
                for rule in sorted(rules, key=lambda x: (x["platform"], x["id"])):
                    print(f"{rule['platform']:<8} {rule['id']:<12} {rule['severity']:<9} "
                          f"{rule['category']:<12} {rule['title']}")
                print(f"\n{len(rules)} rules")
            return EXIT_OK

        color = _use_color(args.color, bool(args.output))
        if args.cmd == "analyze":
            report = analyze(load_collection(args.collection), rules, args.perspective, args.min_severity)
            if args.format == "json":
                text = json.dumps(report, indent=2, ensure_ascii=False) + "\n"
            elif args.format == "md":
                text = render_markdown(report)
            elif args.format == "html":
                text = render_html(report)
            else:
                text = render_text(report, color=color, full=not args.brief)
            _emit(text, args.output)
            return EXIT_FAIL_ON if _fails(report["findings"], args.fail_on) else EXIT_OK

        old = analyze(load_collection(args.old), rules, args.perspective, args.min_severity)
        new = analyze(load_collection(args.new), rules, args.perspective, args.min_severity)
        diff = diff_reports(old, new)
        if args.format == "json":
            text = json.dumps(diff, indent=2, ensure_ascii=False) + "\n"
        elif args.format == "md":
            text = render_diff_markdown(diff)
        elif args.format == "html":
            text = render_diff_html(diff)
        else:
            text = render_diff_text(diff, color=color)
        _emit(text, args.output)
        return EXIT_FAIL_ON if _fails(diff["new_findings"], args.fail_on) else EXIT_OK
    except (RuleError, InputError) as e:
        print(f"privscope: {e}", file=sys.stderr)
        return EXIT_ERROR


if __name__ == "__main__":
    raise SystemExit(main())
