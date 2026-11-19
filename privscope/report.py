"""Text and Markdown renderers for reports and diffs (JSON output is the dict itself)."""
from __future__ import annotations

import textwrap
from typing import Dict, List

from .engine import fmt

COLORS = {
    "critical": "\033[1;35m",
    "high": "\033[1;31m",
    "medium": "\033[33m",
    "low": "\033[36m",
    "info": "\033[2m",
}
RESET = "\033[0m"
BOLD = "\033[1m"
WIDTH = 100


def _tag(sev: str, color: bool) -> str:
    t = f"[{sev.upper()}]"
    return f"{COLORS[sev]}{t}{RESET}" if color else t


def _wrap(label: str, text: str, indent: int = 4) -> List[str]:
    lead = " " * indent + f"{label}: "
    return textwrap.wrap(text, WIDTH, initial_indent=lead,
                         subsequent_indent=" " * len(lead)) or [lead.rstrip()]


def _evidence_line(ev: Dict) -> str:
    parts = [f"{k}: {fmt(v)}" for k, v in ev.items() if v not in (None, "")]
    return " | ".join(parts)


def _header_text(src: Dict) -> List[str]:
    os_line = " ".join(x for x in (src.get("os"), src.get("display_version")) if x)
    if src.get("build"):
        os_line += f" ({src['build']})"
    acct = src.get("user") or "?"
    detail = ", ".join(x for x in (src.get("elevation"), src.get("integrity")) if x)
    return [
        f"host:      {src.get('hostname') or '?'}  {os_line}".rstrip(),
        f"collected: {src.get('collected_at') or '?'} as {acct}" + (f" ({detail})" if detail else ""),
    ]


def _finding_text(f: Dict, color: bool, full: bool) -> List[str]:
    title = f"{BOLD}{f['title']}{RESET}" if color else f["title"]
    out = [f"{_tag(f['severity'], color)} {f['rule']}  {title}",
           f"    subject:  {f['subject']}"]
    ev = _evidence_line(f["evidence"])
    if ev:
        out += _wrap("evidence", ev)
    for n in f["notes"]:
        out += textwrap.wrap(n, WIDTH, initial_indent="    - ", subsequent_indent="      ")
    if full:
        out += _wrap("why", f["why"])
        out += _wrap("fix", f["fix"])
        for r in f["refs"]:
            out.append(f"    ref:      {r}")
    return out


def render_text(report: Dict, color: bool = False, full: bool = True) -> str:
    s = report["summary"]
    lines = [f"privscope {report['privscope']['version']} report", *_header_text(report["source"]),
             f"view:      {report['perspective']['description']}", ""]
    counts = ", ".join(f"{s[k]} {k}" for k in ("critical", "high", "medium", "low", "info") if s[k])
    lines.append(f"{s['total']} finding{'s' if s['total'] != 1 else ''}"
                 + (f": {counts}" if counts else "")
                 + f"  ({report['rules_evaluated']} rules, minimum severity {report['min_severity']})")
    for f in report["findings"]:
        lines.append("")
        lines += _finding_text(f, color, full)
    return "\n".join(lines) + "\n"


def render_diff_text(diff: Dict, color: bool = False) -> str:
    s = diff["summary"]
    lines = [f"privscope {diff['privscope']['version']} diff",
             f"old: {diff['old'].get('hostname') or '?'} collected {diff['old'].get('collected_at') or '?'}",
             f"new: {diff['new'].get('hostname') or '?'} collected {diff['new'].get('collected_at') or '?'}",
             f"view: {diff['perspective']['description']}"]
    for w in diff["warnings"]:
        lines.append(f"warning: {w}")
    lines += ["", f"{s['new']} new, {s['resolved']} resolved, {s['unchanged']} unchanged"]
    for title, key, full in (("NEW", "new_findings", True), ("RESOLVED", "resolved_findings", False),
                             ("UNCHANGED", "unchanged_findings", False)):
        items = diff[key]
        if not items:
            continue
        lines += ["", f"== {title} =="]
        for f in items:
            if full:
                lines.append("")
                lines += _finding_text(f, color, True)
            else:
                lines.append(f"{_tag(f['severity'], color)} {f['rule']}  {f['subject']}")
    return "\n".join(lines) + "\n"


# --- Markdown ---------------------------------------------------------------------------

def _md(text) -> str:
    return fmt(text).replace("|", "\\|").replace("\n", " ")


def _md_code(text) -> str:
    t = fmt(text)
    return f"`{t}`" if "`" not in t else _md(t)


def _finding_md(f: Dict) -> List[str]:
    out = [f"### {f['severity'].upper()} · {f['rule']} · {_md(f['title'])}", "",
           f"**Subject:** {_md_code(f['subject'])}", ""]
    rows = [(k, v) for k, v in f["evidence"].items() if v not in (None, "")]
    if rows:
        out += ["| Evidence | |", "|---|---|"]
        out += [f"| {_md(k)} | {_md_code(v)} |" for k, v in rows]
        out.append("")
    for n in f["notes"]:
        out.append(f"- {_md(n)}")
    if f["notes"]:
        out.append("")
    out += [f"**Why it matters:** {f['why']}", "", f"**Fix:** {f['fix']}", ""]
    if f["refs"]:
        out.append("**References:** " + ", ".join(f"<{r}>" for r in f["refs"]))
        out.append("")
    return out


def render_markdown(report: Dict) -> str:
    src = report["source"]
    s = report["summary"]
    os_line = " ".join(x for x in (src.get("os"), src.get("display_version")) if x)
    if src.get("build"):
        os_line += f" ({src['build']})"
    lines = [f"# privscope report: {_md(src.get('hostname') or 'unknown host')}", "",
             "| | |", "|---|---|",
             f"| OS | {_md(os_line)} |",
             f"| Collected | {_md(src.get('collected_at'))} |",
             f"| Account | {_md(src.get('user'))} ({_md(src.get('elevation'))}, {_md(src.get('integrity'))}) |",
             f"| View | {_md(report['perspective']['description'])} |",
             f"| Rules | {report['rules_evaluated']} (minimum severity {report['min_severity']}) |",
             f"| Analyzer | privscope {report['privscope']['version']} |", "",
             "## Summary", "", "| Severity | Findings |", "|---|---|"]
    for k in ("critical", "high", "medium", "low", "info"):
        lines.append(f"| {k} | {s[k]} |")
    lines += [f"| **total** | **{s['total']}** |", ""]
    if report["findings"]:
        lines += ["## Findings", ""]
        for f in report["findings"]:
            lines += _finding_md(f)
    else:
        lines += ["No findings.", ""]
    return "\n".join(lines)


def render_diff_markdown(diff: Dict) -> str:
    s = diff["summary"]
    lines = [f"# privscope diff: {_md(diff['new'].get('hostname') or 'unknown host')}", "",
             "| | |", "|---|---|",
             f"| Old run | {_md(diff['old'].get('collected_at'))} ({_md(diff['old'].get('hostname'))}) |",
             f"| New run | {_md(diff['new'].get('collected_at'))} ({_md(diff['new'].get('hostname'))}) |",
             f"| View | {_md(diff['perspective']['description'])} |", ""]
    for w in diff["warnings"]:
        lines += [f"> **Warning:** {_md(w)}", ""]
    lines += [f"**{s['new']} new, {s['resolved']} resolved, {s['unchanged']} unchanged.**", ""]
    if diff["new_findings"]:
        lines += ["## New findings", ""]
        for f in diff["new_findings"]:
            lines += _finding_md(f)
    for title, key in (("Resolved", "resolved_findings"), ("Unchanged", "unchanged_findings")):
        if diff[key]:
            lines += [f"## {title}", "", "| Severity | Rule | Subject |", "|---|---|---|"]
            lines += [f"| {f['severity']} | {f['rule']} | {_md_code(f['subject'])} |" for f in diff[key]]
            lines.append("")
    return "\n".join(lines)
