"""Self-contained HTML reports.

One file, no scripts, no external resources, and a Content-Security-Policy that forbids
both: everything in a report (task names, paths, account names) comes from the scanned
host, which may be hostile, so every value is escaped and nothing can execute even if a
value slipped through. Severity filtering is pure CSS (:has()); browsers without it just
show everything.
"""
from __future__ import annotations

import html
from typing import Dict, Iterable, List

from . import __version__
from .engine import fmt

SEVS = ["critical", "high", "medium", "low", "info"]

CSP = "default-src 'none'; style-src 'unsafe-inline'; base-uri 'none'; form-action 'none'"

CSS = """
:root{
  --page:#f9f9f7;--surface:#fcfcfb;--surface-2:#f0efec;--ink:#0b0b0b;--ink-2:#52514e;--muted:#6b6a65;
  --line:#e1e0d9;--accent:#1c5cab;--ok:#007a00;
  --critical:#a3195b;--high:#c2312a;--medium:#8a5d00;--low:#1c5cab;--info:#66655f;
  --mono:ui-monospace,"Cascadia Mono","Cascadia Code",Consolas,"Liberation Mono",monospace;
  color-scheme:light dark;
}
@media (prefers-color-scheme:dark){:root{
  --page:#0d0d0d;--surface:#1a1a19;--surface-2:#262624;--ink:#f0efec;--ink-2:#c3c2b7;--muted:#a3a29b;
  --line:#2c2c2a;--accent:#6da7ec;--ok:#3fb950;
  --critical:#ec6fa6;--high:#f2776b;--medium:#eda100;--low:#6da7ec;--info:#a3a29b;
}}
*{box-sizing:border-box}
html{-webkit-text-size-adjust:100%}
body{margin:0;background:var(--page);color:var(--ink);font:15px/1.55 "Segoe UI",system-ui,-apple-system,sans-serif}
main{max-width:1000px;margin:0 auto;padding:28px 16px 48px}
code,.mono{font-family:var(--mono);font-size:12.5px}
a{color:var(--accent)}
h1{margin:4px 0 2px;font-size:28px;line-height:1.2;overflow-wrap:anywhere}
h2{font-size:18px;margin:30px 0 10px}
.brand{font-family:var(--mono);font-size:12px;letter-spacing:.08em;text-transform:uppercase;color:var(--muted)}
.sub{margin:0;color:var(--ink-2)}
.meta{display:grid;grid-template-columns:max-content 1fr;gap:6px 18px;margin:22px 0;padding:14px 16px;
  background:var(--surface);border:1px solid var(--line);border-radius:10px}
.meta dt{color:var(--muted);font-size:13px}
.meta dd{margin:0;overflow-wrap:anywhere}
.tiles{display:grid;grid-template-columns:repeat(auto-fit,minmax(118px,1fr));gap:10px;margin:0 0 18px}
.tile{background:var(--surface);border:1px solid var(--line);border-top:3px solid var(--c);border-radius:10px;padding:10px 14px}
.tile .n{display:block;font-size:26px;font-weight:650;line-height:1.2;font-variant-numeric:tabular-nums;color:var(--c)}
.tile .l{font-size:12px;color:var(--muted);text-transform:uppercase;letter-spacing:.06em}
.tile.zero{border-top-color:var(--line)}
.tile.zero .n{color:var(--muted)}
.c-critical,[data-sev=critical]{--c:var(--critical)}
.c-high,[data-sev=high]{--c:var(--high)}
.c-medium,[data-sev=medium]{--c:var(--medium)}
.c-low,[data-sev=low]{--c:var(--low)}
.c-info,[data-sev=info]{--c:var(--info)}
.c-total{--c:var(--ink)}
.c-new{--c:var(--high)}
.c-resolved{--c:var(--ok)}
.c-unchanged{--c:var(--info)}
.filters{display:flex;flex-wrap:wrap;gap:6px 16px;align-items:center;margin:0 0 14px;font-size:13px;color:var(--ink-2)}
.filters>span{color:var(--muted)}
.filters label{display:inline-flex;gap:5px;align-items:center;cursor:pointer}
.filters input{accent-color:var(--accent);margin:0}
body:has(#show-critical:not(:checked)) .finding[data-sev=critical],
body:has(#show-high:not(:checked)) .finding[data-sev=high],
body:has(#show-medium:not(:checked)) .finding[data-sev=medium],
body:has(#show-low:not(:checked)) .finding[data-sev=low],
body:has(#show-info:not(:checked)) .finding[data-sev=info]{display:none}
.finding{background:var(--surface);border:1px solid var(--line);border-left:4px solid var(--c);border-radius:10px;margin:0 0 10px}
.finding>summary{position:relative;cursor:pointer;list-style:none;padding:12px 40px 12px 16px;display:flex;flex-wrap:wrap;gap:4px 10px;align-items:baseline}
.finding>summary::-webkit-details-marker{display:none}
.finding>summary::after{content:"\\25B8";position:absolute;right:16px;top:12px;color:var(--muted);transition:transform .15s}
.finding[open]>summary::after{transform:rotate(90deg)}
.sev{font:600 11px/1 var(--mono);letter-spacing:.06em;text-transform:uppercase;color:var(--c);
  border:1px solid currentColor;border-radius:999px;padding:3px 7px;white-space:nowrap}
.rid{font-family:var(--mono);font-size:12.5px;color:var(--muted)}
.ttl{font-weight:600}
.subj{flex-basis:100%;font-family:var(--mono);font-size:12.5px;color:var(--ink-2);overflow-wrap:anywhere}
.body{padding:2px 16px 14px;border-top:1px solid var(--line)}
.body h4{margin:14px 0 4px;font-size:12px;font-weight:600;text-transform:uppercase;letter-spacing:.06em;color:var(--muted)}
.body p{margin:0}
table.ev{width:100%;border-collapse:collapse;font-size:13.5px}
table.ev th{text-align:left;font-weight:500;color:var(--muted);padding:3px 14px 3px 0;vertical-align:top;white-space:nowrap;width:1%}
table.ev td{padding:3px 0;overflow-wrap:anywhere}
ul.notes{margin:0;padding:10px 14px 10px 30px;background:var(--surface-2);border-radius:8px;font-family:var(--mono);font-size:12.5px;overflow-wrap:anywhere}
ul.refs{margin:0;padding-left:18px;font-size:13px;overflow-wrap:anywhere}
.tbl{overflow-x:auto;background:var(--surface);border:1px solid var(--line);border-radius:10px}
table.list{width:100%;border-collapse:collapse;font-size:13.5px}
table.list th,table.list td{text-align:left;padding:8px 12px;border-bottom:1px solid var(--line);vertical-align:top}
table.list tr:last-child td{border-bottom:0}
table.list th{font-size:12px;color:var(--muted);font-weight:500;text-transform:uppercase;letter-spacing:.05em}
table.list td.mono{overflow-wrap:anywhere;min-width:200px}
details.group>summary{cursor:pointer;font-size:18px;font-weight:600;margin:30px 0 10px}
.warn{border-left:4px solid var(--medium);background:var(--surface);padding:10px 14px;border-radius:8px;margin:0 0 10px}
.empty{color:var(--ink-2);padding:14px 16px;background:var(--surface);border:1px dashed var(--line);border-radius:10px}
footer{margin-top:36px;color:var(--muted);font-size:12.5px}
@media (max-width:560px){.meta{grid-template-columns:1fr;gap:0 0}.meta dd{margin-bottom:8px}}
@media print{
  :root{--page:#fff;--surface:#fff;--surface-2:#f3f3f1;--ink:#000;--ink-2:#333;--muted:#555;--line:#ccc}
  .filters{display:none}
  .finding,.tile,.meta{break-inside:avoid}
}
"""


def e(value) -> str:
    return html.escape(fmt(value), quote=True)


def _sev(sev: str) -> str:
    return sev if sev in SEVS else "info"


def _page(title: str, body: str) -> str:
    return (
        "<!doctype html>\n<html lang=\"en\">\n<head>\n<meta charset=\"utf-8\">\n"
        "<meta name=\"viewport\" content=\"width=device-width, initial-scale=1\">\n"
        f"<meta http-equiv=\"Content-Security-Policy\" content=\"{CSP}\">\n"
        "<meta name=\"referrer\" content=\"no-referrer\">\n"
        f"<meta name=\"generator\" content=\"privscope {e(__version__)}\">\n"
        f"<title>{e(title)}</title>\n<style>{CSS}</style>\n</head>\n<body>\n<main>\n"
        f"{body}\n</main>\n</body>\n</html>\n"
    )


def _os_line(src: Dict) -> str:
    line = " ".join(x for x in (src.get("os"), src.get("display_version")) if x)
    if src.get("build"):
        line += f" ({src['build']})"
    return line


def _meta(rows: Iterable) -> str:
    items = "".join(f"<dt>{e(k)}</dt><dd>{v}</dd>" for k, v in rows)
    return f'<dl class="meta">{items}</dl>'


def _account(src: Dict) -> str:
    detail = ", ".join(x for x in (src.get("elevation"), src.get("integrity")) if x)
    return e(src.get("user") or "?") + (f" <span class=\"rid\">({e(detail)})</span>" if detail else "")


def _tiles(items: Iterable) -> str:
    out = []
    for cls, label, n in items:
        zero = " zero" if n == 0 else ""
        out.append(f'<div class="tile c-{e(cls)}{zero}"><span class="n">{n}</span>'
                   f'<span class="l">{e(label)}</span></div>')
    return f'<div class="tiles">{"".join(out)}</div>'


def _link(url: str) -> str:
    if url.startswith(("https://", "http://")):
        return f'<a href="{e(url)}" rel="noopener noreferrer" target="_blank">{e(url)}</a>'
    return e(url)


def _finding(f: Dict, open_: bool = True) -> str:
    sev = _sev(f["severity"])
    rows = "".join(f'<tr><th scope="row">{e(k)}</th><td><code>{e(v)}</code></td></tr>'
                   for k, v in f["evidence"].items() if v not in (None, ""))
    parts = []
    if rows:
        parts.append(f'<h4>Evidence</h4><table class="ev">{rows}</table>')
    if f["notes"]:
        notes = "".join(f"<li>{e(n)}</li>" for n in f["notes"])
        parts.append(f'<h4>Why it was flagged</h4><ul class="notes">{notes}</ul>')
    parts.append(f"<h4>Why it matters</h4><p>{e(f['why'])}</p>")
    parts.append(f"<h4>Fix</h4><p>{e(f['fix'])}</p>")
    if f["refs"]:
        refs = "".join(f"<li>{_link(r)}</li>" for r in f["refs"])
        parts.append(f'<h4>References</h4><ul class="refs">{refs}</ul>')
    return (
        f'<details class="finding" data-sev="{sev}"{" open" if open_ else ""}>'
        f'<summary><span class="sev">{sev}</span><span class="rid">{e(f["rule"])}</span>'
        f'<span class="ttl">{e(f["title"])}</span><span class="subj">{e(f["subject"])}</span></summary>'
        f'<div class="body">{"".join(parts)}</div></details>'
    )


def _footer(extra: str = "") -> str:
    return (f"<footer>privscope {e(__version__)} &middot; read-only collection, offline analysis, "
            f"detect-and-report only{extra}</footer>")


def render_html(report: Dict) -> str:
    src = report["source"]
    s = report["summary"]
    host = src.get("hostname") or "unknown host"
    head = (f'<header><div class="brand">privscope report</div><h1>{e(host)}</h1>'
            f'<p class="sub">{e(_os_line(src))}</p></header>')
    meta = _meta([
        ("Collected", e(src.get("collected_at"))),
        ("Account", _account(src)),
        ("View", e(report["perspective"]["description"])),
        ("Rules", f"{report['rules_evaluated']} evaluated, minimum severity {e(report['min_severity'])}"),
    ])
    tiles = _tiles([("total", "total", s["total"])] + [(k, k, s[k]) for k in SEVS])
    if report["findings"]:
        boxes = "".join(
            f'<label><input type="checkbox" id="show-{k}" checked> {k} ({s[k]})</label>'
            for k in SEVS if s[k])
        filters = f'<div class="filters" role="group" aria-label="Show severities"><span>Show</span>{boxes}</div>'
        body = filters + "".join(_finding(f) for f in report["findings"])
    else:
        body = '<p class="empty">No findings at or above this severity.</p>'
    return _page(f"privscope: {host}",
                 f"{head}{meta}{tiles}<h2>Findings</h2>{body}{_footer()}")


def _list_table(findings: List[Dict]) -> str:
    rows = "".join(
        f'<tr data-sev="{_sev(f["severity"])}"><td><span class="sev">{_sev(f["severity"])}</span></td>'
        f'<td class="rid">{e(f["rule"])}</td><td>{e(f["title"])}</td>'
        f'<td class="mono">{e(f["subject"])}</td></tr>'
        for f in findings)
    return ('<div class="tbl"><table class="list"><thead><tr><th>Severity</th><th>Rule</th>'
            f'<th>Finding</th><th>Subject</th></tr></thead><tbody>{rows}</tbody></table></div>')


def render_diff_html(diff: Dict) -> str:
    old, new, s = diff["old"], diff["new"], diff["summary"]
    host = new.get("hostname") or "unknown host"
    head = (f'<header><div class="brand">privscope diff</div><h1>{e(host)}</h1>'
            f'<p class="sub">{e(_os_line(new))}</p></header>')
    meta = _meta([
        ("Earlier run", f"{e(old.get('collected_at'))} <span class=\"rid\">({e(old.get('hostname'))})</span>"),
        ("Later run", f"{e(new.get('collected_at'))} <span class=\"rid\">({e(new.get('hostname'))})</span>"),
        ("Account", _account(new)),
        ("View", e(diff["perspective"]["description"])),
    ])
    warns = "".join(f'<p class="warn"><strong>Warning:</strong> {e(w)}</p>' for w in diff["warnings"])
    tiles = _tiles([("new", "new", s["new"]), ("resolved", "resolved", s["resolved"]),
                    ("unchanged", "unchanged", s["unchanged"])])
    parts = [head, meta, warns, tiles]
    if not s["new"] and not s["resolved"]:
        parts.append('<p class="empty">Nothing changed between the two runs.</p>')
    if diff["new_findings"]:
        parts.append("<h2>New findings</h2>" + "".join(_finding(f) for f in diff["new_findings"]))
    if diff["resolved_findings"]:
        parts.append("<h2>Resolved</h2>" + _list_table(diff["resolved_findings"]))
    if diff["unchanged_findings"]:
        parts.append(f'<details class="group"><summary>Unchanged ({s["unchanged"]})</summary>'
                     f'{_list_table(diff["unchanged_findings"])}</details>')
    parts.append(_footer())
    return _page(f"privscope diff: {host}", "".join(parts))
