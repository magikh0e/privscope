"""Rule loading, validation and evaluation. Semantics are defined in RULES.md."""
from __future__ import annotations

import json
import re
from pathlib import Path
from typing import Dict, List, Optional, Tuple

from . import __version__
from .acl import (
    PLATFORMS, AclIndex, Perspective, access_check, build_perspective, can_search, doc_platform,
    normalize, parent,
)

SEVERITIES = ["info", "low", "medium", "high", "critical"]
SEV_RANK = {s: i for i, s in enumerate(SEVERITIES)}

FIELD_OPS = ("eq", "ne", "in", "not_in", "regex", "exists", "lt", "lte", "gt", "gte",
             "eq_field", "ne_field")
PATH_OPS = ("writable", "readable", "creatable", "creatable_file", "unquoted_hijack")
REQUIRED = ("id", "title", "category", "severity", "select", "where", "why", "fix")
OPTIONAL = ("subject", "evidence", "refs")

_SEGMENT = re.compile(r"^([A-Za-z0-9_$]+)(\[\*\])?$")
_TEMPLATE = re.compile(r"\{([^{}]+)\}")


class RuleError(ValueError):
    pass


def default_rules_dir() -> Path:
    return Path(__file__).resolve().parent / "rules"


# --- loading and validation ---------------------------------------------------------------

def load_rules(rules_dir=None) -> List[dict]:
    """Rules from <dir>/<platform>/*.json; each loaded rule gets a 'platform' field."""
    d = Path(rules_dir) if rules_dir else default_rules_dir()
    files = [(plat, f) for plat in PLATFORMS for f in sorted((d / plat).glob("*.json"))]
    if not files:
        raise RuleError(f"no rule files in {d} (expected {' and '.join(PLATFORMS)} folders)")
    rules: List[dict] = []
    seen = set()
    for plat, f in files:
        name = f"{plat}/{f.name}"
        try:
            data = json.loads(f.read_text(encoding="utf-8-sig"))
        except json.JSONDecodeError as e:
            raise RuleError(f"{name}: invalid JSON: {e}") from None
        if not isinstance(data, dict) or not isinstance(data.get("rules"), list):
            raise RuleError(f'{name}: expected {{"rules": [...]}}')
        for rule in data["rules"]:
            validate_rule(rule, name)
            if rule["id"] in seen:
                raise RuleError(f"{name}: duplicate rule id {rule['id']}")
            seen.add(rule["id"])
            rules.append(dict(rule, platform=plat))
    return rules


def validate_rule(rule, where: str = "") -> None:
    if not isinstance(rule, dict):
        raise RuleError(f"{where}: rule must be an object")
    rid = rule.get("id", "?")
    ctx = f"{where}: {rid}"
    for k in REQUIRED:
        if k not in rule:
            raise RuleError(f"{ctx}: missing '{k}'")
    for k in rule:
        if k not in REQUIRED and k not in OPTIONAL:
            raise RuleError(f"{ctx}: unknown field '{k}'")
    for k in ("id", "title", "category", "why", "fix", "select"):
        if not isinstance(rule[k], str) or not rule[k].strip():
            raise RuleError(f"{ctx}: '{k}' must be a non-empty string")
    if rule["severity"] not in SEV_RANK:
        raise RuleError(f"{ctx}: severity must be one of {', '.join(SEVERITIES)}")
    parse_select(rule["select"], ctx)
    validate_cond(rule["where"], ctx)
    if "subject" in rule and not isinstance(rule["subject"], str):
        raise RuleError(f"{ctx}: 'subject' must be a string")
    ev = rule.get("evidence", {})
    if not isinstance(ev, dict) or not all(isinstance(v, str) for v in ev.values()):
        raise RuleError(f"{ctx}: 'evidence' must map labels to field paths")
    refs = rule.get("refs", [])
    if not isinstance(refs, list) or not all(isinstance(r, str) for r in refs):
        raise RuleError(f"{ctx}: 'refs' must be a list of strings")


def parse_select(sel: str, ctx: str = "") -> List[Tuple[str, bool]]:
    segs = []
    for part in sel.split("."):
        m = _SEGMENT.match(part)
        if not m:
            raise RuleError(f"{ctx}: bad select segment '{part}'")
        segs.append((m.group(1), m.group(2) is not None))
    return segs


def _is_num(v) -> bool:
    return isinstance(v, (int, float)) and not isinstance(v, bool)


def validate_cond(c, ctx: str) -> None:
    if not isinstance(c, dict) or not c:
        raise RuleError(f"{ctx}: condition must be a non-empty object")
    keys = set(c)
    for comb in ("all", "any"):
        if comb in keys:
            if keys != {comb} or not isinstance(c[comb], list) or not c[comb]:
                raise RuleError(f"{ctx}: '{comb}' needs a non-empty list and nothing else")
            for sub in c[comb]:
                validate_cond(sub, ctx)
            return
    if "not" in keys:
        if keys != {"not"}:
            raise RuleError(f"{ctx}: 'not' takes one condition and nothing else")
        validate_cond(c["not"], ctx)
        return
    path_ops = keys & set(PATH_OPS)
    if path_ops:
        op = path_ops.pop()
        if keys != {op} or not isinstance(c[op], str):
            raise RuleError(f"{ctx}: '{op}' takes a field path and nothing else")
        return
    if "field" not in keys or not isinstance(c["field"], str):
        raise RuleError(f"{ctx}: unknown condition {sorted(keys)}")
    ops = keys - {"field"}
    if len(ops) != 1 or not ops <= set(FIELD_OPS):
        raise RuleError(f"{ctx}: field test needs exactly one of {', '.join(FIELD_OPS)}")
    op = ops.pop()
    val = c[op]
    if op in ("in", "not_in") and not isinstance(val, list):
        raise RuleError(f"{ctx}: '{op}' needs a list")
    if op == "regex":
        if not isinstance(val, str):
            raise RuleError(f"{ctx}: 'regex' needs a string")
        try:
            re.compile(val)
        except re.error as e:
            raise RuleError(f"{ctx}: bad regex {val!r}: {e}") from None
    if op == "exists" and not isinstance(val, bool):
        raise RuleError(f"{ctx}: 'exists' needs true or false")
    if op in ("eq_field", "ne_field") and not isinstance(val, str):
        raise RuleError(f"{ctx}: '{op}' needs a field path")
    if op in ("lt", "lte", "gt", "gte") and not _is_num(val):
        raise RuleError(f"{ctx}: '{op}' needs a number")


# --- evaluation ---------------------------------------------------------------------------

class Ctx:
    __slots__ = ("item", "parent")

    def __init__(self, item, parent: Optional["Ctx"]):
        self.item = item
        self.parent = parent


def select(doc: dict, sel: str) -> List[Ctx]:
    ctxs = [Ctx(doc, None)]
    for name, star in parse_select(sel):
        nxt = []
        for c in ctxs:
            v = c.item.get(name) if isinstance(c.item, dict) else None
            if star:
                if isinstance(v, dict):
                    v = [v]
                if isinstance(v, list):
                    nxt.extend(Ctx(el, c) for el in v)
            elif v is not None:
                nxt.append(Ctx(v, c.parent))
        ctxs = nxt
    return [c for c in ctxs if isinstance(c.item, dict)]


def _walk(v, path: str):
    for part in path.split("."):
        if not isinstance(v, dict):
            return None
        v = v.get(part)
    return v


def resolve(ctx: Optional[Ctx], root: dict, path: str):
    if path.startswith("$root."):
        return _walk(root, path[6:])
    if path.startswith("$parent."):
        return resolve(ctx.parent, root, path[8:]) if ctx and ctx.parent else None
    return _walk(ctx.item, path) if ctx else None


def json_eq(a, b) -> bool:
    if isinstance(a, bool) or isinstance(b, bool):
        return isinstance(a, bool) and isinstance(b, bool) and a == b
    if _is_num(a) and _is_num(b):
        return a == b
    if a is None or b is None:
        return a is None and b is None
    if isinstance(a, str) and isinstance(b, str):
        return a == b
    return False


def fmt(v) -> str:
    if v is None:
        return ""
    if isinstance(v, bool):
        return "true" if v else "false"
    if isinstance(v, float) and v.is_integer():
        return str(int(v))
    if isinstance(v, (int, float, str)):
        return str(v)
    return json.dumps(v, separators=(",", ":"), ensure_ascii=False)


class Evaluator:
    def __init__(self, doc: dict, persp: Perspective):
        self.doc = doc
        self.persp = persp
        self.platform = persp.platform
        facts = doc.get("facts") if isinstance(doc.get("facts"), dict) else {}
        self.acls = AclIndex(facts.get("acls"), self.platform)
        self._regex: Dict[str, re.Pattern] = {}

    def _re(self, pattern: str) -> re.Pattern:
        r = self._regex.get(pattern)
        if r is None:
            r = self._regex[pattern] = re.compile(pattern, re.IGNORECASE)
        return r

    def evaluate(self, c: dict, ctx: Ctx) -> Tuple[bool, List[str]]:
        if "all" in c:
            notes: List[str] = []
            for sub in c["all"]:
                ok, n = self.evaluate(sub, ctx)
                if not ok:
                    return False, []
                notes.extend(n)
            return True, notes
        if "any" in c:
            hit = False
            notes = []
            for sub in c["any"]:
                ok, n = self.evaluate(sub, ctx)
                if ok:
                    hit = True
                    notes.extend(n)
            return hit, notes if hit else []
        if "not" in c:
            ok, _ = self.evaluate(c["not"], ctx)
            return (not ok), []
        for op in PATH_OPS:
            if op in c:
                return getattr(self, "_" + op)(resolve(ctx, self.doc, c[op]))
        return self._field(c, ctx), []

    def _field(self, c: dict, ctx: Ctx) -> bool:
        v = resolve(ctx, self.doc, c["field"])
        if "eq" in c:
            return json_eq(v, c["eq"])
        if "ne" in c:
            return not json_eq(v, c["ne"])
        if "in" in c:
            return any(json_eq(v, x) for x in c["in"])
        if "not_in" in c:
            return not any(json_eq(v, x) for x in c["not_in"])
        if "eq_field" in c:
            return json_eq(v, resolve(ctx, self.doc, c["eq_field"]))
        if "ne_field" in c:
            return not json_eq(v, resolve(ctx, self.doc, c["ne_field"]))
        if "regex" in c:
            return isinstance(v, str) and self._re(c["regex"]).search(v) is not None
        if "exists" in c:
            return (v is not None) == c["exists"]
        if not _is_num(v):
            return False
        if "lt" in c:
            return v < c["lt"]
        if "lte" in c:
            return v <= c["lte"]
        if "gt" in c:
            return v > c["gt"]
        if "gte" in c:
            return v >= c["gte"]
        return False

    # path tests -------------------------------------------------------------------------

    def _grant(self, path, kind: str) -> Tuple[bool, str, Optional[dict]]:
        """Access to `path` plus, on POSIX, search access to every folder above it for the
        same actor. Returns (ok, who, acl)."""
        acl = self.acls.get(path)
        ok, who, actor = access_check(acl, self.persp, kind)
        if ok and actor is not None:
            anc = parent(normalize(path, self.platform), self.platform)
            while anc:
                if not can_search(self.acls.get(anc), self.persp, actor):
                    return False, "", acl
                anc = parent(anc, self.platform)
        return ok, who, acl

    def _writable(self, path) -> Tuple[bool, List[str]]:
        ok, who, _ = self._grant(path, "write")
        return ok, [f"{path} is writable by {who}"] if ok else []

    def _readable(self, path) -> Tuple[bool, List[str]]:
        ok, who, _ = self._grant(path, "read")
        return ok, [f"{path} is readable by {who}"] if ok else []

    def _recorded_missing(self, path) -> Optional[str]:
        """Normalized path when facts.acls records it with exists false; otherwise None."""
        if not isinstance(path, str) or not path.strip():
            return None
        n = normalize(path, self.platform)
        acl = self.acls.get(n)
        if acl is None or acl.get("exists") is not False:
            return None
        return n

    def _folder_chain(self, shown, missing: str) -> Tuple[bool, List[str]]:
        """`missing` (normalized) doesn't exist: can its nearest existing ancestor get a new folder?"""
        anc = parent(missing, self.platform)
        while anc:
            a = self.acls.get(anc)
            if a is None:
                return False, []
            if a.get("exists") is True:
                ok, who, _ = self._grant(anc, "create_dir")
                if not ok:
                    return False, []
                return True, [f"{shown} does not exist; {a.get('path') or anc} lets {who} create folders"]
            anc = parent(anc, self.platform)
        return False, []

    def _creatable(self, path) -> Tuple[bool, List[str]]:
        n = self._recorded_missing(path)
        return self._folder_chain(path, n) if n else (False, [])

    def _creatable_file(self, path) -> Tuple[bool, List[str]]:
        n = self._recorded_missing(path)
        folder = parent(n, self.platform) if n else None
        if not folder:
            return False, []
        f = self.acls.get(folder)
        if f is None:
            return False, []
        if f.get("exists") is True:
            ok, who, _ = self._grant(folder, "write")
            if not ok:
                return False, []
            return True, [f"{path} does not exist; {f.get('path') or folder} lets {who} create files"]
        return self._folder_chain(path, folder)

    def _unquoted_hijack(self, path) -> Tuple[bool, List[str]]:
        if not isinstance(path, str) or " " not in path:
            return False, []
        notes: List[str] = []
        for i, ch in enumerate(path):
            if ch != " ":
                continue
            prefix = path[:i]
            if "\\" not in prefix or prefix.endswith("\\"):
                continue
            folder = parent(normalize(prefix, self.platform), self.platform)
            if not folder:
                continue
            ok, who, acl = self._grant(folder, "write")
            if ok:
                shown = acl.get("path") or folder
                note = f"Windows tries {prefix}.exe first; {shown} is writable by {who}"
                if note not in notes:
                    notes.append(note)
        return bool(notes), notes


def describe_perspective(doc: dict, persp: Perspective) -> str:
    p = doc.get("principal") if isinstance(doc.get("principal"), dict) else {}
    user = p.get("user") or "the collecting account"
    if persp.platform == "linux":
        if persp.mode == "standard-user":
            ran_as_root = " The collector ran as root, so its own rights were not used." \
                if p.get("is_admin") is True else ""
            return ("What any account other than root could reach (for files root runs, that "
                    f"includes their non-root owners and groups).{ran_as_root}")
        if p.get("is_admin") is True:
            return (f"What {user} can reach. That is root, so everything is reachable; "
                    "--perspective standard-user is usually more useful.")
        return f"What {user} can reach."
    if persp.mode == "standard-user":
        if p.get("is_admin") is True:
            return ("What any standard (non-admin) user could reach. The collector ran "
                    "elevated, so its own rights were not used.")
        return "What any standard (non-admin) user could reach."
    if p.get("is_admin") is True:
        return (f"What {user} can reach. The collector ran elevated, so nearly everything "
                "is reachable; --perspective standard-user is usually more useful.")
    if p.get("elevation") == "filtered_admin":
        return (f"What non-elevated code running as {user} can reach without a UAC prompt "
                "(the account is an administrator, so it can also elevate with one).")
    return f"What {user} can reach."


def source_info(doc: dict) -> dict:
    host = doc.get("host") if isinstance(doc.get("host"), dict) else {}
    run = doc.get("run") if isinstance(doc.get("run"), dict) else {}
    meta = doc.get("privscope") if isinstance(doc.get("privscope"), dict) else {}
    p = doc.get("principal") if isinstance(doc.get("principal"), dict) else {}
    build = host.get("version")
    if build and host.get("ubr") is not None:
        build = f"{build}.{host.get('ubr')}"
    return {
        "platform": doc_platform(doc),
        "hostname": host.get("hostname"),
        "os": host.get("caption"),
        "build": build,
        "display_version": host.get("display_version"),
        "collected_at": run.get("collected_at"),
        "collector_version": meta.get("version"),
        "user": p.get("user"),
        "elevation": p.get("elevation"),
        "integrity": p.get("integrity"),
    }


def analyze(doc: dict, rules: List[dict], perspective: str = "auto",
            min_severity: str = "info") -> dict:
    persp = build_perspective(doc, perspective)
    ev = Evaluator(doc, persp)
    rules = [r for r in rules if r.get("platform", "windows") == persp.platform]
    floor = SEV_RANK[min_severity]
    findings = []
    seen = set()
    for rule in rules:
        if SEV_RANK[rule["severity"]] < floor:
            continue
        for ctx in select(doc, rule["select"]):
            ok, notes = ev.evaluate(rule["where"], ctx)
            if not ok:
                continue
            subject = _TEMPLATE.sub(lambda m: fmt(resolve(ctx, doc, m.group(1))),
                                    rule.get("subject", ""))
            key = f"{rule['id']}|{subject}"
            if key in seen:
                continue
            seen.add(key)
            uniq_notes: List[str] = []
            for n in notes:
                if n not in uniq_notes:
                    uniq_notes.append(n)
            findings.append({
                "rule": rule["id"],
                "title": rule["title"],
                "severity": rule["severity"],
                "category": rule["category"],
                "subject": subject,
                "key": key,
                "evidence": {label: resolve(ctx, doc, path)
                             for label, path in (rule.get("evidence") or {}).items()},
                "notes": uniq_notes,
                "why": rule["why"],
                "fix": rule["fix"],
                "refs": list(rule.get("refs") or []),
            })
    findings.sort(key=lambda f: (-SEV_RANK[f["severity"]], f["rule"], f["subject"]))
    summary = {s: 0 for s in reversed(SEVERITIES)}
    for f in findings:
        summary[f["severity"]] += 1
    summary["total"] = len(findings)
    return {
        "privscope": {"tool": "privscope-analyzer", "version": __version__, "kind": "report"},
        "source": source_info(doc),
        "perspective": {"mode": persp.mode, "description": describe_perspective(doc, persp)},
        "rules_evaluated": len(rules),
        "min_severity": min_severity,
        "acl_entries": len(ev.acls),
        "summary": summary,
        "findings": findings,
    }


def diff_reports(old: dict, new: dict) -> dict:
    old_by = {f["key"]: f for f in old["findings"]}
    new_by = {f["key"]: f for f in new["findings"]}
    warnings = []
    oh, nh = old["source"].get("hostname"), new["source"].get("hostname")
    if oh and nh and oh.lower() != nh.lower():
        warnings.append(f"comparing different hosts: {oh} vs {nh}")
    if old["perspective"]["mode"] != new["perspective"]["mode"]:
        warnings.append(
            f"the runs were analyzed from different perspectives ({old['perspective']['mode']} "
            f"vs {new['perspective']['mode']}); pass --perspective to compare like with like")
    added = [f for f in new["findings"] if f["key"] not in old_by]
    resolved = [f for f in old["findings"] if f["key"] not in new_by]
    unchanged = [f for f in new["findings"] if f["key"] in old_by]
    return {
        "privscope": {"tool": "privscope-analyzer", "version": __version__, "kind": "diff"},
        "old": old["source"],
        "new": new["source"],
        "perspective": new["perspective"],
        "min_severity": new["min_severity"],
        "warnings": warnings,
        "summary": {"new": len(added), "resolved": len(resolved), "unchanged": len(unchanged)},
        "new_findings": added,
        "resolved_findings": resolved,
        "unchanged_findings": unchanged,
    }
