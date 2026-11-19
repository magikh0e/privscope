import copy
import json
import tempfile
import unittest
from pathlib import Path

from privscope import cli
from privscope.engine import (
    RuleError, analyze, diff_reports, fmt, json_eq, load_rules, select, validate_rule,
)
from privscope.html_report import render_diff_html, render_html
from privscope.report import render_diff_markdown, render_diff_text, render_markdown, render_text

GOOD = {
    "id": "PS-T-001", "title": "t", "category": "c", "severity": "low",
    "select": "facts.things[*]", "where": {"field": "x", "eq": 1}, "why": "w", "fix": "f",
}
CASE = Path(__file__).parent / "conformance" / "services.json"


def rule(**changes):
    r = copy.deepcopy(GOOD)
    r.update(changes)
    return r


class Validation(unittest.TestCase):
    def test_good(self):
        validate_rule(GOOD)

    def test_rejects(self):
        bad = [
            rule(severity="severe"),
            rule(extra=1),
            rule(select="facts.things[0]"),
            rule(where={"field": "x", "eq": 1, "ne": 2}),
            rule(where={"field": "x", "like": 1}),
            rule(where={"field": "x", "regex": "("}),
            rule(where={"field": "x", "lt": True}),
            rule(where={"field": "x", "exists": "yes"}),
            rule(where={"all": []}),
            rule(where={"writable": "p", "field": "x"}),
            rule(evidence={"a": 1}),
        ]
        for r in bad:
            with self.subTest(r=r):
                with self.assertRaises(RuleError):
                    validate_rule(r)
        no_fix = rule()
        del no_fix["fix"]
        with self.assertRaises(RuleError):
            validate_rule(no_fix)

    def test_bundled_rules_load(self):
        rules = load_rules()
        self.assertGreaterEqual(len(rules), 28)
        self.assertEqual(len({r["id"] for r in rules}), len(rules))


class Semantics(unittest.TestCase):
    def test_json_eq(self):
        self.assertFalse(json_eq(True, 1))
        self.assertFalse(json_eq(1, True))
        self.assertTrue(json_eq(1, 1.0))
        self.assertTrue(json_eq(None, None))
        self.assertFalse(json_eq(None, 0))
        self.assertFalse(json_eq([1], [1]))

    def test_fmt(self):
        self.assertEqual(fmt(None), "")
        self.assertEqual(fmt(True), "true")
        self.assertEqual(fmt(2.0), "2")
        self.assertEqual(fmt(2.5), "2.5")

    def test_select_single_object_as_array(self):
        doc = {"facts": {"things": {"x": 1}}}
        self.assertEqual(len(select(doc, "facts.things[*]")), 1)

    def test_select_skips_non_objects(self):
        doc = {"facts": {"things": [1, None, "s", {"x": 1}]}}
        self.assertEqual(len(select(doc, "facts.things[*]")), 1)

    def test_min_severity(self):
        doc = json.loads(CASE.read_text(encoding="utf-8"))["collection"]
        report = analyze(doc, load_rules(), min_severity="high")
        self.assertTrue(report["findings"])
        self.assertNotIn("PS-SVC-004", {f["rule"] for f in report["findings"]})

    def test_notes_name_the_grant(self):
        doc = json.loads(CASE.read_text(encoding="utf-8"))["collection"]
        report = analyze(doc, load_rules())
        f = next(f for f in report["findings"] if f["key"] == "PS-SVC-003|Unquoted")
        self.assertIn("C:\\Program Files\\Acme.exe", f["notes"][0])
        self.assertIn("BUILTIN\\Users", f["notes"][0])


class Diff(unittest.TestCase):
    def test_new_and_resolved(self):
        rules = load_rules()
        doc = json.loads(CASE.read_text(encoding="utf-8"))["collection"]
        fixed = copy.deepcopy(doc)
        fixed["facts"]["acls"]["c:\\apps\\bin\\svc.exe"]["aces"].pop()  # drop Users: Modify
        fixed["facts"]["services"].append(
            {"name": "NewOne", "path_name_raw": "X:\\New Dir\\n.exe", "image_path": "X:\\New Dir\\n.exe"})
        d = diff_reports(analyze(doc, rules), analyze(fixed, rules))
        self.assertEqual([f["key"] for f in d["resolved_findings"]], ["PS-SVC-001|WritableBin"])
        self.assertEqual([f["key"] for f in d["new_findings"]], ["PS-SVC-004|NewOne"])
        self.assertEqual(d["warnings"], [])


class Rendering(unittest.TestCase):
    def test_renderers(self):
        rules = load_rules()
        doc = json.loads(CASE.read_text(encoding="utf-8"))["collection"]
        report = analyze(doc, rules)
        for text in (render_text(report), render_text(report, color=True, full=False),
                     render_markdown(report)):
            self.assertIn("PS-SVC-003", text)
        d = diff_reports(report, report)
        self.assertIn("unchanged", render_diff_text(d))
        self.assertIn("Unchanged", render_diff_markdown(d))

    def test_html_is_locked_down_and_escaped(self):
        rules = load_rules()
        doc = json.loads(CASE.read_text(encoding="utf-8"))["collection"]
        hostile = '<img src=x onerror=alert(1)>"\'&'
        doc["facts"]["services"][0]["name"] = hostile  # WritableBin -> a finding subject
        doc["host"] = {"hostname": "<b>HOST</b>", "caption": "Windows </style><script>x()</script>"}
        report = analyze(doc, rules)
        out = render_html(report)
        self.assertTrue(out.startswith("<!doctype html>"))
        self.assertIn("Content-Security-Policy", out)
        self.assertIn("default-src 'none'", out)
        self.assertNotIn("<script", out)
        self.assertNotIn("<img", out)
        self.assertNotIn("<b>HOST", out)
        self.assertIn("&lt;img src=x onerror=alert(1)&gt;&quot;&#x27;&amp;", out)
        self.assertIn("PS-SVC-003", out)
        self.assertIn('id="show-high"', out)

        fixed = copy.deepcopy(doc)
        fixed["facts"]["services"] = fixed["facts"]["services"][1:]
        d = diff_reports(report, analyze(fixed, rules))
        dout = render_diff_html(d)
        self.assertIn("Resolved", dout)
        self.assertNotIn("<img", dout)
        self.assertIn("Nothing changed", render_diff_html(diff_reports(report, report)))

    def test_html_empty_report(self):
        report = analyze({"privscope": {"kind": "collection"}}, load_rules())
        self.assertIn("No findings", render_html(report))


class Cli(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.dir = Path(self.tmp.name)
        self.doc = json.loads(CASE.read_text(encoding="utf-8"))["collection"]

    def tearDown(self):
        self.tmp.cleanup()

    def _write(self, name, data: bytes) -> str:
        p = self.dir / name
        p.write_bytes(data)
        return str(p)

    def test_encodings(self):
        text = json.dumps(self.doc)
        for name, data in (("utf8.json", text.encode("utf-8")),
                           ("bom.json", b"\xef\xbb\xbf" + text.encode("utf-8")),
                           ("utf16.json", text.encode("utf-16"))):
            with self.subTest(name=name):
                self.assertEqual(cli.load_collection(self._write(name, data))["facts"].keys(),
                                 self.doc["facts"].keys())

    def test_rejects_non_collection(self):
        with self.assertRaises(cli.InputError):
            cli.load_collection(self._write("x.json", b'{"hello": 1}'))
        with self.assertRaises(cli.InputError):
            cli.load_collection(self._write("bad.json", b"{nope"))

    def test_fail_on_and_output(self):
        src = self._write("c.json", json.dumps(self.doc).encode("utf-8"))
        out = str(self.dir / "r.md")
        self.assertEqual(cli.main(["analyze", src, "--format", "md", "-o", out]), 0)
        self.assertIn("PS-SVC-001", Path(out).read_text(encoding="utf-8"))
        self.assertEqual(cli.main(["analyze", src, "--fail-on", "high", "-o", out]), 3)
        self.assertEqual(cli.main(["diff", src, src, "--fail-on", "low", "-o", out]), 0)
        self.assertEqual(cli.main(["analyze", str(self.dir / "missing.json")]), 1)


if __name__ == "__main__":
    unittest.main()
