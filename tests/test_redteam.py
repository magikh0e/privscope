import json
import unittest
from pathlib import Path

from privscope import cli
from privscope.engine import analyze, load_rules
from privscope.redteam import build_script, techniques_for
from privscope.redteam.generate import LINUX, WINDOWS

RULES = load_rules()
RULE_IDS = {r["id"] for r in RULES}
CONF = Path(__file__).parent / "conformance"


def collection(name):
    return json.loads((CONF / name).read_text(encoding="utf-8"))["collection"]


def report_for(name):
    return analyze(collection(name), RULES)


class Mapping(unittest.TestCase):
    def test_every_technique_targets_real_rules(self):
        for t in LINUX + WINDOWS:
            for rid in t.rules:
                self.assertIn(rid, RULE_IDS, f"{t.id} maps to unknown rule {rid}")

    def test_technique_ids_unique(self):
        ids = [t.id for t in LINUX + WINDOWS]
        self.assertEqual(len(ids), len(set(ids)))

    def test_selection_only_for_present_findings(self):
        rep = report_for("linux-account.json")
        fired = {f["rule"] for f in rep["findings"]}
        for s in techniques_for(rep, "linux"):
            self.assertTrue(s["technique"].rules & fired)


class LinuxScript(unittest.TestCase):
    def setUp(self):
        self.doc = collection("linux-account.json")
        self.rep = analyze(self.doc, RULES)
        self.script = build_script(self.doc, self.rep, "linux")

    def test_is_gated_and_dry_run_by_default(self):
        self.assertTrue(self.script.startswith("#!/bin/bash"))
        self.assertIn("AUTHORIZED TESTING ONLY", self.script)
        self.assertIn('if [ "$EXECUTE" != 1 ]; then pf_list; exit 0; fi', self.script)
        self.assertIn("REFUSED: authorization marker", self.script)
        self.assertIn("hostname", self.script)

    def test_has_expected_techniques(self):
        sel = {s["technique"].id for s in techniques_for(self.rep, "linux")}
        self.assertIn("LIN-SUDO-SHELL", sel)       # alice has NOPASSWD find
        self.assertIn("LIN-DOCKER-SOCK", sel)      # alice in docker, writable sock
        for tid in sel:
            self.assertIn(tid, self.script)

    def test_cleanup_and_proof_present(self):
        self.assertIn("trap pf_cleanup EXIT", self.script)
        self.assertIn("uid=0", self.script)        # the proof check
        self.assertNotIn("\r\n", self.script)      # LF only


class WindowsScript(unittest.TestCase):
    def setUp(self):
        self.doc = collection("services.json")
        self.rep = analyze(self.doc, RULES)
        self.script = build_script(self.doc, self.rep, "windows")

    def test_is_gated_and_dry_run_by_default(self):
        self.assertIn("AUTHORIZED TESTING ONLY", self.script)
        self.assertIn("if (-not $Execute)", self.script)
        self.assertIn("REFUSED: authorization marker", self.script)

    def test_has_service_technique(self):
        sel = {s["technique"].id for s in techniques_for(self.rep, "windows")}
        self.assertIn("WIN-SERVICE-BIN", sel)
        self.assertIn("WIN-SERVICE-BIN", self.script)


class EmptyAndCli(unittest.TestCase):
    def test_no_findings_no_tests(self):
        doc = {"privscope": {"kind": "collection", "platform": "linux"},
               "principal": {"uid": 1000, "groups": []}, "facts": {}}
        script = build_script(doc, analyze(doc, RULES), "linux")
        self.assertIn("(no applicable findings)", script)
        self.assertIn("(none)", script)

    def test_attack_cli_writes_gated_script(self, ):
        import tempfile
        with tempfile.TemporaryDirectory() as d:
            src = Path(d) / "c.json"
            src.write_text(json.dumps(collection("linux-account.json")), encoding="utf-8")
            out = Path(d) / "pack.sh"
            self.assertEqual(cli.main(["attack", str(src), "-o", str(out)]), 0)
            text = out.read_text(encoding="utf-8")
            self.assertIn("AUTHORIZED TESTING ONLY", text)
            self.assertNotIn("\r\n", text)         # bash stays LF


if __name__ == "__main__":
    unittest.main()
