"""Shared conformance cases (tests/conformance/*.json). The browser engine runs the same files."""
import json
import unittest
from pathlib import Path

from privscope.engine import analyze, load_rules

CASES = sorted((Path(__file__).parent / "conformance").glob("*.json"))
RULES = load_rules()


def _load(path: Path) -> dict:
    return json.loads(path.read_text(encoding="utf-8"))


class Conformance(unittest.TestCase):
    def test_cases_exist(self):
        self.assertTrue(CASES, "no conformance cases found")

    def test_cases(self):
        for case_file in CASES:
            case = _load(case_file)
            for run in case["runs"]:
                with self.subTest(case=case_file.stem, perspective=run["perspective"]):
                    report = analyze(case["collection"], RULES, run["perspective"])
                    got = sorted(f["key"] for f in report["findings"])
                    self.assertEqual(got, sorted(run["expect"]))

    def test_every_rule_has_a_positive_case(self):
        covered = set()
        for case_file in CASES:
            for run in _load(case_file)["runs"]:
                covered.update(key.split("|", 1)[0] for key in run["expect"])
        missing = sorted({r["id"] for r in RULES} - covered)
        self.assertEqual(missing, [], "rules with no conformance case expecting them")


if __name__ == "__main__":
    unittest.main()
