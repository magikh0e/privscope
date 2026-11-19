"""End-to-end check of the Linux collector and rules against the misconfigured lab container.

Needs Docker. Builds tests/lab/Dockerfile, runs the collector inside it as alice and as root
(the collector is mounted read-only, not baked into the image), analyzes both collections and
compares the finding keys with tests/lab/expected-<user>.txt. Exit code 0 means they match.

    python tests/lab/run_lab.py
"""
from __future__ import annotations

import json
import shutil
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
LAB = Path(__file__).resolve().parent
OUT = ROOT / "reports" / "lab"          # git-ignored
sys.path.insert(0, str(ROOT))

from privscope.engine import analyze, load_rules  # noqa: E402


def docker(*args: str) -> None:
    subprocess.run(["docker", *args], check=True, capture_output=True, text=True)


def main() -> int:
    if shutil.which("docker") is None:
        print("docker not found")
        return 2
    docker("build", "-q", "-t", "privscope-lab", str(LAB))
    OUT.mkdir(parents=True, exist_ok=True)
    rules = load_rules()
    failed = False
    for user in ("alice", "root"):
        docker("run", "--rm", "-u", user,
               "-v", f"{ROOT / 'collector'}:/privscope:ro", "-v", f"{OUT}:/out",
               "privscope-lab", "sh", "/privscope/privscope-collect.sh", "-o", f"/out/{user}.json")
        doc = json.loads((OUT / f"{user}.json").read_text(encoding="utf-8"))
        got = {f["key"] for f in analyze(doc, rules)["findings"]}
        want = {line.strip() for line in (LAB / f"expected-{user}.txt").read_text(encoding="utf-8-sig").splitlines()
                if line.strip()}
        missing, extra = sorted(want - got), sorted(got - want)
        status = "ok" if not missing and not extra else "MISMATCH"
        print(f"{user:6} {status}: {len(got)} findings, {len(want)} expected")
        for k in missing:
            print(f"   missing: {k}")
        for k in extra:
            print(f"   extra:   {k}")
        failed |= bool(missing or extra)
    shutil.rmtree(OUT, ignore_errors=True)
    return 1 if failed else 0


if __name__ == "__main__":
    raise SystemExit(main())
