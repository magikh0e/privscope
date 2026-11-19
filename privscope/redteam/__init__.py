"""privscope redteam: generate gated, reversible detection-test scripts from findings.

This subpackage is the one active part of privscope. The collector and analyzer never
touch it, stay read-only, and never run a technique. `privscope attack` reads a collection,
runs the analyzer to see which findings are real, and emits a self-contained test script
(bash for a Linux host, PowerShell for Windows) that a human reviews and runs on an
in-scope target to see whether its host-based IDS/IPS catches the activity.

Every generated test is:
  * dry-run by default; it detonates only with --execute AND an on-host authorization
    marker AND a hostname match,
  * reversible: it backs up what it touches, proves the elevated context with id/whoami,
    then restores and cleans up (no new accounts, no persistence, no exfiltration),
  * tagged with a correlation id, a MITRE ATT&CK technique and a timestamp, logged to a run
    file so the operator can line each action up against their detections,
  * free of evasion or obfuscation. The goal is to be detected.

For authorized testing of systems you own or are explicitly permitted to assess.
"""

from .generate import build_script, techniques_for

__all__ = ["build_script", "techniques_for"]
