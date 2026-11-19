# privscope detection-test packs

`privscope attack` turns a collection's findings into a self-contained **detection-test
script** for the host it came from: bash for a Linux collection, PowerShell for a Windows
one. The script performs the real local privilege-escalation techniques behind the findings,
so you can see whether that host's IDS/IPS, EDR or audit rules catch them.

This is the one active part of privscope. The collector and analyzer never touch it, stay
read-only, and never run a technique. Generation happens offline on your machine; the script
is a reviewable artifact you read before it runs anywhere.

> **Authorized testing only.** These scripts actually escalate to root or SYSTEM. Run them
> only on systems you own or are explicitly permitted to assess.

## Use it

```
privscope attack collection.json -o pack.sh        # from a Linux collection
privscope attack collection.json -o pack.ps1       # from a Windows collection
```

Then on the target, after reviewing the script:

```
# Linux
./pack.sh                       # dry run: list the tests, change nothing
sudo sh -c 'echo "engagement X, authorized <date>" > /etc/privscope-authorized'
./pack.sh --execute             # detonate; --only 3,5 and --wait N also available

# Windows (elevated PowerShell)
.\pack.ps1                      # dry run
Set-Content C:\privscope-authorized.txt "engagement X, authorized <date>"
.\pack.ps1 -Execute
```

**Run the pack as the unprivileged account whose findings you're testing, not as root or
full admin.** The point is to escalate *up* from that account; as root or SYSTEM there's
nothing to prove, and the detection you care about never gets exercised. Collect high (root
sees the most) but test low. The one step that needs elevation is placing the authorization
marker once; the tests themselves run as the low-privilege user.

## The gate

A generated script is **dry-run by default**: with no arguments it lists its tests and
changes nothing. It detonates only when all three hold:

1. you pass `--execute` (`-Execute`);
2. an authorization marker exists — `/etc/privscope-authorized`, or `C:\privscope-authorized.txt`,
   or the path in `$PRIVSCOPE_AUTHORIZED`. You place this on each host you are cleared to
   test; its contents (scope, date) are echoed into the run log;
3. the host's name matches the collection's. `--force-host` / `-ForceHost` overrides this
   for throwaway lab hosts whose name differs.

## What each test does

- Performs the technique with a **benign end action**: it proves the elevated context with
  `id` / `whoami` into a marker file and the run log, and does nothing else as root.
- **Backs up anything it modifies and restores it** on exit (including on Ctrl-C), via a
  cleanup trap. No new accounts, no persistence, no exfiltration, no cracking of hashes.
- **No evasion.** No obfuscation, no AMSI/ETW tampering. The point is to be seen.
- Logs one JSON object per step to `<testroot>/run-<id>.jsonl` with a run-wide correlation
  id, the MITRE ATT&CK technique, a UTC timestamp, a status and a detail. Line your
  detections up against these. Default test root: `/tmp/privscope-test` or
  `C:\privscope-test` (`$PRIVSCOPE_TESTROOT` to change).

Status values: `started`, `telemetry` (a detectable action was taken), `success` (reached
root/SYSTEM, proof captured), `no_escalation` (ran but the context didn't elevate, e.g. a
scheduled trigger that didn't fire in the wait window), `planted` (dropped a payload whose
trigger is out of band, such as a logon or a cron tick), `skipped` (a prerequisite like a
compiler was missing). A test never claims success without a captured `id`/`whoami` proof.

## Techniques

Each maps to one or more rule ids, so a test is generated only for a finding that actually
fired. Linux lives in `privscope/redteam/generate.py` under `LINUX`, Windows under `WINDOWS`.

| Script id | ATT&CK | Rules | What it does |
|---|---|---|---|
| LIN-SUID-SHELL | T1548.001 | PL-SUID-002 | Run a command through a setuid-root shell-capable binary |
| LIN-SUID-WRITABLE | T1548.001 | PL-SUID-001 | Overwrite a writable setuid-root binary (needs a compiler) |
| LIN-CAP-SETUID | T1548.001 | PL-CAP-001 | Drop to uid 0 through a cap_setuid interpreter |
| LIN-SUDO-ALL | T1548.003 | PL-SUDO-001 | `sudo -n id` under passwordless-to-anything |
| LIN-SUDO-SHELL | T1548.003 | PL-SUDO-002 | Run a command via a passwordless-sudo shell-capable program |
| LIN-SUDO-LDPRELOAD | T1548.003 | PL-SUDO-005 | Load a library into a sudo-run command (needs a compiler) |
| LIN-CRON-WRITABLE | T1053.003 | PL-CRON-001 | Append a root-proof line to a writable root cron program |
| LIN-LDPRELOAD-FILE | T1574.006 | PL-FILE-003 | Write a library path into a writable /etc/ld.so.preload |
| LIN-DOCKER-SOCK | T1611 | PL-SOCK-001 | Launch a host-root container through a writable engine socket |
| LIN-PATH-WRITABLE | T1574.007 | PL-PATH-001 | Plant a command in a writable root PATH dir |
| LIN-SHADOW-READ | T1003.008 | PL-FILE-002 | Read a readable shadow file (counts only; contents not stored) |
| WIN-SERVICE-BIN | T1574.010 | PS-SVC-001 | Overwrite a writable service binary, restart, prove, restore |
| WIN-UNQUOTED | T1574.009 | PS-SVC-003 | Plant a payload at an unquoted service path's hijack point |
| WIN-SERVICE-DLL | T1574.001 | PS-SVC-002 | Drop a DLL in a writable service directory |
| WIN-TASK-BIN | T1053.005 | PS-TASK-001 | Overwrite a privileged task's program, run it, prove, restore |
| WIN-AUTORUN | T1547.001 | PS-AUTO-001 | Overwrite a machine-wide logon program (fires next logon) |
| WIN-AIE-MSI | T1548.002 | PS-POL-001 | Run a benign MSI under AlwaysInstallElevated |
| WIN-HOOK-TARGET | T1546 | PS-HOOK-001..006 | Overwrite the file a registry execution hook (IFEO, AppInit, Winlogon, Active Setup, LSA/print/netsh) points at |
| WIN-REGKEY-SERVICE | T1574.011 | PS-REGK-001 | Redirect a service's ImagePath through its writable registry key |

The Linux set is validated end to end against `tests/lab/` (a deliberately misconfigured
container): the pack reaches real root and then restores every change. The Windows set is
authored against real findings and parses, but is not detonated in CI — run it on your own
test VMs.
