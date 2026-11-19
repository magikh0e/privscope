#!/bin/sh
# privscope collector for Linux: read-only privilege-escalation audit fact collector.
#
# Gathers configuration FACTS relevant to local privilege-escalation hardening and writes
# them to a JSON document for offline analysis by the privscope analyzer.
#
# This script is READ-ONLY by design:
#   * It reads files, file metadata (stat) and the output of id, uname, find, getcap and
#     sudo -n -l. It writes nothing but its own temporary folder (removed on exit) and the
#     output file. It never changes permissions and never starts or stops anything.
#   * It makes NO exploitation attempts and NO vulnerability judgments: it records modes,
#     owners and the account's ids, and the analyzer decides what is writable.
#   * It NEVER reads secret-bearing files (shadow, SSH keys, credential files, shell
#     history). For those it records presence and file metadata only.
#   * sudo -n -l never prompts for a password, but sudo logs the query and, for accounts
#     that aren't in sudoers, may mail the administrator. --no-sudo skips it.
#
# Needs only POSIX sh, awk, find and stat, so it runs on GNU/Linux and BusyBox systems with
# nothing installed. For systems you own or are explicitly authorized to assess.
#
# Usage: sh privscope-collect.sh [-o FILE] [--no-sudo] [--stdout]
#   -o FILE    write the collection here (default: ./privscope-<host>-<timestamp>.json)
#   --no-sudo  don't run sudo -n -l
#   --stdout   also print the JSON to standard output
#
# privscope collector v0.1.0 - detect-and-report only.

set -u
umask 077
LC_ALL=C
export LC_ALL
VERSION=0.1.0
OUT=
DO_SUDO=1
TO_STDOUT=0

while [ $# -gt 0 ]; do
  case $1 in
    -o|--output)
      [ $# -ge 2 ] || { echo "privscope: $1 needs a file name" >&2; exit 2; }
      OUT=$2; shift ;;
    --no-sudo) DO_SUDO=0 ;;
    --stdout) TO_STDOUT=1 ;;
    -h|--help) awk 'NR > 1 && /^#/ { sub(/^# ?/, ""); print; next } NR > 1 { exit }' "$0"; exit 0 ;;
    *) echo "privscope: unknown option: $1 (see --help)" >&2; exit 2 ;;
  esac
  shift
done

START=$(date +%s 2>/dev/null || echo 0)
TMP=$(mktemp -d 2>/dev/null) || TMP=$(mktemp -d -t privscope.XXXXXX 2>/dev/null) || {
  echo "privscope: can't create a temporary folder" >&2; exit 1; }
trap 'rm -rf "$TMP"' EXIT
trap 'exit 130' INT TERM
US=$(printf '\037')
for f in kv groups sudo sudo_defaults suid caps cron cronpath systemd boot pathdirs sensitive \
         exports lddirs ldpreload sockets creds want stat; do
  : > "$TMP/$f"
done

# --- helpers ------------------------------------------------------------------------------

rec() {  # rec SECTION FIELD... : one record per line, fields joined by the unit separator
  _f=$1; shift
  _line=$1; shift
  for _v in "$@"; do _line="$_line$US$_v"; done
  printf '%s\n' "$_line" >> "$TMP/$_f"
}
kv() { rec kv "$1" "$2" "$3" "$4"; }                    # kv OBJECT KEY TYPE(s|z|n|b) VALUE
want() { case $1 in /*) printf '%s\n' "$1" >> "$TMP/want" ;; esac; }   # stat this path later
addpath() {  # addpath SCOPE PATH-VALUE : one record per PATH entry, empty entries kept
  printf '%s\n' "$2" | tr ':' '\n' | while IFS= read -r _d; do
    rec pathdirs "$1" "$_d"; want "$_d"
  done
}
osr() {
  [ -r /etc/os-release ] || return 0
  awk -v k="$1" -v q="'" 'index($0, k "=") == 1 {
    v = substr($0, length(k) + 2); gsub(/^"|"$/, "", v); gsub("^" q "|" q "$", "", v); print v; exit }' /etc/os-release
}

# --- run, host, account -------------------------------------------------------------------

kv run collected_at s "$(date -u +%Y-%m-%dT%H:%M:%SZ 2>/dev/null)"
kv run collector_user s "$(id -un 2>/dev/null)"

kv host hostname s "$(uname -n 2>/dev/null)"
kv host caption z "$(osr PRETTY_NAME)"
kv host os_id z "$(osr ID)"
kv host os_version_id z "$(osr VERSION_ID)"
kv host version z "$(uname -r 2>/dev/null)"
kv host kernel_build z "$(uname -v 2>/dev/null)"
kv host architecture z "$(uname -m 2>/dev/null)"
ctr=
if [ -f /.dockerenv ]; then ctr=docker
elif [ -f /run/.containerenv ]; then ctr=podman
elif grep -qE 'docker|kubepods|containerd|lxc' /proc/1/cgroup 2>/dev/null; then ctr=container
fi
kv host container z "$ctr"
wsl=false
grep -qi microsoft /proc/sys/kernel/osrelease 2>/dev/null && wsl=true
kv host wsl b "$wsl"
winpath=false                                  # WSL appends the Windows PATH (appendWindowsPath)
if [ "$wsl" = true ]; then case ":${PATH:-}:" in *:/mnt/[a-z]/*) winpath=true ;; esac; fi
kv host wsl_windows_path b "$winpath"

MYUID=$(id -u 2>/dev/null)
kv principal user s "$(id -un 2>/dev/null || echo "$MYUID")"
kv principal uid n "$MYUID"
kv principal gid n "$(id -g 2>/dev/null)"
if [ "$MYUID" = 0 ]; then
  kv principal is_admin b true; kv principal elevation s root
else
  kv principal is_admin b false; kv principal elevation s standard
fi
gnames=$(id -Gn 2>/dev/null)
i=0
for g in $(id -G 2>/dev/null); do
  i=$((i + 1))
  rec groups "$g" "$(printf '%s\n' "$gnames" | awk -v i="$i" '{ print $i }')"
done

# --- sudo ---------------------------------------------------------------------------------

cat > "$TMP/sudo.awk" <<'EOF'
function trim(s) { sub(/^[ \t]+/, "", s); sub(/[ \t]+$/, "", s); return s }
function emit(who, src, spec, raw,   runas, nop, n, parts, i, c, tok, name, tag, k) {
  runas = ""
  spec = trim(spec)
  if (substr(spec, 1, 1) == "(") {
    k = index(spec, ")")
    if (k > 0) { runas = substr(spec, 2, k - 2); spec = trim(substr(spec, k + 1)) }
  }
  nop = 0
  n = split(spec, parts, ",")
  for (i = 1; i <= n; i++) {
    c = trim(parts[i])
    while (match(c, /^[A-Z_]+:/)) {
      tag = substr(c, 1, RLENGTH - 1)
      if (tag == "NOPASSWD") nop = 1
      else if (tag == "PASSWD") nop = 0
      c = trim(substr(c, RLENGTH + 1))
    }
    if (c == "") continue
    tok = c; sub(/[ \t].*$/, "", tok)
    name = tok; sub(/^.*\//, "", name)
    print who US src US runas US nop US c US tok US name US raw >> (T "/sudo")
  }
}
function defaults(src, line,   n, d, i) {
  n = split(line, d, ",")
  for (i = 1; i <= n; i++) if (trim(d[i]) != "") print src US trim(d[i]) >> (T "/sudo_defaults")
}
mode == "list" {
  if ($0 ~ /^Matching Defaults entries/) { sec = "def"; next }
  if ($0 ~ /^User .* may run the following commands/) { sec = "cmd"; next }
  if ($0 ~ /^[^ \t]/) { sec = ""; next }
  line = trim($0)
  if (line == "") next
  if (sec == "def") defaults(src, line)
  else if (sec == "cmd") emit("(this account)", src, line, line)
  next
}
mode == "file" {
  line = $0
  while (line ~ /\\$/ && (getline more) > 0) { sub(/\\$/, "", line); line = line " " more }
  line = trim(line)
  if (line == "" || line ~ /^#/ || line ~ /^@/) next
  if (line ~ /^Defaults/) { sub(/^Defaults[^ \t]*[ \t]+/, "", line); defaults(src, line); next }
  if (line ~ /^(User|Runas|Host|Cmnd|Cmd)_Alias/) next
  who = line; sub(/[ \t].*$/, "", who)
  k = index(line, "=")
  if (k > 0) emit(who, src, substr(line, k + 1), line)
}
EOF

SUDO_STATUS=skipped
if [ "$DO_SUDO" = 1 ]; then
  if ! command -v sudo >/dev/null 2>&1; then SUDO_STATUS=not_installed
  elif sudo -n -l > "$TMP/sudo_l" 2> "$TMP/sudo_err" < /dev/null; then SUDO_STATUS=listed
  elif grep -qi 'password' "$TMP/sudo_err"; then SUDO_STATUS=password_required
  elif grep -qiE 'may not run|not allowed|not in the sudoers' "$TMP/sudo_err" "$TMP/sudo_l"; then SUDO_STATUS=not_allowed
  else SUDO_STATUS=failed
  fi
fi
kv run sudo_status s "$SUDO_STATUS"
if [ "$SUDO_STATUS" = listed ]; then
  awk -v US="$US" -v T="$TMP" -v mode=list -v src="sudo -n -l" -f "$TMP/sudo.awk" "$TMP/sudo_l"
fi
for f in /etc/sudoers /etc/sudoers.d/*; do            # readable only when run as root
  [ -f "$f" ] && [ -r "$f" ] || continue
  case $f in /etc/sudoers.d/*.*|/etc/sudoers.d/*~) continue ;; esac   # sudo skips these too
  awk -v US="$US" -v T="$TMP" -v mode=file -v src="$f" -f "$TMP/sudo.awk" "$f"
done

# --- setuid / setgid programs and file capabilities ---------------------------------------

set -f
PRUNE="-path /proc -o -path /sys -o -path /dev -o -path /run -o -path /var/lib/docker -o -path /var/lib/containers -o -path /var/lib/lxd -o -path /var/lib/lxc -o -path /snap"
for root in / /usr /usr/local /opt /home /var /srv /boot; do
  [ -d "$root" ] && [ ! -L "$root" ] || continue
  find "$root" -xdev \( $PRUNE \) -prune -o -type f \( -perm -4000 -o -perm -2000 \) -print 2>/dev/null
done | sort -u > "$TMP/suid"
set +f
cat "$TMP/suid" >> "$TMP/want"

CAP_STATUS=getcap_missing
if command -v getcap >/dev/null 2>&1; then
  CAP_STATUS=listed
  for d in /usr /bin /sbin /lib /lib64 /opt; do
    [ -d "$d" ] && [ ! -L "$d" ] && getcap -r "$d" 2>/dev/null
  done | sort -u | while IFS= read -r line; do
    p=${line%% *}; caps=${line#"$p"}; caps=${caps# }; caps=${caps#= }
    rec caps "$p" "$caps"; want "$p"
  done
fi
kv run capabilities_status s "$CAP_STATUS"

# --- cron ---------------------------------------------------------------------------------

cat > "$TMP/cron.awk" <<'EOF'
function trim(s) { sub(/^[ \t]+/, "", s); sub(/[ \t]+$/, "", s); return s }
function unq(s) { gsub(/["']/, "", s); return s }
function img(cmd,   n, t, i, j, b) {             # the program a command line runs
  n = split(trim(cmd), t, /[ \t]+/)
  i = 1
  while (i <= n && t[i] ~ /^[A-Za-z_][A-Za-z0-9_]*=/) i++
  if (i > n) return ""
  b = unq(t[i]); sub(/^.*\//, "", b)
  if (b ~ /^(sh|bash|dash|ash|zsh|ksh|python[0-9.]*|perl|php[0-9.]*|ruby|node|nice|nohup|ionice|exec|env|flock|timeout)$/) {
    for (j = i + 1; j <= n; j++) {                # the script an interpreter or wrapper runs
      if (unq(t[j]) ~ /^\//) return unq(t[j])
      if (t[j] !~ /^-/ && t[j] !~ /^[0-9]+$/) break
    }
  }
  return (unq(t[i]) ~ /^\//) ? unq(t[i]) : ""
}
{
  line = $0
  if (line ~ /^[ \t]*#/ || line ~ /^[ \t]*$/) next
  if (line ~ /^[ \t]*[A-Za-z_][A-Za-z0-9_]*[ \t]*=/) {
    if (line ~ /^[ \t]*PATH[ \t]*=/) { v = line; sub(/^[^=]*=[ \t]*/, "", v); gsub(/["']/, "", v); print v >> (T "/cronpath") }
    next
  }
  line = trim(line)
  if (systab) {                                   # /etc/crontab, /etc/cron.d: has a user field
    if (line ~ /^@/) { sched = $1; user = $2; cmd = line; sub(/^[^ \t]+[ \t]+[^ \t]+[ \t]+/, "", cmd) }
    else { if (NF < 7) next; sched = $1 " " $2 " " $3 " " $4 " " $5; user = $6; cmd = line; for (k = 0; k < 6; k++) sub(/^[^ \t]+[ \t]+/, "", cmd) }
  } else {                                        # per-user crontab: the file name is the user
    user = owner
    if (line ~ /^@/) { sched = $1; cmd = line; sub(/^[^ \t]+[ \t]+/, "", cmd) }
    else { if (NF < 6) next; sched = $1 " " $2 " " $3 " " $4 " " $5; cmd = line; for (k = 0; k < 5; k++) sub(/^[^ \t]+[ \t]+/, "", cmd) }
  }
  print src US user US sched US cmd US img(cmd) >> (T "/cron")
}
EOF

for f in /etc/crontab /etc/cron.d/*; do
  [ -f "$f" ] && [ -r "$f" ] || continue
  awk -v US="$US" -v T="$TMP" -v src="$f" -v systab=1 -f "$TMP/cron.awk" "$f"
done
for d in /var/spool/cron/crontabs /var/spool/cron /etc/crontabs; do   # readable only as root
  [ -d "$d" ] && [ -r "$d" ] && [ -x "$d" ] || continue
  for f in "$d"/*; do
    [ -f "$f" ] && [ -r "$f" ] || continue
    awk -v US="$US" -v T="$TMP" -v src="$f" -v systab=0 -v owner="${f##*/}" -f "$TMP/cron.awk" "$f"
  done
done
for d in hourly daily weekly monthly; do
  for f in /etc/cron.$d/*; do
    [ -f "$f" ] || continue
    rec cron "/etc/cron.$d" root "@$d (run-parts)" "$f" "$f"
  done
done
awk -F"$US" '$5 ~ /^\// { print $5 }' "$TMP/cron" >> "$TMP/want"
while IFS= read -r v; do addpath cron "$v"; done < "$TMP/cronpath"

# --- systemd services and boot scripts ----------------------------------------------------

seen_dirs=
for d in /etc/systemd/system /run/systemd/system /lib/systemd/system /usr/lib/systemd/system \
         /usr/local/lib/systemd/system; do
  [ -d "$d" ] || continue
  r=$(cd "$d" 2>/dev/null && pwd -P) || continue
  case " $seen_dirs " in *" $r "*) continue ;; esac
  seen_dirs="$seen_dirs $r"
  find "$d" -maxdepth 2 \( -name '*.service' -o -path '*.service.d/*.conf' \) -type f 2>/dev/null
done > "$TMP/units"

cat > "$TMP/units.awk" <<'EOF'
function trim(s) { sub(/^[ \t]+/, "", s); sub(/[ \t]+$/, "", s); return s }
function prog(v,   t) { v = trim(v); sub(/^[-@:+!]+/, "", v); t = v; sub(/[ \t].*$/, "", t); gsub(/["']/, "", t); return (t ~ /^\//) ? t : "" }
{
  f = $0
  unit = f; sub(/^.*\//, "", unit)
  if (f ~ /\.service\.d\/[^\/]*\.conf$/) { unit = f; sub(/\/[^\/]*$/, "", unit); sub(/^.*\//, "", unit); sub(/\.d$/, "", unit) }
  user = ""; dyn = 0; n = 0
  while ((getline line < f) > 0) {
    line = trim(line)
    if (line ~ /^User[ \t]*=/) { user = line; sub(/^User[ \t]*=[ \t]*/, "", user) }
    else if (line ~ /^DynamicUser[ \t]*=[ \t]*(yes|true|1|on)/) dyn = 1
    else if (line ~ /^Exec(Start|StartPre|StartPost|Reload|Stop|StopPost)[ \t]*=/) {
      dir = line; sub(/[ \t]*=.*$/, "", dir)
      cmd = line; sub(/^[^=]*=[ \t]*/, "", cmd)
      if (cmd != "") { n++; D[n] = dir; C[n] = cmd }
    }
  }
  close(f)
  runas = user; if (runas == "") runas = dyn ? "(dynamic)" : "root"
  if (n == 0) print unit US f US runas US "" US "" US "" >> (T "/systemd")
  for (i = 1; i <= n; i++) print unit US f US runas US D[i] US C[i] US prog(C[i]) >> (T "/systemd")
}
EOF
[ -s "$TMP/units" ] && awk -v US="$US" -v T="$TMP" -f "$TMP/units.awk" "$TMP/units"
awk -F"$US" '{ print $2; if ($6 ~ /^\//) print $6 }' "$TMP/systemd" >> "$TMP/want"

for f in /etc/init.d/* /etc/rc.local /etc/rc.d/rc.local; do
  [ -f "$f" ] || continue
  rec boot "${f%/*}" "$f"; want "$f"
done

# --- PATH as root sees it -----------------------------------------------------------------

addpath process "${PATH:-}"
if [ -r /etc/environment ]; then
  v=$(awk '/^[ \t]*PATH[ \t]*=/ { v = substr($0, index($0, "=") + 1); gsub(/"/, "", v); print v; exit }' /etc/environment)
  [ -n "$v" ] && addpath environment "$v"
fi
if [ -r /etc/login.defs ]; then
  v=$(awk '$1 == "ENV_SUPATH" { v = $2; sub(/^PATH=/, "", v); print v; exit }' /etc/login.defs)
  [ -n "$v" ] && addpath root_login "$v"
fi
v=$(awk -F"$US" 'index($2, "secure_path") == 1 { v = $2; sub(/^secure_path[ \t]*=[ \t]*/, "", v); gsub(/"/, "", v); gsub(/\\:/, ":", v); print v; exit }' "$TMP/sudo_defaults")
[ -n "$v" ] && addpath sudo "$v"

# --- files root relies on -----------------------------------------------------------------

sens() { rec sensitive "$1" "$2"; want "$2"; }
sens passwd /etc/passwd
sens group /etc/group
sens shadow /etc/shadow
sens gshadow /etc/gshadow
for f in /etc/shadow- /etc/gshadow- /var/backups/shadow.bak /var/backups/gshadow.bak; do
  [ -e "$f" ] && sens shadow_backup "$f"
done
sens sudoers /etc/sudoers
sens sudoers_dir /etc/sudoers.d
sens pam_dir /etc/pam.d
sens crontab /etc/crontab
for d in /etc/cron.d /etc/cron.hourly /etc/cron.daily /etc/cron.weekly /etc/cron.monthly; do
  [ -e "$d" ] && sens cron_dir "$d"
done
sens ld_preload /etc/ld.so.preload
sens ld_so_conf /etc/ld.so.conf
sens ld_so_conf_dir /etc/ld.so.conf.d
sens systemd_dir /etc/systemd/system
sens initd_dir /etc/init.d
sens profile /etc/profile
sens profile_dir /etc/profile.d
for f in /etc/bash.bashrc /etc/bashrc; do [ -e "$f" ] && sens bashrc "$f"; done
sens environment /etc/environment
sens root_home /root
sens exports /etc/exports

if [ -r /etc/exports ]; then
  awk -v US="$US" '!/^[ \t]*#/ && NF { print $0 US (index($0, "no_root_squash") ? 1 : 0) }' /etc/exports >> "$TMP/exports"
fi

ldconf() {
  [ -r "$1" ] || return 0
  awk -v US="$US" -v src="$1" '{ sub(/#.*/, ""); sub(/^[ \t]+/, ""); sub(/[ \t]+$/, "") } /^\// { print src US $0 }' "$1" >> "$TMP/lddirs"
}
ldconf /etc/ld.so.conf
for f in /etc/ld.so.conf.d/*.conf; do [ -f "$f" ] && ldconf "$f"; done
awk -F"$US" '{ print $2 }' "$TMP/lddirs" >> "$TMP/want"
if [ -r /etc/ld.so.preload ]; then
  awk '{ sub(/#.*/, "") } { for (i = 1; i <= NF; i++) if ($i ~ /^\//) print $i }' /etc/ld.so.preload > "$TMP/ldpreload"
  cat "$TMP/ldpreload" >> "$TMP/want"
fi

seen_socks=
for s in /run/docker.sock /var/run/docker.sock /run/podman/podman.sock /run/containerd/containerd.sock; do
  [ -e "$s" ] || continue
  r=$(readlink -f "$s" 2>/dev/null || echo "$s")
  case " $seen_socks " in *" $r "*) continue ;; esac
  seen_socks="$seen_socks $r"
  case $r in *docker*) k=docker ;; *podman*) k=podman ;; *) k=containerd ;; esac
  rec sockets "$k" "$r"; want "$r"
done

# --- credentials: presence only, contents never read --------------------------------------

cred() { if [ -e "$2" ]; then rec creds "$1" "$2"; want "$2"; fi; }
for h in /root /home/*; do
  [ -d "$h" ] || continue
  for f in .bash_history .zsh_history .ash_history .sh_history .history .python_history \
           .mysql_history .psql_history; do
    cred shell_history "$h/$f"
  done
  for f in "$h"/.ssh/id_*; do
    case $f in *.pub|*'*') ;; *) cred ssh_private_key "$f" ;; esac
  done
  cred git_credentials "$h/.git-credentials"
  cred netrc "$h/.netrc"
  cred pgpass "$h/.pgpass"
  cred mysql_config "$h/.my.cnf"
  cred aws_credentials "$h/.aws/credentials"
  cred docker_config "$h/.docker/config.json"
  cred kube_config "$h/.kube/config"
done

# --- stat every recorded path and its ancestors -------------------------------------------

awk '/^\// {
  p = $0
  while (length(p) > 1 && substr(p, length(p)) == "/") p = substr(p, 1, length(p) - 1)
  print p
  while (p != "/") { sub(/\/[^\/]*$/, "", p); if (p == "") p = "/"; print p }
}' "$TMP/want" | sort -u > "$TMP/statlist"

FMT="%a$US%u$US%g$US%U$US%G$US%F$US%n"
if printf '/\000' | xargs -0 stat -L -c '%a' >/dev/null 2>&1; then
  tr '\n' '\000' < "$TMP/statlist" | xargs -0 stat -L -c "$FMT" 2>/dev/null > "$TMP/stat"
else
  while IFS= read -r p; do stat -L -c "$FMT" "$p" 2>/dev/null; done < "$TMP/statlist" > "$TMP/stat"
fi

END_=$(date +%s 2>/dev/null || echo 0)
kv run duration_ms n "$(( (END_ - START) * 1000 ))"

# --- assemble JSON ------------------------------------------------------------------------

cat > "$TMP/json.awk" <<'EOF'
BEGIN { FS = US }
function esc(s,   out, i, n, c) {               # JSON string; byte loop, portable across awks
  out = ""; n = length(s)
  for (i = 1; i <= n; i++) {
    c = substr(s, i, 1)
    if (c == "\\") out = out "\\\\"
    else if (c == "\"") out = out "\\\""
    else if (c == "\t") out = out "\\t"
    else if (c < " ") out = out " "
    else out = out c
  }
  return "\"" out "\""
}
function jstr(s) { return (s == "") ? "null" : esc(s) }
function jnum(s) { return (s ~ /^[0-9]+$/) ? s : "null" }
function jbool(s) { return (s == "1" || s == "true") ? "true" : "false" }
function base(p) { sub(/^.*\//, "", p); return p }
function dirn(p) { if (p !~ /^\//) return ""; sub(/\/[^\/]*$/, "", p); return (p == "") ? "/" : p }
function pad4(m) { while (length(m) < 4) m = "0" m; return m }
function uidof(u) { if (u ~ /^[0-9]+$/) return u; if (u in PW) return PW[u]; return (u == "root") ? "0" : "" }
function add(sec, r) { N[sec]++; R[sec, N[sec]] = r }
function arr(sec,   i, s) { s = "["; for (i = 1; i <= N[sec]; i++) s = s (i > 1 ? "," : "") R[sec, i]; return s "]" }
function obj(o,   i, k, t, v, s) {
  s = "{"
  for (i = 1; i <= KN[o]; i++) {
    k = KK[o, i]; t = KT[o, k]; v = KV[o, k]
    if (t == "n") v = jnum(v); else if (t == "b") v = jbool(v); else if (t == "z") v = jstr(v); else v = esc(v)
    s = s (i > 1 ? "," : "") esc(k) ":" v
  }
  return s
}
{ sec = base(FILENAME) }
sec == "passwd" { split($0, pw, ":"); if (pw[1] != "" && !(pw[1] in PW)) PW[pw[1]] = pw[3]; next }
sec == "stat" {
  p = $7; for (i = 8; i <= NF; i++) p = p US $i
  SM[p] = $1; SU[p] = $2; SG[p] = $3; SO[p] = $4; SGN[p] = $5; ST[p] = $6; next
}
sec == "statlist" { L[++NL] = $0; next }
sec == "kv" { if (!(($1, $2) in KT)) { KN[$1]++; KK[$1, KN[$1]] = $2 } KT[$1, $2] = $3; KV[$1, $2] = $4; next }
sec == "groups" { add("groups", "{\"gid\":" jnum($1) ",\"name\":" jstr($2) "}"); next }
sec == "sudo" {
  add("sudo", "{\"who\":" jstr($1) ",\"source\":" jstr($2) ",\"runas\":" jstr($3) ",\"nopasswd\":" jbool($4) \
    ",\"command\":" jstr($5) ",\"command_path\":" jstr(($6 ~ /^\//) ? $6 : "") ",\"command_name\":" jstr($7) ",\"raw\":" jstr($8) "}")
  next
}
sec == "sudo_defaults" { add("sudo_defaults", "{\"source\":" jstr($1) ",\"setting\":" jstr($2) "}"); next }
sec == "suid" {
  p = $0; m = (p in SM) ? pad4(SM[p]) : ""
  add("suid", "{\"path\":" esc(p) ",\"name\":" esc(base(p)) ",\"setuid\":" jbool(m != "" && substr(m, 1, 1) ~ /[4567]/) \
    ",\"setgid\":" jbool(m != "" && substr(m, 1, 1) ~ /[2367]/) ",\"owner\":" jstr(SO[p]) ",\"owner_uid\":" jnum(SU[p]) "}")
  next
}
sec == "caps" { add("caps", "{\"path\":" esc($1) ",\"name\":" esc(base($1)) ",\"capabilities\":" jstr($2) "}"); next }
sec == "cron" {
  add("cron", "{\"source\":" jstr($1) ",\"user\":" jstr($2) ",\"run_as_uid\":" jnum(uidof($2)) ",\"schedule\":" jstr($3) \
    ",\"command\":" jstr($4) ",\"image_path\":" jstr($5) ",\"image_dir\":" jstr(dirn($5)) "}")
  next
}
sec == "systemd" {
  add("systemd", "{\"unit\":" jstr($1) ",\"unit_file\":" jstr($2) ",\"run_as\":" jstr($3) ",\"run_as_uid\":" jnum(uidof($3)) \
    ",\"directive\":" jstr($4) ",\"command\":" jstr($5) ",\"image_path\":" jstr($6) ",\"image_dir\":" jstr(dirn($6)) "}")
  next
}
sec == "boot" { add("boot", "{\"source\":" jstr($1) ",\"path\":" jstr($2) "}"); next }
sec == "pathdirs" { add("pathdirs", "{\"scope\":" jstr($1) ",\"dir\":" esc($2) "}"); next }
sec == "sensitive" { add("sensitive", "{\"kind\":" jstr($1) ",\"path\":" jstr($2) "}"); next }
sec == "exports" { add("exports", "{\"line\":" jstr($1) ",\"no_root_squash\":" jbool($2) "}"); next }
sec == "lddirs" { add("lddirs", "{\"source\":" jstr($1) ",\"dir\":" jstr($2) "}"); next }
sec == "ldpreload" { add("ldpreload", "{\"path\":" jstr($1) "}"); next }
sec == "sockets" { add("sockets", "{\"kind\":" jstr($1) ",\"path\":" jstr($2) "}"); next }
sec == "creds" { p = $2; add("creds", "{\"type\":" jstr($1) ",\"path\":" esc(p) ",\"owner\":" jstr(SO[p]) ",\"owner_uid\":" jnum(SU[p]) "}"); next }
END {
  printf "{\"privscope\":{\"tool\":\"privscope-collector\",\"platform\":\"linux\",\"version\":%s,", esc(VERSION)
  printf "\"schema_version\":1,\"kind\":\"collection\",\"read_only\":true}"
  printf ",\"run\":%s}", obj("run")
  printf ",\"host\":%s}", obj("host")
  printf ",\"principal\":%s,\"groups\":%s}", obj("principal"), arr("groups")
  printf ",\"facts\":{\"suid_files\":%s,\"capabilities\":%s", arr("suid"), arr("caps")
  printf ",\"cron\":%s,\"systemd\":%s,\"boot_scripts\":%s", arr("cron"), arr("systemd"), arr("boot")
  printf ",\"path_dirs\":%s,\"sensitive_files\":%s,\"nfs_exports\":%s", arr("pathdirs"), arr("sensitive"), arr("exports")
  printf ",\"ld_so_dirs\":%s,\"ld_preload_libs\":%s,\"sockets\":%s", arr("lddirs"), arr("ldpreload"), arr("sockets")
  printf ",\"sudo_rules\":%s,\"sudo_defaults\":%s", arr("sudo"), arr("sudo_defaults")
  printf ",\"credential_artifacts\":%s,\"acls\":{", arr("creds")
  for (i = 1; i <= NL; i++) {
    p = L[i]
    if (p in SM)
      e = "{\"path\":" esc(p) ",\"exists\":true,\"mode\":" esc(SM[p]) ",\"uid\":" jnum(SU[p]) ",\"gid\":" jnum(SG[p]) \
          ",\"owner\":" jstr(SO[p]) ",\"group\":" jstr(SGN[p]) ",\"type\":" jstr(ST[p]) "}"
    else
      e = "{\"path\":" esc(p) ",\"exists\":false}"
    printf "%s%s:%s", (i > 1 ? "," : ""), esc(p), e
  }
  printf "}}}\n"
}
EOF

if [ -r /etc/passwd ]; then cat /etc/passwd > "$TMP/passwd"; else : > "$TMP/passwd"; fi
[ -n "$OUT" ] || OUT="./privscope-$(uname -n 2>/dev/null || echo host)-$(date +%Y%m%d-%H%M%S 2>/dev/null).json"
cd "$TMP" || exit 1
awk -v US="$US" -v VERSION="$VERSION" -f json.awk passwd stat statlist kv groups sudo sudo_defaults \
    suid caps cron systemd boot pathdirs sensitive exports lddirs ldpreload sockets creds > json || {
  echo "privscope: failed to build the JSON document" >&2; exit 1; }
cd - >/dev/null || exit 1
cat "$TMP/json" > "$OUT" || { echo "privscope: can't write $OUT" >&2; exit 1; }
echo "[privscope] read-only collection written to $OUT" >&2
[ "$TO_STDOUT" = 1 ] && cat "$OUT"
exit 0
