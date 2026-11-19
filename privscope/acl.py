"""Filesystem access evaluation over the collector's facts.acls table.

Windows entries carry a DACL (`aces`); Linux entries carry a mode, owner and group
(`mode`, `uid`, `gid`). Everything here follows RULES.md ("Access evaluation"); the
browser engine implements the same logic and must agree with it on every conformance case.
"""
from __future__ import annotations

import re
from typing import Dict, FrozenSet, List, Optional, Tuple

PLATFORMS = ("windows", "linux")

READ_DATA = 0x1
WRITE_DATA = 0x2
APPEND_DATA = 0x4
WRITE_DAC = 0x40000
WRITE_OWNER = 0x80000

GENERIC_READ = 0x80000000
GENERIC_WRITE = 0x40000000
GENERIC_EXECUTE = 0x20000000
GENERIC_ALL = 0x10000000
GENERIC_BITS = GENERIC_READ | GENERIC_WRITE | GENERIC_EXECUTE | GENERIC_ALL

FILE_GENERIC_READ = 0x120089
FILE_GENERIC_WRITE = 0x120116
FILE_GENERIC_EXECUTE = 0x1200A0
FILE_ALL_ACCESS = 0x1F01FF

MASKS = {
    "write": WRITE_DATA | WRITE_DAC | WRITE_OWNER,
    "read": READ_DATA | WRITE_DAC | WRITE_OWNER,
    "create_dir": APPEND_DATA | WRITE_DAC | WRITE_OWNER,
}

# .NET FileSystemRights names, as the Windows collector's ToString() writes them.
RIGHT_NAMES = {
    "ReadData": 0x1,
    "ListDirectory": 0x1,
    "WriteData": 0x2,
    "CreateFiles": 0x2,
    "AppendData": 0x4,
    "CreateDirectories": 0x4,
    "ReadExtendedAttributes": 0x8,
    "WriteExtendedAttributes": 0x10,
    "ExecuteFile": 0x20,
    "Traverse": 0x20,
    "DeleteSubdirectoriesAndFiles": 0x40,
    "ReadAttributes": 0x80,
    "WriteAttributes": 0x100,
    "Write": 0x116,
    "Delete": 0x10000,
    "ReadPermissions": 0x20000,
    "Read": 0x20089,
    "ReadAndExecute": 0x200A9,
    "Modify": 0x301BF,
    "ChangePermissions": 0x40000,
    "TakeOwnership": 0x80000,
    "Synchronize": 0x100000,
    "FullControl": 0x1F01FF,
}

STANDARD_USER_SIDS: FrozenSet[str] = frozenset(
    {
        "S-1-1-0",  # Everyone
        "S-1-5-11",  # Authenticated Users
        "S-1-5-32-545",  # Users
        "S-1-5-4",  # INTERACTIVE
        "S-1-2-0",  # LOCAL
        "S-1-2-1",  # CONSOLE LOGON
        "S-1-5-113",  # Local account
    }
)

_INT = re.compile(r"^-?\d+$")
_OCTAL = re.compile(r"^[0-7]{1,6}$")
_DRIVE = re.compile(r"^[a-z]:$")
_DRIVE_ROOT = re.compile(r"^[a-z]:\\$")


def doc_platform(doc: dict) -> str:
    meta = doc.get("privscope") if isinstance(doc.get("privscope"), dict) else {}
    p = meta.get("platform")
    return p if p in PLATFORMS else "windows"


def _int(v) -> Optional[int]:
    return v if isinstance(v, int) and not isinstance(v, bool) else None


# --- paths ------------------------------------------------------------------------------

def normalize(path: str, platform: str = "windows") -> str:
    if platform == "linux":
        return path.rstrip("/") or "/" if len(path) > 1 else path
    p = path.strip().replace("/", "\\").lower()
    if len(p) > 3 and p.endswith("\\"):
        p = p.rstrip("\\")
    if _DRIVE.match(p):
        p += "\\"
    return p


def parent(normalized: str, platform: str = "windows") -> Optional[str]:
    if platform == "linux":
        if normalized == "/" or "/" not in normalized:
            return None
        return normalized[:normalized.rfind("/")] or "/"
    if _DRIVE_ROOT.match(normalized):
        return None
    i = normalized.rfind("\\")
    if i <= 0:
        return None
    head = normalized[:i]
    if _DRIVE.match(head):
        return head + "\\"
    return head


# --- Windows rights ---------------------------------------------------------------------

def parse_rights(value) -> int:
    if value is None or isinstance(value, bool):
        return 0
    s = str(value).strip()
    if _INT.match(s):
        return int(s) & 0xFFFFFFFF
    mask = 0
    for part in s.split(","):
        mask |= RIGHT_NAMES.get(part.strip(), 0)
    return mask


def map_generic(mask: int) -> int:
    m = mask & ~GENERIC_BITS & 0xFFFFFFFF
    if mask & GENERIC_ALL:
        m |= FILE_ALL_ACCESS
    if mask & GENERIC_READ:
        m |= FILE_GENERIC_READ
    if mask & GENERIC_WRITE:
        m |= FILE_GENERIC_WRITE
    if mask & GENERIC_EXECUTE:
        m |= FILE_GENERIC_EXECUTE
    return m


# --- perspective ------------------------------------------------------------------------

class Perspective:
    """Whose access counts: Windows SIDs (+ owner name), or a Linux uid and gids."""

    def __init__(self, mode: str, sids: FrozenSet[str] = frozenset(), owner_name: Optional[str] = None,
                 domain_users: bool = False, platform: str = "windows", uid: Optional[int] = None,
                 gids: FrozenSet[int] = frozenset()):
        self.mode = mode
        self.sids = sids
        self.owner_name = owner_name
        self.domain_users = domain_users
        self.platform = platform
        self.uid = uid
        self.gids = gids

    def matches(self, sid: str) -> bool:
        if sid in self.sids:
            return True
        return self.domain_users and sid.startswith("S-1-5-21-") and sid.endswith("-513")


def build_perspective(doc: dict, mode: str = "auto") -> Perspective:
    platform = doc_platform(doc)
    principal = doc.get("principal") if isinstance(doc.get("principal"), dict) else {}
    if mode == "auto":
        mode = "standard-user" if principal.get("is_admin") is True else "principal"
    if mode not in ("principal", "standard-user"):
        raise ValueError(f"unknown perspective: {mode}")
    owner = principal.get("user") if isinstance(principal.get("user"), str) else None

    if platform == "linux":
        if mode == "standard-user":
            return Perspective("standard-user", platform="linux")
        gids = set()
        if _int(principal.get("gid")) is not None:
            gids.add(principal["gid"])
        for g in principal.get("groups") or []:
            if isinstance(g, dict) and _int(g.get("gid")) is not None:
                gids.add(g["gid"])
        return Perspective("principal", platform="linux", owner_name=owner,
                           uid=_int(principal.get("uid")), gids=frozenset(gids))

    if mode == "standard-user":
        return Perspective("standard-user", STANDARD_USER_SIDS, domain_users=True)
    sids = set()
    if isinstance(principal.get("sid"), str):
        sids.add(principal["sid"])
    for g in principal.get("groups") or []:
        if isinstance(g, dict) and isinstance(g.get("sid"), str):
            sids.add(g["sid"])
    return Perspective("principal", frozenset(sids), owner_name=owner)


# --- ACL table --------------------------------------------------------------------------

class AclIndex:
    def __init__(self, table, platform: str = "windows"):
        self.platform = platform
        self._t: Dict[str, dict] = {}
        if isinstance(table, dict):
            for key, acl in table.items():
                if isinstance(key, str) and isinstance(acl, dict):
                    self._t[normalize(key, platform)] = acl

    def get(self, path) -> Optional[dict]:
        if not isinstance(path, str) or not path.strip():
            return None
        return self._t.get(normalize(path, self.platform))

    def __len__(self) -> int:
        return len(self._t)


Grant = Tuple[str, str, int]


def effective_access(acl: dict, persp: Perspective) -> Tuple[int, List[Grant], int]:
    allow = 0
    deny = 0
    grants: List[Grant] = []
    for ace in acl.get("aces") or []:
        if not isinstance(ace, dict) or ace.get("inherit_only") is True:
            continue
        sid = ace.get("sid")
        if not isinstance(sid, str) or not persp.matches(sid):
            continue
        m = map_generic(parse_rights(ace.get("rights")))
        kind = ace.get("access")
        if kind == "Deny":
            deny |= m
        elif kind == "Allow":
            allow |= m
            grants.append((str(ace.get("identity") or sid), str(ace.get("rights") or ""), m))
    owner = acl.get("owner")
    if persp.owner_name and isinstance(owner, str) and owner.lower() == persp.owner_name.lower():
        allow |= WRITE_DAC
        grants.append((f"{owner} (owner)", "implicit ChangePermissions", WRITE_DAC))
    return allow & ~deny & 0xFFFFFFFF, grants, deny


Actor = Tuple  # who a POSIX grant is for: ("root",), ("principal",), ("other",), ("group", gid), ("owner", uid)


def _mode(acl: dict) -> Optional[int]:
    mode_s = str(acl.get("mode", ""))
    return int(mode_s, 8) if _OCTAL.match(mode_s) else None


def posix_check(acl: dict, persp: Perspective, kind: str) -> Tuple[bool, str, Optional[Actor]]:
    """Unix permission bits on the object itself. See RULES.md for the two perspectives."""
    mode = _mode(acl)
    if mode is None:
        return False, "", None
    shown = f"{mode & 0o7777:04o}"
    uid, gid = _int(acl.get("uid")), _int(acl.get("gid"))
    owner = acl.get("owner") or (str(uid) if uid is not None else "?")
    group = acl.get("group") or (str(gid) if gid is not None else "?")
    bit = 4 if kind == "read" else 2

    if persp.mode == "principal":
        me = ("principal",)
        if persp.uid == 0:
            return True, "root", ("root",)
        if uid is not None and uid == persp.uid:
            return True, f"its owner {owner} (mode {shown})", me  # the owner can always chmod
        if gid is not None and gid in persp.gids:
            return (True, f"group {group} (mode {shown})", me) if mode >> 3 & bit else (False, "", None)
        return (True, f"everyone (mode {shown})", me) if mode & bit else (False, "", None)

    # standard-user: any account other than root
    if mode & bit:
        return True, f"everyone (mode {shown})", ("other",)
    if kind == "read":
        return False, "", None
    if gid not in (None, 0) and mode >> 3 & 2:
        return True, f"group {group} (mode {shown})", ("group", gid)
    if uid not in (None, 0):
        return True, f"its non-root owner {owner} (mode {shown})", ("owner", uid)
    return False, "", None


def can_search(acl: Optional[dict], persp: Perspective, actor: Actor) -> bool:
    """POSIX: can this actor pass through the folder (execute bit)? Unknown folders block."""
    if not acl or acl.get("exists") is not True:
        return False
    mode = _mode(acl)
    if mode is None:
        return False
    uid, gid = _int(acl.get("uid")), _int(acl.get("gid"))
    if actor[0] == "root":
        return True
    if actor[0] == "principal":
        if uid is not None and uid == persp.uid:
            return bool(mode & 0o100)
        if gid is not None and gid in persp.gids:
            return bool(mode & 0o010)
        return bool(mode & 0o001)
    if actor[0] == "owner" and uid == actor[1]:
        return bool(mode & 0o100)
    if actor[0] == "group" and gid == actor[1]:
        return bool(mode & 0o010)
    return bool(mode & 0o001)


def access_check(acl: Optional[dict], persp: Perspective, kind: str) -> Tuple[bool, str, Optional[Actor]]:
    """Access to the object itself, plus (POSIX only) the actor the grant is for, so the
    caller can check that the same actor can reach it through the folders above."""
    if not acl or acl.get("exists") is not True:
        return False, "", None
    if "mode" in acl:
        return posix_check(acl, persp, kind)
    eff, grants, deny = effective_access(acl, persp)
    mask = MASKS[kind]
    if not eff & mask:
        return False, "", None
    who = [f"{ident} ({rights})" for ident, rights, m in grants if (m & ~deny) & mask]
    return True, ", ".join(who), None


def check(acl: Optional[dict], persp: Perspective, kind: str) -> Tuple[bool, str]:
    """Access to the object itself (no folder traversal); True plus a 'who' description."""
    ok, who, _ = access_check(acl, persp, kind)
    return ok, who


# --- registry keys (Windows) ------------------------------------------------------------
# A writable registry key is its own escalation path: set a hook from scratch, or redirect a
# service's ImagePath. Registry rights differ from file rights, so they get their own mask.

KEY_SET_VALUE = 0x2
KEY_CREATE_SUB_KEY = 0x4
REG_WRITE = KEY_SET_VALUE | KEY_CREATE_SUB_KEY | WRITE_DAC | WRITE_OWNER
REG_FULL = 0xF003F

REG_RIGHT_NAMES = {
    "QueryValues": 0x1, "SetValue": 0x2, "CreateSubKey": 0x4, "EnumerateSubKeys": 0x8,
    "Notify": 0x10, "CreateLink": 0x20, "Delete": 0x10000, "ReadPermissions": 0x20000,
    "ChangePermissions": 0x40000, "TakeOwnership": 0x80000,
    "WriteKey": 0x20006, "ReadKey": 0x20019, "ExecuteKey": 0x20019, "FullControl": 0xF003F,
}

_REG_HIVES = (
    ("hkey_local_machine", "hklm"), ("hkey_current_user", "hkcu"), ("hkey_users", "hku"),
    ("hkey_classes_root", "hkcr"), ("hklm:", "hklm"), ("hkcu:", "hkcu"),
    ("hku:", "hku"), ("hkcr:", "hkcr"),
)


def normalize_reg(path) -> str:
    if not isinstance(path, str):
        return ""
    p = re.sub(r"(?i)^microsoft\.powershell\.core\\registry::", "", path.strip().replace("/", "\\"))
    low = p.lower()
    for a, b in _REG_HIVES:
        if low.startswith(a):
            p = b + p[len(a):]
            break
    return p.rstrip("\\").lower()


def parse_reg_rights(value) -> int:
    if value is None or isinstance(value, bool):
        return 0
    s = str(value).strip()
    if _INT.match(s):
        return int(s) & 0xFFFFFFFF
    mask = 0
    for part in s.split(","):
        mask |= REG_RIGHT_NAMES.get(part.strip(), 0)
    return mask


def map_generic_reg(mask: int) -> int:
    m = mask & ~GENERIC_BITS & 0xFFFFFFFF
    if mask & GENERIC_ALL:
        m |= REG_FULL
    if mask & GENERIC_WRITE:
        m |= 0x20006
    if mask & (GENERIC_READ | GENERIC_EXECUTE):
        m |= 0x20019
    return m


def reg_writable(acl: Optional[dict], persp: Perspective) -> Tuple[bool, str]:
    """True plus a 'who' description when the perspective can set values / create subkeys /
    rewrite the DACL of this registry key."""
    if not acl or acl.get("exists") is not True:
        return False, ""
    allow = deny = 0
    grants = []
    for ace in acl.get("aces") or []:
        if not isinstance(ace, dict) or ace.get("inherit_only") is True:
            continue
        sid = ace.get("sid")
        if not isinstance(sid, str) or not persp.matches(sid):
            continue
        m = map_generic_reg(parse_reg_rights(ace.get("rights")))
        if ace.get("access") == "Deny":
            deny |= m
        elif ace.get("access") == "Allow":
            allow |= m
            grants.append((str(ace.get("identity") or sid), str(ace.get("rights") or ""), m))
    owner = acl.get("owner")
    if persp.owner_name and isinstance(owner, str) and owner.lower() == persp.owner_name.lower():
        allow |= WRITE_DAC
        grants.append((f"{owner} (owner)", "implicit ChangePermissions", WRITE_DAC))
    eff = allow & ~deny & 0xFFFFFFFF
    if not eff & REG_WRITE:
        return False, ""
    who = [f"{ident} ({rights})" for ident, rights, m in grants if (m & ~deny) & REG_WRITE]
    return True, ", ".join(who)
