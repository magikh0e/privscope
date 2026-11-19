# privscope rule format

Rules are data, not code. They live in `privscope/rules/<platform>/*.json`, where the
platform is `windows` or `linux`, and are read by both the Python analyzer and the browser
page. Both engines must produce **identical findings** for the same collection, rule set
and perspective; `tests/conformance/` holds the shared cases each engine has to pass. This
file is the contract between them, so any change to engine behaviour starts here.

Each rule file is `{"rules": [ ... ]}`. Files load in platform then filename order, and rule
ids must be unique across all of them. A rule only runs against collections from its own
platform: the collection's `privscope.platform` (`windows` when absent).

## Rule fields

| Field | Required | Meaning |
|---|---|---|
| `id` | yes | Stable id: `PS-<AREA>-<NNN>` for Windows, `PL-<AREA>-<NNN>` for Linux. Never reuse an id for a different check: run-to-run diffs key on it. |
| `title` | yes | One line, states the problem. |
| `category` | yes | Grouping label (`services`, `tasks`, `cron`, `systemd`, `path`, `sudo`, `credentials`, ...). |
| `severity` | yes | `critical`, `high`, `medium`, `low` or `info`. |
| `select` | yes | Which records the rule looks at (below). |
| `where` | yes | Condition a selected record must meet (below). |
| `subject` | no | Template naming the affected thing, e.g. `"{name}"`. Must be unique per finding. |
| `evidence` | no | `{"label": "field path", ...}` copied into the finding. |
| `why` | yes | Why it is exploitable. |
| `fix` | yes | How to fix it. |
| `refs` | no | List of reference URLs. |

## select

A dotted path from the document root. A segment ending in `[*]` iterates an array, and
each element becomes a record whose **parent** is the record the array was reached from.
Without `[*]` at the end, the path selects one object.

- `facts.services[*]`: one record per service.
- `facts.scheduled_tasks[*].actions[*]`: one record per task action; `$parent` is the task.
- `facts.policies` or `host`: one record, that object.

Only objects become records: missing values, `null`, strings and numbers are skipped. A
single object where an array is expected counts as a one-element array (older PowerShell
can serialize one-element arrays that way).

## Field paths

A dotted path into the current record. Two prefixes reach elsewhere:

- `$parent.` is the record one `[*]` level up (it can repeat: `$parent.$parent.x`).
- `$root.` is the whole collection document.

Anything missing along the way resolves to `null`. There is no array indexing.

## Conditions

Combinators:

- `{"all": [c, ...]}`: every condition is true (non-empty list).
- `{"any": [c, ...]}`: at least one is true (non-empty list). Every branch is evaluated,
  so evidence notes from all true branches are kept.
- `{"not": c}`: c is false. Notes from inside a `not` are dropped.

Field tests, `{"field": "<path>", "<op>": <value>}` with exactly one op:

| Op | True when |
|---|---|
| `eq` / `ne` | JSON equality / inequality. Booleans never equal numbers (`true` ≠ `1`); `null` equals only `null`; arrays and objects never compare equal. |
| `in` / `not_in` | The value `eq`s / doesn't `eq` any list element. |
| `eq_field` / `ne_field` | The value `eq`s / doesn't `eq` the value at another field path (e.g. `"$root.principal.uid"`). |
| `regex` | The value is a string and the pattern matches **anywhere** in it, case-insensitively. Patterns must stay within the subset Python `re` and JavaScript `RegExp` share: no lookbehind, named groups or inline flags. |
| `exists` | `true`: the value is not `null`. `false`: it is `null`. |
| `lt` `lte` `gt` `gte` | The value is a number (not a boolean) and the comparison holds. Anything else is false. |

Path tests. The value is a field path that holds a filesystem path. A true result also
adds human-readable notes to the finding:

| Op | True when |
|---|---|
| `writable` | The object exists and grants the perspective **write** access. |
| `readable` | The object exists and grants the perspective **read** access. |
| `creatable` | A **folder** that `facts.acls` records with `exists: false`, whose nearest existing ancestor grants the perspective **create-folder** access. |
| `creatable_file` | A **file** that `facts.acls` records with `exists: false`. If its folder exists, the folder must grant **write** (add file); if the folder is missing too, its nearest existing ancestor must grant **create-folder**. |
| `unquoted_hijack` | Windows only. The path contains a space and, for at least one space, the folder that would hold `<text before the space>.exe` grants **write** access. Prefixes with no `\` or ending in `\` are skipped. |

For both `creatable` ops, the path itself must be in `facts.acls`, and if any ancestor up
to the first existing one is missing from it, the answer is false: unknown is not a finding.
On Linux every path test also requires that the same actor can pass through every folder
above the object (see "Linux" below).

Rule conventions:

- Rules about things that run (services, tasks) skip disabled ones (`start_mode` /
  `$parent.state` equal to `"Disabled"`), because nothing can start them until an admin
  re-enables them. A separate low-severity rule reports disabled privileged tasks that
  *would* be exploitable, so they still get cleaned up.
- Rules about the collecting account's own groups and privileges require
  `$root.principal.is_admin` to be `false`: for an administrator or root they are expected.

## Access evaluation

Each `facts.acls` entry is either a Windows DACL (it has `aces`) or Linux file metadata (it
has `mode`, `uid`, `gid`). An object that is missing from the table, or recorded with
`exists: false`, grants nothing.

The perspective decides whose access counts. `auto` (the default) means `standard-user`
when `principal.is_admin` is `true` (an elevated Windows collector, or root), otherwise
`principal`.

### Windows

Perspective, as a set of SIDs:

- `principal`: `principal.sid` plus every `principal.groups[].sid`. If an object's `owner`
  equals `principal.user` (case-insensitive), the owner gets implicit change-permissions.
- `standard-user`: `S-1-1-0` Everyone, `S-1-5-11` Authenticated Users, `S-1-5-32-545`
  Users, `S-1-5-4` INTERACTIVE, `S-1-2-0` LOCAL, `S-1-2-1` CONSOLE LOGON, `S-1-5-113`
  Local account, and any domain's Domain Users (`S-1-5-21-…-513`). No owner rule.

Path lookup: `facts.acls` keys and looked-up paths are both normalized: trim, `/` → `\`,
lower-case, strip trailing `\` unless the result would be shorter than `x:\`, then `x:` →
`x:\`. The parent of `x:\` is nothing; otherwise it's the text before the last `\`, with
`x:` turned into `x:\`. No folder traversal check (Windows grants everyone "bypass traverse
checking" by default).

Rights: an ACE counts only if `inherit_only` is not `true` and its `sid` is in the
perspective. `rights` is either a .NET `FileSystemRights` name list
(`"Modify, Synchronize"`) or a 32-bit integer string (possibly negative), read as unsigned.
Generic bits are mapped to file rights (`GENERIC_ALL` → `0x1F01FF`, `GENERIC_READ` →
`0x120089`, `GENERIC_WRITE` → `0x120116`, `GENERIC_EXECUTE` → `0x1200A0`). Effective access
= allowed bits minus denied bits.

| Check | Any of these bits |
|---|---|
| write | `0x2` write data / add file, `0x40000` change permissions, `0x80000` take ownership |
| read | `0x1` read data / list folder, `0x40000`, `0x80000` |
| create-folder | `0x4` append data / add subfolder, `0x40000`, `0x80000` |

Change-permissions and take-ownership count everywhere because either one lets the holder
grant themselves the rest.

### Linux

`mode` is an octal string (`"4755"`). write and create-folder test the `w` bit, read the
`r` bit. ACLs set with setfacl are not evaluated.

- `principal` (the collecting account's `uid`, its `gid` and every `groups[].gid`): exactly
  the kernel's rule. root gets everything. The owner gets everything (the owner can always
  chmod). Otherwise, if the file's group is one of the account's groups, the group bits
  decide, even when the "other" bits would allow more. Otherwise the "other" bits decide.
- `standard-user` (any account other than root): for **read**, only the "other" bits count.
  For **write** and **create-folder**, the "other" bits, or the group bits when the group
  isn't root (gid 0), or ownership by any account other than root. That last part is what
  makes a root cron job whose script belongs to an ordinary user a finding.

Each grant is for an **actor**: root, the principal, "other", a specific group, or a specific
owner. After the object itself passes, every folder above it, up to `/`, must give that same
actor the execute (search) bit: the owner bits when the folder belongs to the owner actor,
the group bits when it belongs to the group actor, otherwise the "other" bits (the
principal uses the kernel's rule as above). A folder missing from `facts.acls` blocks.

Path lookup: paths are case-sensitive and only a trailing `/` is stripped (except on `/`
itself). The parent is the text before the last `/`, or `/`.

## Subjects, keys and order

`subject` replaces each `{field path}` with the field's value: `null` → empty, booleans →
`true`/`false`, integral numbers without a decimal point. A finding's **key** is
`<id>|<subject>`; a second finding with the same key is dropped. Findings sort by severity
(critical first), then id, then subject, comparing strings ordinally.
