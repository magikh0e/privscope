import unittest

from privscope.acl import (
    FILE_ALL_ACCESS, GENERIC_ALL, WRITE_DATA, Perspective, build_perspective, check, map_generic,
    normalize, parent, parse_rights,
)


def ace(sid, rights, access="Allow", inherit_only=False):
    return {"identity": sid, "sid": sid, "rights": rights, "access": access, "inherit_only": inherit_only}


USERS = Perspective("principal", frozenset({"S-1-5-32-545"}), owner_name="LAB\\alice")


class Paths(unittest.TestCase):
    def test_normalize(self):
        self.assertEqual(normalize("C:\\Foo\\"), "c:\\foo")
        self.assertEqual(normalize("C:"), "c:\\")
        self.assertEqual(normalize("c:\\"), "c:\\")
        self.assertEqual(normalize("C:/a/B"), "c:\\a\\b")
        self.assertEqual(normalize("  D:\\X  "), "d:\\x")
        self.assertEqual(normalize(normalize("C:\\Foo\\")), normalize("C:\\Foo\\"))

    def test_parent(self):
        self.assertEqual(parent("c:\\a\\b"), "c:\\a")
        self.assertEqual(parent("c:\\a"), "c:\\")
        self.assertIsNone(parent("c:\\"))
        self.assertIsNone(parent("relative"))


class Rights(unittest.TestCase):
    def test_names(self):
        self.assertEqual(parse_rights("Modify, Synchronize"), 0x301BF | 0x100000)
        self.assertEqual(parse_rights("CreateFiles"), WRITE_DATA)
        self.assertEqual(parse_rights("bogus"), 0)
        self.assertEqual(parse_rights(None), 0)

    def test_numeric(self):
        self.assertEqual(parse_rights("268435456"), GENERIC_ALL)
        self.assertEqual(parse_rights("-1610612736"), 0xA0000000)

    def test_generic_mapping(self):
        self.assertEqual(map_generic(GENERIC_ALL), FILE_ALL_ACCESS)
        self.assertFalse(map_generic(0xA0000000) & WRITE_DATA)  # GENERIC_READ | GENERIC_EXECUTE


class Access(unittest.TestCase):
    def test_allow(self):
        ok, who = check({"exists": True, "aces": [ace("S-1-5-32-545", "Modify, Synchronize")]}, USERS, "write")
        self.assertTrue(ok)
        self.assertIn("S-1-5-32-545", who)

    def test_deny_wins(self):
        acl = {"exists": True, "aces": [ace("S-1-5-32-545", "Modify"), ace("S-1-5-32-545", "Write", "Deny")]}
        self.assertFalse(check(acl, USERS, "write")[0])
        self.assertTrue(check(acl, USERS, "read")[0])

    def test_inherit_only_ignored(self):
        acl = {"exists": True, "aces": [ace("S-1-5-32-545", "268435456", inherit_only=True)]}
        self.assertFalse(check(acl, USERS, "write")[0])

    def test_change_permissions_counts_as_write(self):
        acl = {"exists": True, "aces": [ace("S-1-5-32-545", "ChangePermissions")]}
        self.assertTrue(check(acl, USERS, "write")[0])

    def test_owner(self):
        acl = {"exists": True, "owner": "lab\\ALICE", "aces": []}
        self.assertTrue(check(acl, USERS, "write")[0])

    def test_missing_object(self):
        self.assertFalse(check({"exists": False, "aces": [ace("S-1-5-32-545", "FullControl")]}, USERS, "write")[0])
        self.assertFalse(check(None, USERS, "write")[0])

    def test_append_is_not_write(self):
        acl = {"exists": True, "aces": [ace("S-1-5-32-545", "AppendData")]}
        self.assertFalse(check(acl, USERS, "write")[0])
        self.assertTrue(check(acl, USERS, "create_dir")[0])


LINUX_ALICE = Perspective("principal", platform="linux", uid=1000, gids=frozenset({1000}))
LINUX_ANY = Perspective("standard-user", platform="linux")


def node(mode, uid=0, gid=0):
    return {"exists": True, "mode": mode, "uid": uid, "gid": gid, "owner": f"u{uid}", "group": f"g{gid}"}


class Posix(unittest.TestCase):
    def test_paths(self):
        self.assertEqual(normalize("/etc/", "linux"), "/etc")
        self.assertEqual(normalize("/", "linux"), "/")
        self.assertEqual(normalize("/Case/Kept", "linux"), "/Case/Kept")
        self.assertEqual(parent("/etc/cron.d", "linux"), "/etc")
        self.assertEqual(parent("/etc", "linux"), "/")
        self.assertIsNone(parent("/", "linux"))

    def test_principal_precedence(self):
        self.assertTrue(check(node("644", uid=1000), LINUX_ALICE, "write")[0])     # owner can chmod
        self.assertFalse(check(node("607", gid=1000), LINUX_ALICE, "write")[0])    # group bits win
        self.assertTrue(check(node("757"), LINUX_ALICE, "write")[0])               # other bits
        self.assertFalse(check(node("755"), LINUX_ALICE, "write")[0])
        self.assertTrue(check(node("640", gid=1000), LINUX_ALICE, "read")[0])
        self.assertFalse(check(node("640", gid=42), LINUX_ALICE, "read")[0])

    def test_root_principal(self):
        root = Perspective("principal", platform="linux", uid=0, gids=frozenset({0}))
        self.assertTrue(check(node("000"), root, "write")[0])

    def test_standard_user(self):
        self.assertTrue(check(node("664", gid=50), LINUX_ANY, "write")[0])         # non-root group
        self.assertFalse(check(node("664", gid=0), LINUX_ANY, "write")[0])
        self.assertTrue(check(node("700", uid=1000), LINUX_ANY, "write")[0])       # non-root owner
        self.assertFalse(check(node("640", gid=42), LINUX_ANY, "read")[0])         # read: other only
        self.assertTrue(check(node("604"), LINUX_ANY, "read")[0])

    def test_bad_mode(self):
        self.assertFalse(check({"exists": True, "mode": "rwx", "uid": 0, "gid": 0}, LINUX_ANY, "write")[0])

    def test_search(self):
        from privscope.acl import can_search
        self.assertTrue(can_search(node("711"), LINUX_ANY, ("other",)))
        self.assertFalse(can_search(node("700", uid=1000), LINUX_ANY, ("other",)))
        self.assertTrue(can_search(node("700", uid=1000), LINUX_ANY, ("owner", 1000)))
        self.assertTrue(can_search(node("750", gid=50), LINUX_ANY, ("group", 50)))
        self.assertFalse(can_search(node("700"), LINUX_ALICE, ("principal",)))
        self.assertTrue(can_search(node("700", uid=1000), LINUX_ALICE, ("principal",)))
        self.assertFalse(can_search(None, LINUX_ANY, ("other",)))


class Perspectives(unittest.TestCase):
    def test_auto(self):
        self.assertEqual(build_perspective({"principal": {"is_admin": True}}).mode, "standard-user")
        self.assertEqual(build_perspective({"principal": {"is_admin": False}}).mode, "principal")
        self.assertEqual(build_perspective({}).mode, "principal")

    def test_domain_users(self):
        p = build_perspective({}, "standard-user")
        self.assertTrue(p.matches("S-1-5-21-1-2-3-513"))
        self.assertFalse(p.matches("S-1-5-21-1-2-3-512"))
        self.assertFalse(p.matches("S-1-5-32-544"))

    def test_bad_mode(self):
        with self.assertRaises(ValueError):
            build_perspective({}, "nope")


if __name__ == "__main__":
    unittest.main()
