"""verified_exec: systemd kullanıcı servisinin ad alanında root sahipli ikililer overflow (65534) görünür.

Yalnız root eşlenmemişken, dosya ve üst dizin yazılamazken ve üst dizin bize ait değilken kabul edilir."""
import os
import tempfile
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest import mock

import verified_exec


def _info(uid: int):
    return SimpleNamespace(st_uid=uid, st_mode=0o100755)


class VisibleRootUidTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.overflow = Path(self.tmp.name) / "overflowuid"
        self.overflow.write_text("65534\n")

    def _map(self, text):
        path = Path(self.tmp.name) / "uid_map"
        path.write_text(text)
        return str(path)

    def test_full_map_maps_root(self):
        self.assertIsNone(verified_exec._visible_root_uid(self._map("0 0 4294967295\n"), str(self.overflow)))

    def test_single_user_map_hides_root(self):
        self.assertEqual(verified_exec._visible_root_uid(self._map("1000 1000 1\n"), str(self.overflow)), 65534)

    def test_unreadable_map_is_strict(self):
        self.assertIsNone(verified_exec._visible_root_uid(str(Path(self.tmp.name) / "yok"), str(self.overflow)))


class NamespacedRootOwnedTests(unittest.TestCase):
    def test_root_owned_system_binary_accepted_in_namespace(self):
        target = "/usr/bin/env"
        with mock.patch.object(verified_exec, "_visible_root_uid", return_value=65534), \
                mock.patch.object(verified_exec.os, "stat", return_value=SimpleNamespace(st_uid=65534, st_mode=0o40755)):
            self.assertTrue(verified_exec._namespaced_root_owned(target, _info(65534)))

    def test_outside_namespace_overflow_owner_rejected(self):
        with mock.patch.object(verified_exec, "_visible_root_uid", return_value=None):
            self.assertFalse(verified_exec._namespaced_root_owned("/usr/bin/env", _info(65534)))

    def test_other_uid_rejected(self):
        with mock.patch.object(verified_exec, "_visible_root_uid", return_value=65534):
            self.assertFalse(verified_exec._namespaced_root_owned("/usr/bin/env", _info(1234)))

    def test_parent_owned_by_us_rejected(self):
        with tempfile.TemporaryDirectory() as tmp:
            tool = Path(tmp) / "tool"
            tool.write_text("#!/bin/sh\n")
            tool.chmod(0o555)
            with mock.patch.object(verified_exec, "_visible_root_uid", return_value=65534):
                self.assertFalse(verified_exec._namespaced_root_owned(str(tool), _info(65534)))

    def test_group_writable_parent_rejected(self):
        with mock.patch.object(verified_exec, "_visible_root_uid", return_value=65534), \
                mock.patch.object(verified_exec.os, "stat", return_value=SimpleNamespace(st_uid=65534, st_mode=0o40775)):
            self.assertFalse(verified_exec._namespaced_root_owned("/usr/bin/env", _info(65534)))

    def test_writable_binary_rejected(self):
        with mock.patch.object(verified_exec, "_visible_root_uid", return_value=65534), \
                mock.patch.object(verified_exec.os, "stat", return_value=SimpleNamespace(st_uid=65534, st_mode=0o40755)), \
                mock.patch.object(verified_exec.os, "access", return_value=True):
            self.assertFalse(verified_exec._namespaced_root_owned("/usr/bin/env", _info(65534)))

    def test_overflow_equal_to_own_uid_rejected(self):
        with mock.patch.object(verified_exec, "_visible_root_uid", return_value=os.getuid()):
            self.assertFalse(verified_exec._namespaced_root_owned("/usr/bin/env", _info(os.getuid())))


if __name__ == "__main__":
    unittest.main()
