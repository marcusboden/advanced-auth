# Copyright 2021 Canonical
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

import os
import pwd
import unittest
from collections import namedtuple
from pathlib import Path
from tempfile import TemporaryDirectory
from unittest.mock import call, patch
from subprocess import CompletedProcess, CalledProcessError

from lib import local_users


class TestLocalUsers(unittest.TestCase):
    @patch("pwd.getpwnam")
    def test_substitute_path_vars_for_user(self, mock_getpwnam):
        mock_getpwnam.return_value = pwd.struct_passwd(
            ("testuser", "x", 99999, 99999, "Test User", "/home/testuser", "/bin/bash")
        )
        self.assertEqual(
            local_users._substitute_path_vars_for_user(
                path=Path("/etc/ssh/user-authorized-keys/$USER"), username="testuser"
            ),
            Path("/etc/ssh/user-authorized-keys/testuser"),
        )
        self.assertEqual(
            local_users._substitute_path_vars_for_user(
                path=Path("/etc/ssh/user-authorized-keys/$UID"), username="testuser"
            ),
            Path("/etc/ssh/user-authorized-keys/99999"),
        )
        self.assertEqual(
            local_users._substitute_path_vars_for_user(
                path=Path("$HOME/.ssh/authorized_keys"), username="testuser"
            ),
            Path("/home/testuser/.ssh/authorized_keys"),
        )

    @patch("pwd.getpwnam")
    def test_path_under_user_home(self, mock_getpwnam):
        mock_getpwnam.return_value = pwd.struct_passwd(
            ("testuser", "x", 99999, 99999, "Test User", "/home/testuser", "/bin/bash")
        )
        self.assertTrue(
            local_users._path_under_user_home(
                path=Path("/home/testuser/.ssh"), username="testuser"
            )
        )
        self.assertFalse(
            local_users._path_under_user_home(
                path=Path("/etc/ssh"), username="testuser"
            )
        )
        self.assertFalse(
            local_users._path_under_user_home(
                path=Path("/var/home/testuser/.ssh"), username="testuser"
            )
        )

    @patch("shutil.chown")
    @patch("pathlib.Path.chmod")
    @patch("pwd.getpwnam")
    def test_set_ssh_authorized_keys_update(
        self, mock_getpwnam, mock_chmod, *args, **kwargs
    ):
        testuser = local_users.User(
            "testuser", ["Test User", "", "", "", ""], ["ssh-rsa ABC testuser@testhost"]
        )

        testuser2 = local_users.User(
            "testuser", ["Test User", "", "", "", ""], ["ssh-rsa XYZ testuser@testhost"]
        )

        with TemporaryDirectory() as fake_home:
            mock_getpwnam.return_value = pwd.struct_passwd(
                ("testuser", "x", 99999, 99999, "Test User", fake_home, "/bin/bash")
            )

            testfile_path = os.path.join(fake_home, ".ssh", "authorized_keys")
            local_users.set_ssh_authorized_keys(testuser, "$HOME/.ssh/authorized_keys")
            with open(testfile_path, "r") as f:
                keys = f.readlines()
                self.assertIn(
                    "ssh-rsa ABC testuser@testhost # charm-local-users\n", keys
                )

            mock_chmod.assert_has_calls(
                [
                    call(mode=0o700),  # .ssh directory
                    call(mode=0o600),  # auth_keys file
                ]
            )
            mock_chmod.reset_mock()

            # update the key
            local_users.set_ssh_authorized_keys(testuser2, "$HOME/.ssh/authorized_keys")
            with open(testfile_path, "r") as f:
                keys = f.readlines()
                self.assertIn(
                    "ssh-rsa XYZ testuser@testhost # charm-local-users\n", keys
                )
                self.assertNotIn(
                    "ssh-rsa ABC testuser@testhost # charm-local-users\n", keys
                )

            mock_chmod.assert_has_calls([call(mode=0o700), call(mode=0o600)])

    @patch("pathlib.Path.chmod")
    @patch("pwd.getpwnam")
    def test_set_ssh_authorized_keys_in_etc(
        self, mock_getpwnam, mock_chmod, *args, **kwargs
    ):
        testuser = local_users.User(
            "testuser", ["Test User", "", "", "", ""], ["ssh-rsa ABC testuser@testhost"]
        )

        with TemporaryDirectory() as fake_etc:
            mock_getpwnam.return_value = pwd.struct_passwd(
                (
                    "testuser",
                    "x",
                    99999,
                    99999,
                    "Test User",
                    "/home/testuser",
                    "/bin/bash",
                )
            )

            testfile_path = os.path.join(
                fake_etc, "ssh", "user-authorized-keys", "testuser"
            )
            local_users.set_ssh_authorized_keys(
                testuser, f"{fake_etc}/ssh/user-authorized-keys/$USER"
            )
            with open(testfile_path, "r") as f:
                keys = f.readlines()
                self.assertIn(
                    "ssh-rsa ABC testuser@testhost # charm-local-users\n", keys
                )
        mock_chmod.assert_called_once_with(mode=0o644)

    def test_check_lp_user(self):
        test_lp_users = ["lp:test1", "test2"]
        self.assertTrue(local_users.is_lp_user(test_lp_users[0]))
        self.assertFalse(local_users.is_lp_user(test_lp_users[1]))

    @patch("subprocess.run")
    def test_get_lp_ssh_keys(self, mock_sub_run):
        test_lp_user = "lp:test_lpuser"
        valid_output = CompletedProcess(
            args=["ssh-import-id", "-o", "-", "lp:test_lpuser"],
            returncode=0,
            stdout=b"2023-01-01 10:10:10,100 INFO Authorized key ['2048', 'SHA256:SOMESHA', 'test_lpuser@home', '(RSA)']\n2023-01-01 10:10:10,101 INFO Authorized key ['3072', 'SHA256:ANOTHERSHA', 'test_lpuser@work', '(RSA)']\nssh-rsa ABC test_lpuser@home # ssh-import-id lp:test_lpuser\n\nssh-rsa XYZ test_lpuser@work # ssh-import-id lp:test_lpuser\n\n2023-01-01 10:10:10,112 INFO [2] SSH keys [Authorized]\n",
        )

        # returns valid_output the first time subprocess.run mock method is called
        # returns CalledProcessError exception the second time
        mock_sub_run.side_effect = [valid_output, CalledProcessError(1, "test_command")]

        test_lp_keys = [
            "ssh-rsa ABC test_lpuser@home # ssh-import-id lp:test_lpuser",
            "ssh-rsa XYZ test_lpuser@work # ssh-import-id lp:test_lpuser",
        ]
        self.assertEqual(local_users.get_lp_ssh_keys(test_lp_user), test_lp_keys)
        self.assertIsNone(local_users.get_lp_ssh_keys("lp:invalid_lpuser"))

    def test_parse_gecos(self):
        test_cases = [
            ("", ["", "", "", "", ""]),
            ("Test User", ["Test User", "", "", "", ""]),
            ("Test,,,,", ["Test", "", "", "", ""]),
            ("Test,,", ["Test", "", "", "", ""]),
            ("Test,,+0123456789", ["Test", "", "+0123456789", "", ""]),
            (",,,", ["", "", "", "", ""]),
            (",,,,,,ignored", ["", "", "", "", ""]),
            (",,,,'other' field", ["", "", "", "", "'other' field"]),
        ]

        for tc in test_cases:
            result = local_users.parse_gecos(tc[0])
            self.assertEqual(result, tc[1])

    def test_get_gecos(self):
        testcases = [
            (
                # standard account
                "testuser",
                b"testuser:x:1000:1000:Test User,,,:/home/testuser:/usr/bin/bash",
                ["Test User", "", "", "", ""],
            ),
            (
                # system account, empty GECOS
                "svcaccount",
                b"svcaccount:x:999:999::/var/lib/svcaccount:/bin/false",
                ["", "", "", "", ""],
            ),
            (
                # all fields
                "testuser",
                b"testuser:x:1000:1000:Test User,ACME,+123,+321,test:/home/testuser:"
                b"/usr/bin/bash",
                ["Test User", "ACME", "+123", "+321", "test"],
            ),
            (
                # one field, no commas
                "testuser",
                b"testuser:x:1000:1000:Test:home/testuser:/usr/bin/bash",
                ["Test", "", "", "", ""],
            ),
        ]

        for tc in testcases:
            with patch("subprocess.check_output") as mock_cmd:
                mock_cmd.return_value = tc[1]
                result = local_users.get_gecos(tc[0])
                self.assertEqual(result, tc[2])

    def test_update_gecos(self):
        # ensure that only fields that changed are passed to chfn
        testcase = namedtuple(
            "testcase", ["prev", "updated", "expected", "should_call"]
        )

        # NOTE: order of chfn flags in GECOS fields order is: -f -r -w -h -o
        testcases = [
            testcase(["", "", "", "", ""], ["", "", "", "", ""], [], False),
            testcase(["A", "B", "0", "1", "2"], ["A", "B", "0", "1", "2"], [], False),
            testcase(
                ["A", "B", "0", "1", "2"],
                ["A", "X", "9", "1", "2"],
                ["-r", "X", "-w", "9"],
                True,
            ),
            testcase(["A", "", "", "", ""], ["B", "", "", "", ""], ["-f", "B"], True),
        ]

        for tc in testcases:
            with patch("lib.local_users.get_gecos") as mock_prev, patch(
                "subprocess.check_call"
            ) as mock_call:
                u = local_users.User("test", tc.updated, "")
                mock_prev.return_value = tc.prev
                local_users.update_gecos(u)

                if tc.should_call:
                    expected_cmd = ["chfn"] + tc.expected + ["test"]
                    mock_call.assert_called_once_with(expected_cmd)
                else:
                    mock_call.assert_not_called()

    def test_rename_group(self):
        with patch("subprocess.check_call") as mock_call:
            # the old and the new name are identical - ensure groupmod not called
            local_users.rename_group("test1", "test1")
            mock_call.assert_not_called()

            # ensure it is called when renaming test1 to test2
            local_users.rename_group("test1", "test2")
            mock_call.assert_called_once_with(["groupmod", "-n", "test2", "test1"])

    def test_get_user_membership(self):
        with patch("subprocess.check_output") as mock_call:
            expected = ["test", "group1", "group2", "group3"]
            mock_call.return_value = b"test : test group1 group2 group3"
            result = local_users.get_user_membership("test")
            self.assertListEqual(result, expected)

    def test_get_group_users(self):
        with patch("subprocess.check_output") as mock_call:
            mock_call.return_value = b"acme:x:1001:test1,test2,test3"
            result = local_users.get_group_users("acme")
            self.assertListEqual(result, ["test1", "test2", "test3"])

    def test_get_group_users_empty(self):
        with patch("subprocess.check_output") as mock_call:
            mock_call.return_value = b"acme:x:1001:"
            result = local_users.get_group_users("acme")
            self.assertListEqual(result, [])
