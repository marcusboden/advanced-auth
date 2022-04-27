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
import unittest
from collections import namedtuple
from tempfile import TemporaryDirectory
from unittest.mock import patch

from lib import local_users


class TestLocalUsers(unittest.TestCase):
    @patch("os.chmod")
    def test_set_ssh_authorized_keys_update(self, _):
        testuser = local_users.User(
            "testuser", ["Test User", "", "", "", ""], "ssh-rsa ABC testuser@testhost"
        )

        testuser2 = local_users.User(
            "testuser", ["Test User", "", "", "", ""], "ssh-rsa XYZ testuser@testhost"
        )

        with TemporaryDirectory() as fake_home:
            testfile_path = os.path.join(
                fake_home, "testuser", ".ssh", "authorized_keys"
            )
            with patch("lib.local_users.HOME_DIR_PATH", fake_home):
                local_users.set_ssh_authorized_keys(testuser)
                with open(testfile_path, "r") as f:
                    keys = f.readlines()
                    self.assertIn(
                        "ssh-rsa ABC testuser@testhost # charm-local-users\n", keys
                    )

                # update the key
                local_users.set_ssh_authorized_keys(testuser2)
                with open(testfile_path, "r") as f:
                    keys = f.readlines()
                    self.assertIn(
                        "ssh-rsa XYZ testuser@testhost # charm-local-users\n", keys
                    )
                    self.assertNotIn(
                        "ssh-rsa ABC testuser@testhost # charm-local-users\n", keys
                    )

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
                b"testuser:x:1000:1000:Test User,ACME,+123,+321,test:/home/testuser:/usr/bin/bash",
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
