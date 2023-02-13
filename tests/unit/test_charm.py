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

import unittest
from unittest.mock import patch
from subprocess import CompletedProcess

from src.charm import CharmLocalUsersCharm
from ops.model import ActiveStatus, BlockedStatus
from ops.testing import Harness


class TestCharm(unittest.TestCase):
    def setUp(self):
        self.harness = Harness(CharmLocalUsersCharm)
        self.addCleanup(self.harness.cleanup)
        self.harness.begin()

    @patch("os.makedirs")
    @patch("subprocess.run")
    @patch("src.charm.get_lp_ssh_keys")
    @patch("charmhelpers.core.host.group_exists")
    @patch("src.charm.rename_group")
    @patch("src.charm.get_group_users")
    @patch("src.charm.add_group")
    @patch("src.charm.configure_user")
    def test_config_changed(
        self,
        mock_conf_user,
        mock_add_group,
        mock_get_gr_users,
        mock_rename,
        mock_exists,
        mock_get_lp_keys,
        mock_sub_run,
        _,
    ):
        # group doesn't exist yet
        mock_exists.return_value = False

        mock_sub_run.return_value = CompletedProcess(
            args=["ssh-import-id", "-o", "-", "lp:test_lpuser"],
            returncode=0,
            stdout=b"2023-01-01 10:10:10,100 INFO Authorized key ['2048',\
                'SHA256:SOMESHA', 'test_lpuser@home', '(RSA)']\n2023-01-01 \
                10:10:10,101 INFO Authorized key \
                ['3072', 'SHA256:ANOTHERSHA', 'test_lpuser@work', '(RSA)'] \
                \nssh-rsa ABC test_lpuser@home # ssh-import-id lp:test_lpuser \
                \n\nssh-rsa XYZ test_lpuser@work # ssh-import-id lp:test_lpuser \
                \n\n2023-01-01 10:10:10,112 INFO [2] SSH keys [Authorized]\n",
        )

        # correct configuration
        self.harness.update_config(
            {
                "group": "testgroup",
                "users": "test1;Test 1;key1\ntest2;Test 2;key2\ntest3;Test3;lp:test_lpuser",
            }
        )
        # a new group must be created
        mock_add_group.assert_called_once_with("testgroup")
        # first execution, no rename expected
        mock_rename.assert_not_called()
        mock_get_gr_users.assert_called_once()
        # ssh keys fetched for launchpad user
        mock_get_lp_keys.assert_called_once_with("lp:test_lpuser")
        # 3 users to configure
        self.assertEqual(mock_conf_user.call_count, 3)
        # everything went well
        self.assertIsInstance(self.harness.model.unit.status, ActiveStatus)

    @patch("os.makedirs")
    @patch("charmhelpers.core.host.group_exists")
    @patch("src.charm.rename_group")
    @patch("src.charm.get_group_users")
    @patch("src.charm.add_group")
    @patch("src.charm.configure_user")
    def test_config_changed_invalid_userlist(
        self,
        mock_conf_user,
        mock_add_group,
        mock_get_gr_users,
        mock_rename,
        mock_exists,
        _,
    ):
        # group doesn't exist yet
        mock_exists.return_value = False

        # empty users list
        self.harness.update_config(
            {"group": "testgroup", "users": ";User with no name;\n"}
        )

        # a new group must be created
        mock_add_group.assert_called_once_with("testgroup")
        # first execution, no rename expected
        mock_rename.assert_not_called()
        # we shouldn't be comapring with existing users if the config is invalid
        mock_get_gr_users.assert_not_called()
        # no users to configure
        mock_conf_user.assert_not_called()
        # we should enter blocked state
        self.assertIsInstance(self.harness.model.unit.status, BlockedStatus)

    @patch("os.makedirs")
    def test_empty_group_config(self, _):
        self.harness.update_config({"group": "", "users": "test;;"})
        self.assertIsInstance(self.harness.model.unit.status, BlockedStatus)
