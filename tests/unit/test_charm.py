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
import json
from unittest.mock import patch, mock_open, call

from lib.local_users import User
from src.charm import CharmLocalUsersCharm
from ops.model import ActiveStatus, BlockedStatus
from ops.testing import Harness


class TestCharm(unittest.TestCase):
    def setUp(self):
        self.harness = Harness(CharmLocalUsersCharm)
        self.addCleanup(self.harness.cleanup)
        self.harness.begin()

    @patch("builtins.open", new_callable=mock_open)
    @patch("os.makedirs")
    @patch("src.charm.group_exists")
    @patch("src.charm.rename_group")
    @patch("src.charm.add_group")
    def test_config_changed(
        self, mock_add_group, mock_rename, mock_exists, mock_mkdir, mock_open
    ):
        # group doesn't exist yet
        mock_exists.return_value = False

        # correct configuration
        self.harness.update_config(
            {
                "group": "testgroup",
                "remote-user-source": "https://localhost:4443",
                "cert": "dGVzdC1jb250ZW50Cg==",
            }
        )

        # a new group must be created
        mock_add_group.assert_called_once_with("testgroup")
        # first execution, no rename expected
        mock_rename.assert_not_called()
        # check if cert is written
        mock_open.assert_called_once_with("/etc/ssl/certs/remote-cert.pem", "w")
        mock_open().write.assert_called_once_with("test-content\n")

        # everything went well
        self.assertIsInstance(self.harness.model.unit.status, ActiveStatus)

    @patch("os.makedirs")
    @patch("src.charm.group_exists")
    @patch("builtins.open")
    def test_config_changed_no_cert(self, mock_open, mock_exists, _):
        self.harness.update_config(
            {
                "remote-user-source": "https://localhost:4443",
            }
        )
        mock_exists.return_value = True
        mock_open.assert_not_called()
        self.assertIsInstance(self.harness.model.unit.status, BlockedStatus)

    @patch("os.makedirs")
    @patch("src.charm.group_exists")
    def test_config_changed_no_source(self, mock_exists, _):
        self.harness.update_config(
            {
                "remote-user-source": "",
            }
        )
        mock_exists.return_value = True
        self.assertIsInstance(self.harness.model.unit.status, BlockedStatus)

    @patch("builtins.open", new_callable=mock_open)
    @patch("os.makedirs")
    @patch("src.charm.group_exists")
    def test_bad_cert(self, mock_exists, mock_mkdir, mock_open):
        # group doesn't exist yet
        mock_exists.return_value = True

        # correct configuration
        self.harness.update_config(
            {
                "remote-user-source": "https://localhost:4443",
                "cert": "dVzdC1jb250ZW50Cg==",
            }
        )

        # everything went well
        self.assertIsInstance(self.harness.model.unit.status, BlockedStatus)

    @patch("os.makedirs")
    def test_empty_group_config(self, _):
        self.harness.update_config({"group": ""})
        self.assertIsInstance(self.harness.model.unit.status, BlockedStatus)

    @patch("os.makedirs")
    @patch("src.charm.group_exists")
    @patch("builtins.open")
    @patch("src.charm.requests.get")
    def test_get_users(self, mock_requests, mock_open, mock_exists, _):
        mock_exists.return_value = True
        self.harness.update_config(
            {
                "remote-user-source": "https://localhost:4443",
                "cert": "dGVzdC1jb250ZW50Cg==",
            }
        )

        # specify the return value of the get() method
        mock_requests.return_value.text = (
            '{"testuer1":{"gecos": "value1", "keys": ["dsf", "sd"]}}'
        )
        self.harness.charm.get_users()

    @patch("os.makedirs")
    @patch("src.charm.group_exists")
    @patch("builtins.open")
    @patch("src.charm.requests.get")
    @patch("ops.ActionEvent")
    @patch("src.charm.is_unmanaged_user")
    @patch("src.charm.get_group_users")
    @patch("src.charm.configure_user")
    def test_sync_users(
        self,
        mock_config_user,
        mock_get_group_users,
        mock_unmanaged,
        mock_action,
        mock_requests,
        mock_open,
        mock_exists,
        _,
    ):
        mock_exists.return_value = True
        mock_unmanaged.return_value = False

        self.harness.update_config(
            {
                "remote-user-source": "https://localhost:4443",
                "cert": "dGVzdC1jb250ZW50Cg==",
            }
        )

        # specify the return value of the get() method
        usermap = {
            "testuer1": {"gecos": "value1", "keys": ["dsf", "sd"]},
            "testuer2": {"gecos": "value2", "keys": ["dsf", "sd"]},
            "testuer3": {"gecos": "value3", "keys": ["dsf", "sd"]},
            "testuer4": {"gecos": "value4", "keys": ["dsf", "sd"]},
        }
        group = "charm-managed"
        auth_key_path = "$HOME/.ssh/authorized_keys"
        mock_requests.return_value.text = json.dumps(usermap)
        self.harness.charm._on_sync_users_action(mock_action)
        mock_get_group_users.assert_called_once_with(group)
        calls = []
        for username in usermap:
            user_obj = User(
                username, usermap[username]["gecos"], usermap[username]["keys"]
            )
            calls.append(call(user_obj, group, auth_key_path))

        mock_config_user.assert_has_calls(calls)


#    test wrong cert
#    test malformed data
#    test action user sync
#    test action user sync wrong data
