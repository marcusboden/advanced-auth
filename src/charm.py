#!/usr/bin/env python3
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

"""Create and manage local user accounts and groups with Juju."""

import logging
import base64
import json
import os
import requests

from ops.charm import CharmBase
from ops.framework import StoredState
from ops.main import main
from ops.model import ActiveStatus, BlockedStatus

from local_users import (
    add_group,
    configure_user,
    check_sudoers_file,
    delete_user,
    get_group_users,
    group_exists,
    is_unmanaged_user,
    remove_group,
    rename_group,
    User,
    write_sudoers_file,
)

log = logging.getLogger(__name__)


class CharmLocalUsersCharm(CharmBase):
    """Charm the service."""

    _stored = StoredState()

    def __init__(self, *args):
        super().__init__(*args)
        self.framework.observe(self.on.install, self.on_install)
        self.framework.observe(self.on.config_changed, self.on_config_changed)
        self.framework.observe(self.on.stop, self.on_stop)
        self.framework.observe(self.on.sync_users_action, self._on_sync_users_action)
        self.cert_file = "/etc/ssl/certs/remote-cert.pem"
        self._stored.set_default(group="")

    def on_install(self, _):
        self.unit.status = ActiveStatus()

    def on_config_changed(self, _):
        """Create and update system users and groups to match the config.

        Ensure that the charm managed group exists on the unit.
        Remove any users in charm managed group who are not in the current 'users' config value.
        Resolve any differences between users listed in the config and their equivalent system
        users (i.e. change in GECOS or SSH public keys).
        Add any new users who are in UserList but not CharmManagedGroup.
        """
        # ensure that directory for home dir backups exists
        backup_path = self.config["backup-path"]
        if not os.path.exists(backup_path):
            os.makedirs(backup_path, mode=0o700)

        # configure charm managed group
        group = self.config["group"]
        if not group:
            self.unit.status = BlockedStatus("'group' config option value is required")
            return

        if not group_exists(group):
            if self._stored.group and self._stored.group != group:
                log.debug(
                    "renaming charm managed group: '%s' to '%s'",
                    self._stored.group,
                    group,
                )
                rename_group(self._stored.group, group)
            else:
                add_group(group)

        # save the current managed group name in StoredState so that the charm can detect if rename
        # is needed on future config_changed events
        self._stored.group = group

        if not self.config["remote-user-source"]:
            error_msg = "remote-user-source not specified"
            log.error(error_msg)
            self.unit.status = BlockedStatus(error_msg)
            return

        if self.config["cert"]:
            with open(self.cert_file, "w") as f:
                try:
                    f.write(base64.b64decode(self.config["cert"]).decode("utf-8"))
                except base64.binascii.Error as e:
                    log.error(e)
                    self.unit.status = BlockedStatus(e)
                    return

        else:
            error_msg = "remote-user-source needs cert to be configured"
            log.error(error_msg)
            self.unit.status = BlockedStatus(error_msg)
            return

        # Configure custom /etc/sudoers.d file
        sudoers = self.config["sudoers"]
        error = check_sudoers_file(sudoers)
        if error:
            msg = "parse error in sudoers config, check juju debug-log for more information"
            self.unit.status = BlockedStatus(msg)
            return
        else:
            write_sudoers_file(sudoers)

        self.unit.status = ActiveStatus()

    def _on_sync_users_action(self, event):
        # parse user list from the config
        group = self.config["group"]

        # sync remote users only via action
        userlist = self.get_users()

        # check if there are any conflicts between the user list in the config and on the unit,
        # back out if so unless the config flag 'allow-existing-users' is set to True
        unmanaged_users = []
        for user in userlist:
            if is_unmanaged_user(user.name, group):
                unmanaged_users.append(user.name)
        if len(unmanaged_users) > 0:
            msg = "users {} already exist and are not members of {}".format(
                unmanaged_users, group
            )
            if not self.config["allow-existing-users"]:
                log.error(msg)
                self.unit.status = BlockedStatus(msg)
                return
            log.warning(msg)

        # remove users that are no longer in the config but still exist on the unit
        current_users = get_group_users(group)
        remote_usernames = [u.name for u in userlist]
        users_to_remove = set(current_users) - set(remote_usernames)
        users_to_add = set(remote_usernames) - set(current_users)
        if users_to_remove:
            if len(users_to_remove) > 1 and (
                ("force" not in event.params or not event.params["force"])
            ):
                msg = "more than 1 user to remove. Danger!\n"
                msg += f"Users to remove: {list(users_to_remove)}"
                log.error(msg)
                event.fail(msg)
                return

            log.debug(f"removing users: {list(users_to_remove)}")
            event.log(f"removing users: {list(users_to_remove)}")
            for u in users_to_remove:
                delete_user(u, self.config["backup-path"])

        # configure user accounts specified in the config
        authorized_keys_path = self.config["ssh-authorized-keys"]
        for user in userlist:
            configure_user(user, group, authorized_keys_path)

        event.set_results(
            {"users-added": users_to_add, "users-removed": users_to_remove}
        )

    def on_stop(self, _):
        """Remove charm managed users and group from the machine."""
        group = self.config["group"]
        backup_path = self.config["backup-path"]
        users = get_group_users(group)
        for user in users:
            delete_user(user, backup_path)
        remove_group(group)
        self.unit.status = ActiveStatus()

    def get_users(self):
        resp = requests.get(self.config["remote-user-source"], verify=self.cert_file)
        """Return prepared user list from users config.
        Return error message string on error"""
        users = json.loads(resp.text)
        userlist = []

        log.debug(f"List of users: {list(users.keys())}")

        for username in users:
            user = User(username, users[username]["gecos"], users[username]["keys"])
            userlist.append(user)

        return userlist


if __name__ == "__main__":
    main(CharmLocalUsersCharm)
