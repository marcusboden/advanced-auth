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
import os
import pathlib

from ops.charm import CharmBase
from ops.framework import StoredState
from ops.main import main
from ops.model import ActiveStatus, BlockedStatus

from local_users import (
    add_group,
    check_sudoers_file,
    delete_user,
    get_group_users,
    group_exists,
    remove_group,
    rename_group,
    write_sudoers_file,
)

from common import AdvancedAuthSyncer, CHARM_DATA

log = logging.getLogger(__name__)

CRON_SCRIPT_PATH = CHARM_DATA / "cron-sync.py"
CRON_PATH = pathlib.Path("/etc/cron.d/advanced-auth-sync")


class CharmLocalUsersCharm(CharmBase):
    """Charm the service."""

    _stored = StoredState()

    def __init__(self, *args):
        super().__init__(*args)
        self.framework.observe(self.on.install, self.on_install)
        self.framework.observe(self.on.config_changed, self.on_config_changed)
        self.framework.observe(self.on.stop, self.on_stop)
        self.framework.observe(self.on.sync_users_action, self._on_sync_users_action)
        self._stored.set_default(group="")

    def on_install(self, _):
        self.unit.status = ActiveStatus()

    def _install_cron_script(self):
        cron_template = pathlib.Path(
            self.charm_dir / "templates/cron-sync.py"
        ).read_text()
        cron_script = cron_template.replace("REPLACE_CHARMDIR", str(self.charm_dir))

        fd = os.open(str(CRON_SCRIPT_PATH), os.O_CREAT | os.O_WRONLY, 0o755)
        with open(fd, "w") as f:
            f.write(cron_script)

    def _install_cron(self):
        cron_job = f"* * * * * root {CRON_SCRIPT_PATH}\n"
        CRON_PATH.write_text(cron_job)

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

        if not self.config["portal-secret"]:
            error_msg = "Config option 'protal-secret' needs to be configured"
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

        syncer = AdvancedAuthSyncer(self._get_config())

        log.warning(self._get_config)
        syncer.write_config()

        self._install_cron_script()
        self._install_cron()

        self.unit.status = ActiveStatus()

    def _on_sync_users_action(self, event):

        syncer = AdvancedAuthSyncer(self._get_config(), event)
        syncer.sync_users()
        # parse user list from the config

    def on_stop(self, _):
        """Remove charm managed users and group from the machine."""
        group = self.config["group"]
        backup_path = self.config["backup-path"]
        users = get_group_users(group)
        for user in users:
            delete_user(user, backup_path)
        remove_group(group)
        # TODO: Remove config file
        self.unit.status = ActiveStatus()

    def _get_config(self):
        """Get the necessary config values for helper class"""
        keys = (
            "portal-secret",
            "remote-user-source",
            "backup-path",
            "group",
            "ssh-authorized-keys",
            "allow-existing-users",
        )
        return {k: self.config[k] for k in keys}


if __name__ == "__main__":
    main(CharmLocalUsersCharm)
