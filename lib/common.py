# Copyright 2024 Canonical
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

"""Utility library for manipulating user accounts and groups."""

import requests
import time
import hashlib
import pathlib
import logging
import json

from local_users import (
    configure_user,
    delete_user,
    get_group_users,
    is_unmanaged_user,
    User,
)

log = logging.getLogger(__name__)
CHARM_DATA = pathlib.Path("/var/lib/advanced-auth")
CONFIG_FILE = CHARM_DATA / "config.yaml"
TIMESTAMP_RANGE = 2


class AdvancedAuthSyncer:
    """Helper Class to sync users"""

    def __init__(self, config=None, event=None):
        """Initialise the helper."""
        if config:
            self.config = config
        else:
            with open(CONFIG_FILE, "r") as f:
                self.config = json.load(f)

        self.event = event

    def write_config(self):
        CONFIG_FILE.parents[0].mkdir(parents=True, exist_ok=True)
        with open(CONFIG_FILE, "w", encoding="utf-8") as f:
            json.dump(self.config, f, ensure_ascii=False)

    def _read_config(self):
        with open(CONFIG_FILE, "r", encoding="utf-8") as f:
            self.config = json.load(f)

    def _verify_config(self):
        # TODO write this function
        return True

    def _get_remote_users(self):
        """Return prepared user list from users config.
        Return error message string on error"""

        # TODO: try except this
        r = requests.get(self.config["remote-user-source"])

        if not _check_timestamp(r.headers["Timestamp"]):
            msg = "Timestamp difference to portal too high"
            self._log(msg)
            return

        if not self._check_validity(
            r.headers["Sso-Token"],
            r.headers["Timestamp"],
        ):
            msg = "Tokens don't match!"
            self._log(msg)
            return

        users = json.loads(r.text)
        userlist = []

        self._log(f"List of users: {list(users.keys())}", "DEBUG")

        for username in users:
            user = User(username, users[username]["gecos"], users[username]["keys"])
            userlist.append(user)

        return userlist

    def sync_users(self):
        """sync users"""
        group = self.config["group"]
        userlist = self._get_remote_users()

        # will return NoneType if verification fails
        if userlist is None:
            return

        # check if there are any conflicts between the user list in the config and on the unit,
        # back out if so unless the config flag 'allow-existing-users' is set to True
        if not self._check_unmanaged(userlist):
            return

        # remove users that are no longer in the config but still exist on the unit
        current_users = get_group_users(group)
        remote_usernames = [u.name for u in userlist]
        users_to_remove = set(current_users) - set(remote_usernames)
        users_to_add = set(remote_usernames) - set(current_users)

        if not self._remove_users(users_to_remove):
            return

        # configure user accounts specified in the config
        authorized_keys_path = self.config["ssh-authorized-keys"]
        for user in userlist:
            configure_user(user, group, authorized_keys_path)

        if self.event:
            self.event.set_results(
                {"users-added": users_to_add, "users-removed": users_to_remove}
            )

    def _check_validity(self, portal_token, timestamp):
        """Calculate token and checks if it matches the message token."""
        token = f'{timestamp}{self.config["portal-secret"]}'
        h = hashlib.sha512()
        h.update(token.encode("utf-8"))
        return h.hexdigest() == portal_token

    def _log(self, msg, level="ERROR"):
        lvls = {
            "ERROR": logging.ERROR,
            "WARNING": logging.WARNING,
            "DEBUG": logging.DEBUG,
        }
        log.log(lvls[level], msg)
        if self.event is not None:
            if level == "ERROR":
                self.event.fail(msg)
            else:
                self.event.log(msg)

    def _check_unmanaged(self, userlist):
        unmanaged_users = []
        for user in userlist:
            if is_unmanaged_user(user.name, self.config["group"]):
                unmanaged_users.append(user.name)
        if len(unmanaged_users) > 0:
            msg = "users {} already exist and are not members of {}".format(
                unmanaged_users, self.config["group"]
            )
            if not self.config["allow-existing-users"]:
                self._log(msg)
                return False
            self._log(msg, "WARNING")
        return True

    def _remove_users(self, users_to_remove):
        """Remove users from the machine, but only if run as an acton with `force` set to true"""
        force = (
            self.event is not None
            and "force" in self.event.params
            and self.event.params["force"]
        )
        if users_to_remove:
            if len(users_to_remove) > 1 and not force:
                msg = "more than 1 user to remove. Danger!\n"
                msg += f"Users to remove: {list(users_to_remove)}"
                self._log(msg)
                return False

            self._log(f"removing users: {list(users_to_remove)}", "DEBUG")
            for u in users_to_remove:
                delete_user(u, self.config["backup-path"])
        return True


def _check_timestamp(timestamp):
    """Check if timestamp is withing accepted range."""
    return abs(int(time.time()) - int(timestamp)) < TIMESTAMP_RANGE
