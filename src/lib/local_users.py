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

"""Utility library for manipulating user accounts and groups."""

import os
import shutil
import re
import subprocess
import logging
import tempfile
import grp
from collections import namedtuple

from charmhelpers.core import host

log = logging.getLogger(__name__)

User = namedtuple("User", ["name", "gecos", "ssh_keys"])

HOME_DIR_PATH = "/home"
SUDOERS_FILE = "/etc/sudoers.d/70-local-users-charm"


def add_user(username, shell="/bin/bash", home_dir=None, gecos=None):
    """Add a user to the system."""
    cmd = ["adduser"]
    cmd.extend(["--disabled-password"])
    cmd.extend(["--shell", shell])
    if home_dir:
        cmd.extend(["--home", str(home_dir)])
    if gecos:
        cmd.extend(["--gecos", ",".join(gecos)])
    cmd.append(username)
    subprocess.check_call(cmd)


def configure_user(user, group):
    """Idempotently apply requested User configuration.

    Create a new account if it doesn't exist. Ensure it belongs to the requested group.
    Ensure that the SSH public key is set up and GECOS is up to date.
    """
    log.debug("configuring user {}".format(user.name))
    if not host.user_exists(user.name):
        add_user(
            user.name,
            home_dir=os.path.join("/home", user.name),
            gecos=user.gecos,
        )
    host.add_user_to_group(user.name, group)
    set_ssh_authorized_keys(user)
    update_gecos(user)


def delete_user(username, backupdir):
    """Remove a user from the system."""
    cmd = ["deluser", "--remove-home", "--backup", "--backup-to", backupdir, username]
    subprocess.check_call(cmd)


def get_user_membership(username):
    """Return the list of groups that the user is a member of."""
    cmd = ["groups", username]
    raw_output = subprocess.check_output(cmd)
    output = raw_output.decode().strip()
    groups = output.split(":")[1].strip()
    return groups.split(" ")


def is_unmanaged_user(username, expected_group):
    """Test whether this user exists but doesn't belong to the `expected_group`."""
    if host.user_exists(username):
        groups = get_user_membership(username)
        if expected_group not in groups:
            return True
    return False


def get_group_users(group):
    """Return a list of users belonging to a group on the system."""
    cmd = ["getent", "group", group]
    raw_output = subprocess.check_output(cmd)
    output = raw_output.decode().rstrip()
    users_field = output.rstrip().split(":")[3]
    users = users_field.split(",")
    # ensure that empty strings will not be returned
    return list(filter(None, users))


def remove_group(group_name):
    """Remove a group if empty."""
    cmd = ["delgroup", "--only-if-empty", group_name]
    subprocess.check_call(cmd)


def rename_group(old_name, new_name):
    """Rename the `old_name` group to `new_name` using `groupmod` command."""
    if old_name != new_name:
        cmd = ["groupmod", "-n", new_name, old_name]
        subprocess.check_call(cmd)


def set_ssh_authorized_keys(user):
    """Idempotently set up the SSH public key in `authorized_keys`."""
    comment = "# charm-local-users"
    authorized_keys = []
    for ssh_key in user.ssh_keys:
        authorized_key = " ".join([ssh_key, comment])
        authorized_keys.append(authorized_key)
    ssh_path = os.path.join(HOME_DIR_PATH, user.name, ".ssh")
    authorized_keys_path = os.path.join(ssh_path, "authorized_keys")
    if not os.path.exists(ssh_path):
        os.makedirs(ssh_path, mode=0o700)
    os.chmod(ssh_path, 0o700)
    shutil.chown(ssh_path, user=user.name, group=user.name)

    # get currently configured keys
    current_keys = []
    if os.path.exists(authorized_keys_path):
        with open(authorized_keys_path, "r") as keys_file:
            current_keys = keys_file.readlines()
            keys_file.close()

    # keep the non-managed keys
    regex = re.compile(r"charm-local-users")
    new_keys = [i for i in current_keys if not regex.search(i)]
    # (re-)add the charm managed key
    for authorized_key in authorized_keys:
        new_keys.append(authorized_key + "\n")
    with open(authorized_keys_path, "w+") as keys_file:
        for key in new_keys:
            keys_file.write(key)
        keys_file.close()

    # ensure correct permissions
    if os.path.exists(authorized_keys_path):
        os.chmod(authorized_keys_path, 0o600)
        shutil.chown(authorized_keys_path, user=user.name, group=user.name)


def get_gecos(username):
    """Get user's GECOS from the passwd file."""
    cmd = ["getent", "passwd", username]
    raw_output = subprocess.check_output(cmd)
    output = raw_output.decode().rstrip()
    gecos_field = output.rstrip().split(":")[4]
    gecos_list = gecos_field.split(",")
    gecos = [""] * 5
    for i in range(5):
        try:
            gecos[i] = gecos_list[i]
        except IndexError:
            gecos[i] = ""
    return gecos


def update_gecos(user):
    """Update GECOS info for a given user."""
    current_gecos = get_gecos(user.name)
    cmd = ["chfn"]
    chfn_gecos_flags = ["-f", "-r", "-w", "-h", "-o"]
    for i in range(5):
        if user.gecos[i] != current_gecos[i]:
            cmd.extend([chfn_gecos_flags[i], user.gecos[i]])
    cmd.append(user.name)
    if len(cmd) > 2:
        subprocess.check_call(cmd)


def parse_gecos(raw):
    """Convert a raw GECOS string into a 5 elements list."""
    gecos = [""] * 5
    fields = raw.split(",")
    for i in range(5):
        try:
            gecos[i] = fields[i]
        except IndexError:
            gecos[i] = ""
    return gecos


def check_sudoers_file(sudoers):
    if sudoers == "":
        log.debug("Skipping sudoers check, config is not set.")
        return 0
    sudoers_file = tempfile.NamedTemporaryFile(delete=False)
    sudoers_file.write(sudoers.encode())
    sudoers_file.close()
    check_cmd = "visudo -c -f {}".format(sudoers_file.name)
    log.debug("Checking sudoers file: {}".format(check_cmd))
    run = subprocess.run(
        check_cmd.split(), stdout=subprocess.PIPE, stderr=subprocess.PIPE
    )
    log.debug("Stdout: {}, Stderr: {}".format(run.stdout, run.stderr))
    log.debug("Cleaning up {}".format(sudoers_file.name))
    os.remove(sudoers_file.name)
    return run.returncode


def write_sudoers_file(sudoers):
    if sudoers == "":
        if os.path.exists(SUDOERS_FILE):
            os.remove(SUDOERS_FILE)
    else:
        NEW_FILE = SUDOERS_FILE + ".new"
        with open(NEW_FILE, "w+") as sudoers_file:
            sudoers_file.write("# This file is managed by Juju, do not edit.\n")
            sudoers_file.write(sudoers)
            sudoers_file.close()
        os.chmod(NEW_FILE, 0o440)
        os.replace(NEW_FILE, SUDOERS_FILE)


def group_exists(groupname):
    """Check if a group exists."""
    try:
        grp.getgrnam(groupname)
        group_exists = True
    except KeyError:
        group_exists = False
    return group_exists


def add_group(group_name, system_group=False, gid=None):
    """Add a group to the system.

    Will log but otherwise succeed if the group already exists.
    :param str group_name: group to create
    :param bool system_group: Create system group
    :param int gid: GID for user being created
    :returns: The password database entry struct, as returned by `grp.getgrnam`
    """
    try:
        group_info = grp.getgrnam(group_name)
        log('group {0} already exists!'.format(group_name))
        if gid:
            group_info = grp.getgrgid(gid)
            log('group with gid {0} already exists!'.format(gid))
    except KeyError:
        log('creating group {0}'.format(group_name))
        add_new_group(group_name, system_group, gid)
        group_info = grp.getgrnam(group_name)
    return group_info


def add_new_group(group_name, system_group=False, gid=None):
    cmd = ['addgroup']
    if gid:
        cmd.extend(['--gid', str(gid)])
    if system_group:
        cmd.append('--system')
    else:
        cmd.extend([
            '--group',
        ])
    cmd.append(group_name)
    subprocess.check_call(cmd)
