"""Functional tests for charm-local-users."""
from subprocess import run
from tempfile import NamedTemporaryFile
import unittest

import zaza

from tests.modules.utils import generate_keypair


class TestLocalUsers(unittest.TestCase):
    """Tests related to the local-users charm."""

    @classmethod
    def setUpClass(cls):
        """Test setup."""
        cls.app_name = "local-users"
        cls.principal_app_name = "ubuntu"
        cls.principal_unit_name = cls.principal_app_name + "/0"
        cls.ssh_pub_key, cls.ssh_priv_key = generate_keypair()

    def wait_for_application_states(self):
        """Wait for application states are ready.

        zaza.model.block_until_all_applications_idle() seems to not wait for
        (config-changed) to settle. Causing a race.
        """
        zaza.model.wait_for_agent_status()
        zaza.model.block_until_all_units_idle()

    def run_command_ssh(self, user, command, key=None):
        """Run a command on the unit via ssh return stdout, stderr and returncode as dict."""
        key = key or self.ssh_priv_key
        with NamedTemporaryFile(
            mode="w"
        ) as private_key_file, NamedTemporaryFile() as known_hosts:
            private_key_file.write(key)
            private_key_file.flush()

            cmd = [
                "ssh",
                "-o",
                "StrictHostKeyChecking=no",
                # disables the 'Permanently added to list of known hosts'
                "-o",
                "LogLevel=ERROR",
                "-o",
                "IdentitiesOnly=yes",
                "-o",
                f"UserKnownHostsFile={known_hosts.name}",
                "-i",
                private_key_file.name,
                "-l",
                user,
                zaza.model.get_app_ips(self.principal_app_name)[0],
                command,
            ]

            output = run(cmd, capture_output=True)
            # some login-processes linger, which can cause problems if the user will be deleted
            # namely systemd and sd-pam.
            zaza.model.run_on_unit(self.principal_unit_name, f"pkill -u {user}")
            return {
                "stdout": output.stdout.decode().strip(),
                "stderr": output.stderr.decode().strip(),
                "returncode": output.returncode,
            }

    def test_10_default_ssh_login(self):
        """Test the default ssh login functionality.

        The path of the authorized_keys file can be configured,
        we want the default configuration to allow logins
        via standard paths.
        """

        zaza.model.set_application_config(
            self.app_name, {"users": f"testuser;Test User;{self.ssh_pub_key}"}
        )
        self.wait_for_application_states()

        self.assertEqual(
            self.run_command_ssh("testuser", "whoami")["stdout"], "testuser"
        )

    def test_11_ssh_custom_authorized_keys_file(self):
        """Test the ssh-authorized-keys config option."""
        zaza.model.set_application_config(
            self.app_name,
            {"ssh-authorized-keys": "/etc/ssh/user-authorized-keys/$USER"},
        )
        self.wait_for_application_states()

        expected_ssh_pub_key = self.ssh_pub_key + " # charm-local-users\n"
        zaza.model.block_until_file_has_contents(
            application_name=self.principal_app_name,
            remote_file="/etc/ssh/user-authorized-keys/testuser",
            expected_contents=expected_ssh_pub_key,
        )

    def test_12_update_ssh_key(self):
        """Test replacing the SSH key with a new one"""
        second_pub_key, second_priv_key = generate_keypair()
        zaza.model.set_application_config(
            self.app_name,
            {
                "users": f"testuser;Test User;{second_pub_key}",
                "ssh-authorized-keys": "/home/$USER/.ssh/authorized_keys",
            },
        )
        self.wait_for_application_states()

        self.assertEqual(
            self.run_command_ssh("testuser", "whoami", second_priv_key)["stdout"],
            "testuser",
        )

    def test_13_allow_existing_users(self):
        """Test if the allow-existing-user option works

        This creates a non-charm user and then tries to manage it. First
        without the allow-existing-user option to see if it correctly blocks
        and then with said option"""
        zaza.model.set_application_config(
            self.app_name,
            {
                "allow-existing-users": "false",
                "users": f"testuser;Test User;{self.ssh_pub_key}",
            },
        )
        user = "non-charm-user"
        cmd = ["adduser", "--disabled-password", "--gecos", "test", user]
        zaza.model.run_on_unit(self.principal_unit_name, " ".join(cmd))

        zaza.model.set_application_config(
            self.app_name, {"users": f"{user};Test User;{self.ssh_pub_key}"}
        )

        zaza.model.wait_for_agent_status()
        zaza.model.wait_for_application_states(
            states={
                self.app_name: {
                    "workload-status": "blocked",
                    "workload-status-message-regex": "^.*$",
                },
                self.principal_app_name: {
                    "workload-status": "active",
                    "workload-status-message-regex": "^$",
                },
            },
        )

        zaza.model.set_application_config(
            self.app_name, {"allow-existing-users": "true"}
        )
        self.wait_for_application_states()

        self.assertEqual(self.run_command_ssh(user, "whoami")["stdout"], user)

        # get group name from config
        conf = zaza.model.get_application_config(self.app_name)
        ret = zaza.model.run_on_unit(self.principal_unit_name, f"groups {user}")
        self.assertIn(conf["group"]["value"], ret["Stdout"].strip().split(" "))

    def test_14_add_and_remove_users(self):
        """Test if users are added and removed from the system correctly

        This test first adds a test-user and then removes it again"""

        zaza.model.set_application_config(
            self.app_name, {"users": f"testuser;Test User;{self.ssh_pub_key}"}
        )
        self.wait_for_application_states()

        ret = zaza.model.run_on_unit(self.principal_unit_name, "getent passwd testuser")
        self.assertEqual(ret["Code"], "0")

        zaza.model.set_application_config(self.app_name, {"users": ""})
        self.wait_for_application_states()

        ret = zaza.model.run_on_unit(self.principal_unit_name, "getent passwd testuser")
        # getent passwd returns 2 if user isn't there
        self.assertEqual(ret["Code"], "2")

    def test_15_group(self):
        """Test the group config

        This function first tests if users are put into the default charm group
        and then tests if the group is changed correctly"""
        zaza.model.set_application_config(
            self.app_name,
            {
                "users": f"testuser;Test User;{self.ssh_pub_key}",
                "group": "charm-managed",
            },
        )

        self.wait_for_application_states()
        ret = zaza.model.run_on_unit(self.principal_unit_name, "groups testuser")
        self.assertIn("charm-managed", ret["Stdout"].strip().split(" "))

        zaza.model.set_application_config(self.app_name, {"group": "test-group"})
        self.wait_for_application_states()
        ret = zaza.model.run_on_unit(self.principal_unit_name, "groups testuser")
        self.assertIn("test-group", ret["Stdout"].strip().split(" "))

    def test_16_ssh_multiple_keys(self):
        """Test if multiple ssh keys can be added for a user"""

        second_pub_key, second_priv_key = generate_keypair()
        zaza.model.set_application_config(
            self.app_name,
            {
                "users": (
                    f"testuser;Test User;{self.ssh_pub_key}\n"
                    f"testuser;Test User;{second_pub_key}"
                )
            },
        )
        self.wait_for_application_states()

        self.assertEqual(
            self.run_command_ssh("testuser", "whoami")["stdout"], "testuser"
        )
        self.assertEqual(
            self.run_command_ssh("testuser", "whoami", second_priv_key)["stdout"],
            "testuser",
        )

    def test_17_sudoers(self):
        """Test if sudoers config option works

        This checks if the /etc/sudoers.d/70-local-users-charm is created and
        tests a sudo command to make sure it works"""
        sudoers_content = """Cmnd_Alias ALLOWED_CMDS = /usr/bin/whoami

testuser ALL = (ALL) NOPASSWD: ALLOWED_CMDS"""
        zaza.model.set_application_config(self.app_name, {"sudoers": sudoers_content})

        zaza.model.block_until_file_has_contents(
            application_name=self.principal_app_name,
            remote_file="/etc/sudoers.d/70-local-users-charm",
            expected_contents=sudoers_content,
        )

        self.assertEqual(
            self.run_command_ssh("testuser", "sudo whoami")["stdout"], "root"
        )

        zaza.model.set_application_config(self.app_name, {"sudoers": ""})
        self.wait_for_application_states()

        self.assertEqual(
            self.run_command_ssh("testuser", "sudo -l whoami")["returncode"], 1
        )
