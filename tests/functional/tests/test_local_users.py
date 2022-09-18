"""Functional tests for charm-local-users."""
from subprocess import check_output
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
        zaza.model.wait_for_application_states(
            states={
                self.app_name: {
                    "workload-status": "active",
                    "workload-status-message-regex": "^$",
                },
                self.principal_app_name: {
                    "workload-status": "active",
                    "workload-status-message-regex": "^$",
                },
            },
        )

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

        with NamedTemporaryFile(
            mode="w"
        ) as private_key_file, NamedTemporaryFile() as known_hosts:
            private_key_file.write(self.ssh_priv_key)
            private_key_file.flush()

            cmd = [
                "ssh",
                "-o",
                "StrictHostKeyChecking=no",
                "-o",
                f"UserKnownHostsFile={known_hosts.name}",
                "-i",
                private_key_file.name,
                "-l",
                "testuser",
                zaza.model.get_app_ips(self.principal_app_name)[0],
                "whoami",
            ]
            stdout = check_output(cmd).decode().strip()
        self.assertEqual(stdout, "testuser")

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
