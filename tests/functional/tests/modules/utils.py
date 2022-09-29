"""Utilities to be used during charm-local-users functests."""
import logging

from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import serialization

logger = logging.getLogger(__name__)


def generate_keypair():
    """Generate a public/private keypair."""
    private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    public_key = private_key.public_key()

    private_key_string = (
        private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.TraditionalOpenSSL,
            encryption_algorithm=serialization.NoEncryption(),
        )
        .decode()
        .strip()
    )

    public_key_string = (
        public_key.public_bytes(
            encoding=serialization.Encoding.OpenSSH,
            format=serialization.PublicFormat.OpenSSH,
        )
        .decode()
        .strip()
    )

    logger.info(f"Generated public key:\n{public_key_string}")
    logger.info(f"Generated private key:\n{private_key_string}")

    return public_key_string, private_key_string
