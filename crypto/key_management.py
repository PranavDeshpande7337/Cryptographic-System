"""
crypto/key_management.py
------------------------
Handles RSA-2048 key pair generation, storage, and retrieval.

RSA-2048 key pairs are used exclusively for digital signatures (RSA-PSS).
Encryption is handled separately by AES-256-GCM in crypto/encryption.py.
"""

import os
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import serialization

PRIVATE_KEY_DIR = os.path.join(os.path.dirname(__file__), "..", "keys", "private")
PUBLIC_KEY_DIR  = os.path.join(os.path.dirname(__file__), "..", "keys", "public")


def _private_key_path(user_id: str) -> str:
    return os.path.join(PRIVATE_KEY_DIR, f"{user_id}.pem")


def _public_key_path(user_id: str) -> str:
    return os.path.join(PUBLIC_KEY_DIR, f"{user_id}.pem")


def generate_key_pair(user_id: str, password: str = None) -> None:
    """
    Generate an RSA-2048 key pair for a user and save both keys to disk.
    Idempotent: skips generation if keys already exist for this user.
    The password parameter is accepted but unused (kept for interface compatibility).
    """
    os.makedirs(PRIVATE_KEY_DIR, exist_ok=True)
    os.makedirs(PUBLIC_KEY_DIR,  exist_ok=True)

    if os.path.exists(_private_key_path(user_id)):
        return

    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048
    )

    private_pem = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption()
    )

    public_pem = private_key.public_key().public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    )

    with open(_private_key_path(user_id), "wb") as f:
        f.write(private_pem)

    with open(_public_key_path(user_id), "wb") as f:
        f.write(public_pem)


def load_private_key(user_id: str, password: str = None):
    """
    Load a user's RSA private key from disk.
    Raises FileNotFoundError if the key does not exist.
    """
    path = _private_key_path(user_id)
    if not os.path.exists(path):
        raise FileNotFoundError(f"Private key not found for user: {user_id}")

    with open(path, "rb") as f:
        pem_data = f.read()

    return serialization.load_pem_private_key(pem_data, password=None)


def load_public_key(user_id: str):
    """
    Load a user's RSA public key from disk.
    Raises FileNotFoundError if the key does not exist.
    """
    path = _public_key_path(user_id)
    if not os.path.exists(path):
        raise FileNotFoundError(f"Public key not found for user: {user_id}")

    with open(path, "rb") as f:
        pem_data = f.read()

    return serialization.load_pem_public_key(pem_data)


def key_pair_exists(user_id: str) -> bool:
    """Check whether a key pair already exists for a given user."""
    return (
        os.path.exists(_private_key_path(user_id)) and
        os.path.exists(_public_key_path(user_id))
    )
