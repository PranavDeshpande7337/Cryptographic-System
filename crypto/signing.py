"""
crypto/signing.py
-----------------
Implements digital signatures using RSA-PSS with SHA-256.
"""

from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric.rsa import RSAPrivateKey, RSAPublicKey
from cryptography.exceptions import InvalidSignature

# PSS salt length set to maximum for SHA-256
PSS_SALT_LENGTH = padding.PSS.MAX_LENGTH


def sign_data(data: bytes, private_key: RSAPrivateKey) -> bytes:
    """
    Sign data using RSA-PSS with SHA-256.
    Returns the raw signature bytes (256 bytes for RSA-2048).
    """
    signature = private_key.sign(
        data,
        padding.PSS(
            mgf=padding.MGF1(hashes.SHA256()),
            salt_length=PSS_SALT_LENGTH
        ),
        hashes.SHA256()
    )
    return signature


def verify_signature(data: bytes, signature: bytes, public_key: RSAPublicKey) -> bool:
    """
    Verify an RSA-PSS signature against the original data.
    Returns True if the signature is valid, False otherwise.
    """
    try:
        public_key.verify(
            signature,
            data,
            padding.PSS(
                mgf=padding.MGF1(hashes.SHA256()),
                salt_length=PSS_SALT_LENGTH
            ),
            hashes.SHA256()
        )
        return True
    except InvalidSignature:
        return False


def sign_file(file_path: str, private_key: RSAPrivateKey) -> bytes:
    """
    Read a file and return its RSA-PSS signature.
    """
    with open(file_path, "rb") as f:
        data = f.read()
    return sign_data(data, private_key)


def verify_file_signature(file_path: str, signature: bytes, public_key: RSAPublicKey) -> bool:
    """
    Read a file and verify its RSA-PSS signature.
    Returns True if the file contents match the signature, False otherwise.
    """
    with open(file_path, "rb") as f:
        data = f.read()
    return verify_signature(data, signature, public_key)
