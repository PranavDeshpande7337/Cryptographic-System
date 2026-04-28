"""
crypto/encryption.py
--------------------
Implements AES-256-GCM encryption with HKDF key derivation.

Stored file layout (.enc):
    [16 bytes : HKDF salt]
    [12 bytes : AES-GCM nonce]
    [remaining: AES-GCM ciphertext + 16-byte auth tag]
"""

import os
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives import hashes

# AES-256-GCM and HKDF constants
AES_KEY_SIZE   = 32   # 256 bits
AES_NONCE_SIZE = 12   # 96 bits -- NIST recommended for GCM
HKDF_SALT_SIZE = 16   # 128 bits -- random per file


def _derive_key(password: str, salt: bytes) -> bytes:
    """
    Derive a 256-bit AES key from a password and salt using HKDF-SHA256.
    The info parameter binds the key to this application context.
    """
    hkdf = HKDF(
        algorithm=hashes.SHA256(),
        length=AES_KEY_SIZE,
        salt=salt,
        info=b"clinical-research-platform-aes256"
    )
    return hkdf.derive(password.encode("utf-8"))


def encrypt_data(plaintext: bytes, password: str) -> bytes:
    """
    Encrypt plaintext with AES-256-GCM using an HKDF-derived key.

    Returns a bytes blob:
        [16 bytes: HKDF salt] + [12 bytes: nonce] + [ciphertext + 16-byte GCM tag]

    A fresh salt and nonce are generated per call.
    """
    salt  = os.urandom(HKDF_SALT_SIZE)
    nonce = os.urandom(AES_NONCE_SIZE)
    key   = _derive_key(password, salt)

    aesgcm     = AESGCM(key)
    ciphertext = aesgcm.encrypt(nonce, plaintext, associated_data=None)

    return salt + nonce + ciphertext


def decrypt_data(encrypted_blob: bytes, password: str) -> bytes:
    """
    Decrypt a blob produced by encrypt_data().

    Raises cryptography.exceptions.InvalidTag if the ciphertext has been
    tampered with or the password is wrong.
    """
    if len(encrypted_blob) < HKDF_SALT_SIZE + AES_NONCE_SIZE:
        raise ValueError("Encrypted blob is too short to be valid.")

    salt       = encrypted_blob[:HKDF_SALT_SIZE]
    nonce      = encrypted_blob[HKDF_SALT_SIZE: HKDF_SALT_SIZE + AES_NONCE_SIZE]
    ciphertext = encrypted_blob[HKDF_SALT_SIZE + AES_NONCE_SIZE:]

    key    = _derive_key(password, salt)
    aesgcm = AESGCM(key)

    return aesgcm.decrypt(nonce, ciphertext, associated_data=None)


def encrypt_file(input_path: str, output_path: str, password: str) -> None:
    """
    Read a file, encrypt its contents, and write the encrypted blob to output_path.
    """
    with open(input_path, "rb") as f:
        plaintext = f.read()
    with open(output_path, "wb") as f:
        f.write(encrypt_data(plaintext, password))


def decrypt_file(input_path: str, output_path: str, password: str) -> None:
    """
    Read an encrypted file, decrypt its contents, and write plaintext to output_path.
    Raises InvalidTag if the file has been tampered with or the password is wrong.
    """
    with open(input_path, "rb") as f:
        blob = f.read()
    with open(output_path, "wb") as f:
        f.write(decrypt_data(blob, password))
