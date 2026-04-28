"""
crypto/hashing.py
-----------------
Provides SHA-256 file integrity checking and HMAC-SHA256 audit log authentication.

SHA-256 is used to generate file fingerprints and detect tampering.
HMAC-SHA256 is used to authenticate audit log entries using a shared secret key,
providing both integrity and origin verification.
"""

import hmac
import hashlib
import os


def hash_data(data: bytes) -> str:
    """
    Compute the SHA-256 hash of a bytes object.
    Returns the hash as a lowercase hex string (64 characters).
    """
    return hashlib.sha256(data).hexdigest()


def hash_file(file_path: str) -> str:
    """
    Compute the SHA-256 hash of a file's contents.
    Reads in 64 KB chunks to handle large files efficiently.
    Returns the hash as a lowercase hex string.
    """
    sha256 = hashlib.sha256()
    with open(file_path, "rb") as f:
        while chunk := f.read(65536):
            sha256.update(chunk)
    return sha256.hexdigest()


def verify_file_integrity(file_path: str, expected_hash: str) -> bool:
    """
    Verify a file's SHA-256 hash against an expected value.
    Returns True if the file matches, False if it has been modified.
    """
    return hash_file(file_path) == expected_hash.lower()


def compute_hmac(data: bytes, key: bytes) -> str:
    """
    Compute an HMAC-SHA256 over data using the provided key.
    Returns the MAC as a lowercase hex string (64 characters).
    """
    mac = hmac.new(key, data, hashlib.sha256)
    return mac.hexdigest()


def verify_hmac(data: bytes, key: bytes, expected_mac: str) -> bool:
    """
    Verify an HMAC-SHA256 MAC against an expected value.
    Uses hmac.compare_digest() for constant-time comparison to prevent
    timing side-channel attacks.
    """
    computed = compute_hmac(data, key)
    return hmac.compare_digest(computed, expected_mac.lower())


def generate_hmac_key() -> bytes:
    """
    Generate a fresh 256-bit (32-byte) random key for HMAC.
    Used to initialise the audit log HMAC key on first run.
    """
    return os.urandom(32)
