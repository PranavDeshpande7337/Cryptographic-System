"""
roles/auditor.py
----------------
Operations available to the Auditor role:
  1. View the audit log (all system actions)
  2. Verify the integrity of the audit log (HMAC validation)
  3. Verify a digital signature on any encrypted file (using researcher's public key)
  4. Verify the integrity of an encrypted file (SHA-256 hash check)
"""

import os
from crypto.signing        import verify_file_signature
from crypto.hashing        import hash_file, verify_file_integrity
from crypto.key_management import load_public_key
from storage.audit_logger  import read_log, verify_log_integrity, log_action
from storage.file_registry import verify_file_against_registry, get_registry_entry

SIG_DIR       = os.path.join(os.path.dirname(__file__), "..", "storage", "signatures")
ENCRYPTED_DIR = os.path.join(os.path.dirname(__file__), "..", "storage", "encrypted_data")
SHARED_DIR    = os.path.join(os.path.dirname(__file__), "..", "storage", "shared_records")


def view_audit_log(session: dict) -> list[dict]:
    """
    Retrieve all audit log entries.
    Each entry includes a 'valid' field indicating whether its HMAC is intact.
    An invalid entry indicates the log has been tampered with since it was written.
    """
    log_action(session, "VIEW_AUDIT_LOG", "auditor accessed full log")
    return read_log()


def check_log_integrity(session: dict) -> tuple[int, int]:
    """
    Verify the HMAC of every entry in the audit log.
    Returns (valid_count, invalid_count).
    """
    valid, invalid = verify_log_integrity()
    log_action(session, "VERIFY_LOG_INTEGRITY",
               f"valid={valid} invalid={invalid}")
    return valid, invalid


def verify_signature(session: dict, file_path: str,
                     sig_path: str, signer_user_id: str) -> bool:
    """
    Verify the RSA-PSS signature on a file using the researcher's public key.

    The signer_user_id must be the researcher who produced the signature.
    Raises ValueError if signer_user_id matches the auditor's own user ID.
    Returns True if the signature is valid, False otherwise.
    """
    if signer_user_id.strip() == session["user_id"]:
        raise ValueError(
            "An auditor cannot verify their own signature -- auditors do not sign data. "
            "Enter the user ID of the researcher who signed this file."
        )

    if not os.path.exists(file_path):
        raise FileNotFoundError(f"File not found: {file_path}")
    if not os.path.exists(sig_path):
        raise FileNotFoundError(f"Signature file not found: {sig_path}")

    signer_pub = load_public_key(signer_user_id)

    with open(sig_path, "rb") as f:
        signature = f.read()

    result = verify_file_signature(file_path, signature, signer_pub)

    filename = os.path.basename(file_path)
    status   = "VALID" if result else "INVALID"
    log_action(session, "AUDITOR_VERIFY_SIGNATURE",
               f"file={filename} signer={signer_user_id} result={status}")

    return result


def verify_file_hash(session: dict, file_path: str, expected_hash: str | None = None,
                     file_id: str | None = None) -> bool:
    """
    Verify the SHA-256 integrity of a file against a known-good baseline hash.

    Preferred mode: reads the baseline from the tamper-evident file registry.
    Fallback mode: if expected_hash is provided, compare against it directly.

    Returns True if the file matches the baseline, False otherwise.
    """
    if not os.path.exists(file_path):
        raise FileNotFoundError(f"File not found: {file_path}")

    if expected_hash:
        result = verify_file_integrity(file_path, expected_hash)
    else:
        result, _, _ = verify_file_against_registry(file_path, file_id=file_id)

    filename = os.path.basename(file_path)
    status   = "MATCH" if result else "MISMATCH"
    log_action(session, "VERIFY_FILE_HASH",
               f"file={filename} result={status}")

    return result


def get_file_baseline(session: dict, file_path: str, file_id: str | None = None) -> str:
    """
    Return the registered baseline hash for a file.
    Raises FileNotFoundError if no baseline exists.
    """
    if not os.path.exists(file_path):
        raise FileNotFoundError(f"File not found: {file_path}")

    entry = get_registry_entry(file_path=file_path, file_id=file_id)
    if entry is None:
        raise FileNotFoundError("No baseline hash registered for this file.")

    log_action(session, "VIEW_FILE_BASELINE", f"file={os.path.basename(file_path)}")
    return entry["sha256"]


def list_signatures(session: dict) -> list[str]:
    """List all signature files available for verification."""
    if not os.path.exists(SIG_DIR):
        return []
    sigs = [f for f in os.listdir(SIG_DIR) if f.endswith(".sig")]
    log_action(session, "LIST_SIGNATURES", f"count={len(sigs)}")
    return sigs


def list_all_encrypted_files(session: dict) -> list[str]:
    """
    List all encrypted files across personal and shared storage.
    Auditors can see all stored file names (not their contents) for oversight purposes.
    """
    files = []
    if os.path.exists(ENCRYPTED_DIR):
        files += [f"encrypted_data/{f}" for f in os.listdir(ENCRYPTED_DIR) if f.endswith(".enc")]
    if os.path.exists(SHARED_DIR):
        files += [f"shared_records/{f}" for f in os.listdir(SHARED_DIR) if f.endswith(".enc")]
    log_action(session, "LIST_ALL_FILES", f"count={len(files)}")
    return sorted(files)
