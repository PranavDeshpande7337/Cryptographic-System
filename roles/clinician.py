"""
roles/clinician.py
------------------
Operations available to the Clinician role:
  1. Create and encrypt a patient dataset (in-memory, no plaintext written to disk)
  2. Upload (encrypt) an existing file from disk
  3. Retrieve (decrypt) a previously stored dataset
  4. List available encrypted datasets
  5. View and verify shared research records from a researcher
"""

import os
import json
from datetime import datetime, timezone

from crypto.encryption     import encrypt_data, decrypt_data, encrypt_file, decrypt_file
from crypto.signing        import verify_signature
from crypto.hashing        import hash_data, hash_file
from crypto.key_management import load_public_key
from storage.audit_logger  import log_action
from storage.file_registry import register_file_baseline

ENCRYPTED_DIR   = os.path.join(os.path.dirname(__file__), "..", "storage", "encrypted_data")
SHARED_DIR      = os.path.join(os.path.dirname(__file__), "..", "storage", "shared_records")
SIG_DIR         = os.path.join(os.path.dirname(__file__), "..", "storage", "signatures")
SHARED_KEY_PATH = os.path.join(os.path.dirname(__file__), "..", "config", "shared_research.key")


def _load_shared_key() -> bytes:
    """Load the shared AES-256 key used for cross-role file sharing."""
    if not os.path.exists(SHARED_KEY_PATH):
        raise FileNotFoundError(
            "Shared research key not found at config/shared_research.key."
        )
    with open(SHARED_KEY_PATH, "rb") as f:
        key = f.read()
    if len(key) != 32:
        raise ValueError("Shared research key must be exactly 32 bytes (AES-256).")
    return key


def create_and_encrypt_dataset(session: dict, password: str, records: list[dict]) -> str:
    """
    Serialise a list of patient records to JSON, encrypt in memory, and
    write only the ciphertext (.enc) to disk. No plaintext file is created.

    Injects 'created_by' and 'timestamp' fields automatically.
    Returns the path to the saved .enc file.
    """
    os.makedirs(ENCRYPTED_DIR, exist_ok=True)

    dataset = {
        "created_by": session["username"],
        "timestamp":  datetime.now(timezone.utc).isoformat(),
        "records":    records
    }

    plaintext_bytes = json.dumps(dataset, indent=2).encode("utf-8")
    encrypted_blob  = encrypt_data(plaintext_bytes, password)

    ts       = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%S")
    filename = f"{session['user_id']}_dataset_{ts}.enc"
    out_path = os.path.join(ENCRYPTED_DIR, filename)

    with open(out_path, "wb") as f:
        f.write(encrypted_blob)
    register_file_baseline(
        out_path,
        session=session,
        context="CREATE_DATASET",
        file_id=f"encrypted_data/{filename}"
    )

    plaintext_hash = hash_data(plaintext_bytes)
    log_action(session, "CREATE_DATASET",
               f"records={len(records)} sha256={plaintext_hash[:16]}...")
    return out_path


def upload_patient_dataset(session: dict, password: str, input_path: str) -> str:
    """
    Encrypt a patient dataset file and store it securely.
    Returns the path to the stored encrypted file.
    Raises FileNotFoundError if the input file does not exist.
    """
    os.makedirs(ENCRYPTED_DIR, exist_ok=True)

    if not os.path.exists(input_path):
        raise FileNotFoundError(f"Input file not found: {input_path}")

    original_hash = hash_file(input_path)
    filename      = os.path.basename(input_path)
    stored_name   = f"{session['user_id']}_{filename}.enc"
    output_path   = os.path.join(ENCRYPTED_DIR, stored_name)

    encrypt_file(input_path, output_path, password)
    register_file_baseline(
        output_path,
        session=session,
        context="UPLOAD_DATASET",
        file_id=f"encrypted_data/{stored_name}"
    )

    log_action(session, "UPLOAD_DATASET",
               f"file={filename} stored_as={stored_name} sha256={original_hash[:16]}...")
    return output_path


def retrieve_patient_dataset(session: dict, password: str,
                              stored_filename: str) -> dict | str:
    """
    Decrypt a previously stored patient dataset.

    Returns a dict with 'records' (list) and metadata if the dataset was created
    via create_and_encrypt_dataset(). Otherwise returns raw decrypted text.
    Raises InvalidTag if tampered or wrong password.
    """
    enc_path = os.path.join(ENCRYPTED_DIR, stored_filename)

    if not os.path.exists(enc_path):
        raise FileNotFoundError(f"Encrypted dataset not found: {stored_filename}")

    with open(enc_path, "rb") as f:
        blob = f.read()

    plaintext_bytes = decrypt_data(blob, password)

    log_action(session, "RETRIEVE_DATASET", f"stored_as={stored_filename}")

    try:
        return json.loads(plaintext_bytes.decode("utf-8"))
    except (json.JSONDecodeError, UnicodeDecodeError):
        return plaintext_bytes.decode("utf-8", errors="replace")


def list_datasets(session: dict) -> list[str]:
    """
    List all encrypted datasets belonging to this clinician.
    Files are namespaced by user_id prefix so clinicians only see their own.
    """
    if not os.path.exists(ENCRYPTED_DIR):
        return []

    prefix = f"{session['user_id']}_"
    files  = [f for f in os.listdir(ENCRYPTED_DIR) if f.startswith(prefix)]

    log_action(session, "LIST_DATASETS", f"count={len(files)}")
    return files


# ---------------------------------------------------------------------------
# Receive and verify shared research from a researcher
# ---------------------------------------------------------------------------

def list_shared_records(session: dict) -> list[str]:
    """
    List all shared research records available to the clinician role.
    All .shared.enc files in storage/shared_records/ are visible to clinicians.
    """
    if not os.path.exists(SHARED_DIR):
        return []
    files = [f for f in os.listdir(SHARED_DIR) if f.endswith(".shared.enc")]
    log_action(session, "LIST_SHARED_RECORDS", f"count={len(files)}")
    return sorted(files)


def view_shared_research(session: dict, shared_filename: str,
                          researcher_user_id: str) -> dict:
    """
    Decrypt a researcher-shared record and verify the researcher's RSA-PSS signature.

    Signature is verified BEFORE decryption (fail-fast on tampered data).
    Raises ValueError if signature is invalid.
    Raises FileNotFoundError if the shared file or signature is missing.

    Returns a dict with keys:
        'record'            -- the decrypted research record
        'signature_valid'   -- True (always; raises on invalid)
        'verified_signer'   -- the confirmed researcher_user_id
    """
    shared_enc_path = os.path.join(SHARED_DIR, shared_filename)
    if not os.path.exists(shared_enc_path):
        raise FileNotFoundError(f"Shared record not found: {shared_filename}")

    sig_filename = shared_filename + ".sig"
    sig_path     = os.path.join(SIG_DIR, sig_filename)
    if not os.path.exists(sig_path):
        raise FileNotFoundError(
            f"Signature file not found: {sig_filename}. "
            "The researcher must sign the record before sharing."
        )

    # Verify signature before decrypting
    with open(shared_enc_path, "rb") as f:
        shared_blob = f.read()
    with open(sig_path, "rb") as f:
        signature = f.read()

    researcher_pub = load_public_key(researcher_user_id)
    sig_valid = verify_signature(shared_blob, signature, researcher_pub)

    if not sig_valid:
        log_action(session, "VIEW_SHARED_RESEARCH",
                   f"file={shared_filename} signer={researcher_user_id} sig=INVALID")
        raise ValueError(
            f"Signature INVALID for {shared_filename}. "
            "The record may have been tampered with, or the wrong researcher ID was specified."
        )

    # Decrypt with shared key
    shared_key  = _load_shared_key()
    shared_pass = shared_key.hex()
    plaintext_bytes = decrypt_data(shared_blob, shared_pass)
    record = json.loads(plaintext_bytes.decode("utf-8"))

    log_action(session, "VIEW_SHARED_RESEARCH",
               f"file={shared_filename} signer={researcher_user_id} sig=VALID")

    return {
        "record":          record,
        "signature_valid": True,
        "verified_signer": researcher_user_id,
    }
