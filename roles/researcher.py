"""
roles/researcher.py
-------------------
Operations available to the Researcher role:
  1. Create and encrypt a patient/research record (no plaintext written to disk)
  2. Decrypt and view a research record
  3. Sign an encrypted record file with RSA-PSS
  4. Verify a signature on a record (third-party only -- cannot verify own signature)
  5. Share a record with clinicians using the shared AES key
"""

import os
import json
from datetime import datetime, timezone

from crypto.encryption     import encrypt_data, decrypt_data
from crypto.signing        import sign_data, verify_signature
from crypto.hashing        import hash_data
from crypto.key_management import load_private_key, load_public_key
from storage.audit_logger  import log_action
from storage.file_registry import register_file_baseline

ENCRYPTED_DIR   = os.path.join(os.path.dirname(__file__), "..", "storage", "encrypted_data")
SIG_DIR         = os.path.join(os.path.dirname(__file__), "..", "storage", "signatures")
SHARED_DIR      = os.path.join(os.path.dirname(__file__), "..", "storage", "shared_records")
SHARED_KEY_PATH = os.path.join(os.path.dirname(__file__), "..", "config", "shared_research.key")


def _load_shared_key() -> bytes:
    """Load the shared AES-256 key used for cross-role file sharing."""
    if not os.path.exists(SHARED_KEY_PATH):
        raise FileNotFoundError(
            "Shared research key not found at config/shared_research.key. "
            "Generate it once with: "
            "python3 -c \"import os; open('config/shared_research.key','wb').write(os.urandom(32))\""
        )
    with open(SHARED_KEY_PATH, "rb") as f:
        key = f.read()
    if len(key) != 32:
        raise ValueError("Shared research key must be exactly 32 bytes (AES-256).")
    return key


def create_and_encrypt_record(session: dict, password: str, record: dict) -> str:
    """
    Serialise a research record dict to JSON, encrypt it in memory, and
    write only the ciphertext (.enc) to disk. No plaintext file is created.

    Injects 'created_by' and 'timestamp' fields automatically.
    Returns the path to the saved .enc file.
    """
    os.makedirs(ENCRYPTED_DIR, exist_ok=True)

    record["created_by"] = session["username"]
    record["timestamp"]  = datetime.now(timezone.utc).isoformat()

    plaintext_bytes = json.dumps(record, indent=2).encode("utf-8")
    encrypted_blob  = encrypt_data(plaintext_bytes, password)

    patient_id  = record.get("patient_id", "record").replace(" ", "_")
    filename    = f"{session['user_id']}_{patient_id}.enc"
    output_path = os.path.join(ENCRYPTED_DIR, filename)

    with open(output_path, "wb") as f:
        f.write(encrypted_blob)
    register_file_baseline(
        output_path,
        session=session,
        context="CREATE_RECORD",
        file_id=f"encrypted_data/{filename}"
    )

    plaintext_hash = hash_data(plaintext_bytes)
    log_action(session, "CREATE_RECORD",
               f"patient_id={patient_id} sha256={plaintext_hash[:16]}...")
    return output_path


def decrypt_research_record(session: dict, password: str, enc_path: str) -> dict:
    """
    Decrypt a .enc research record and return the original dict.
    Raises InvalidTag if the file has been tampered with or the password is wrong.
    """
    with open(enc_path, "rb") as f:
        blob = f.read()

    plaintext_bytes = decrypt_data(blob, password)
    record = json.loads(plaintext_bytes.decode("utf-8"))

    filename = os.path.basename(enc_path)
    log_action(session, "DECRYPT_RECORD", f"file={filename}")
    return record


def list_research_records(session: dict) -> list[str]:
    """
    List all encrypted research records belonging to this researcher.
    Files are namespaced by user_id prefix for access isolation.
    """
    if not os.path.exists(ENCRYPTED_DIR):
        return []

    prefix = f"{session['user_id']}_"
    files  = [f for f in os.listdir(ENCRYPTED_DIR) if f.startswith(prefix)]

    log_action(session, "LIST_RECORDS", f"count={len(files)}")
    return files


def sign_record(session: dict, enc_path: str) -> str:
    """
    Sign an encrypted research record file with the researcher's RSA-2048
    private key (PSS scheme).
    Returns the path to the saved .sig file.
    """
    os.makedirs(SIG_DIR, exist_ok=True)

    private_key = load_private_key(session["user_id"])

    with open(enc_path, "rb") as f:
        data = f.read()

    signature = sign_data(data, private_key)

    filename = os.path.basename(enc_path)
    sig_path = os.path.join(SIG_DIR, f"{filename}.sig")
    with open(sig_path, "wb") as f:
        f.write(signature)

    log_action(session, "SIGN_RECORD",
               f"file={filename} sig={os.path.basename(sig_path)}")
    return sig_path


def verify_record_signature(session: dict, enc_path: str,
                             sig_path: str, signer_user_id: str) -> bool:
    """
    Verify the RSA-PSS signature on an encrypted record file.
    Raises ValueError if the caller tries to verify their own signature.
    Returns True if signature is valid, False otherwise.
    """
    if signer_user_id.strip() == session["user_id"]:
        raise ValueError(
            "Self-verification is not permitted. "
            "A researcher cannot verify their own signature -- this proves nothing. "
            "Verification must be performed by a clinician or auditor using your public key."
        )

    signer_pub = load_public_key(signer_user_id)

    with open(enc_path, "rb") as f:
        data = f.read()
    with open(sig_path, "rb") as f:
        signature = f.read()

    result   = verify_signature(data, signature, signer_pub)
    filename = os.path.basename(enc_path)
    status   = "VALID" if result else "INVALID"
    log_action(session, "VERIFY_RECORD_SIGNATURE",
               f"file={filename} signer={signer_user_id} result={status}")
    return result


# ---------------------------------------------------------------------------
# Cross-role sharing
# ---------------------------------------------------------------------------

def share_record_with_clinician(session: dict, password: str,
                                 enc_path: str) -> tuple[str, str]:
    """
    Share an existing encrypted research record with clinicians.

    Steps:
      1. Decrypt the researcher's personal copy using their password.
      2. Re-encrypt with the shared AES-256 key so clinicians can access it.
      3. Sign the shared ciphertext with the researcher's RSA private key
         so clinicians and auditors can verify authorship.

    Returns (shared_enc_path, shared_sig_path).
    """
    os.makedirs(SHARED_DIR, exist_ok=True)
    os.makedirs(SIG_DIR,    exist_ok=True)

    # Step 1: decrypt researcher's personal copy
    with open(enc_path, "rb") as f:
        personal_blob = f.read()
    plaintext_bytes = decrypt_data(personal_blob, password)

    # Step 2: re-encrypt with shared AES key
    shared_key  = _load_shared_key()
    shared_pass = shared_key.hex()
    shared_blob = encrypt_data(plaintext_bytes, shared_pass)

    base_name       = os.path.basename(enc_path)
    shared_name     = base_name.replace(".enc", "") + ".shared.enc"
    shared_enc_path = os.path.join(SHARED_DIR, shared_name)

    with open(shared_enc_path, "wb") as f:
        f.write(shared_blob)
    register_file_baseline(
        shared_enc_path,
        session=session,
        context="SHARE_RECORD",
        file_id=f"shared_records/{shared_name}"
    )

    # Step 3: sign the shared ciphertext with the researcher's RSA private key
    private_key = load_private_key(session["user_id"])
    signature   = sign_data(shared_blob, private_key)

    sig_path = os.path.join(SIG_DIR, f"{shared_name}.sig")
    with open(sig_path, "wb") as f:
        f.write(signature)

    log_action(session, "SHARE_RECORD",
               f"original={base_name} shared_as={shared_name} signed=True")
    return shared_enc_path, sig_path
