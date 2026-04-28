"""
storage/file_registry.py
------------------------
Tamper-evident baseline hash registry for encrypted files.

Stores the initial SHA-256 hash of each file at write-time so auditors can
later verify file integrity by comparing the live hash against this baseline.

Registry format (JSON):
{
  "entries": {
    "encrypted_data/example.enc": {
      "sha256": "...",
      "registered_at": "...",
      "registered_by": "usr_001",
      "role": "researcher",
      "context": "CREATE_RECORD"
    },
    ...
  },
  "hmac": "..."
}

The HMAC is computed over the canonical JSON representation of "entries".
Any modification to stored baselines is detected during read/verify.
"""

import json
import os
import hashlib
import hmac as hmac_lib
from datetime import datetime, timezone

from crypto.hashing import hash_file

REGISTRY_FILE     = os.path.join(os.path.dirname(__file__), "file_registry.json")
REGISTRY_KEY_FILE = os.path.join(os.path.dirname(__file__), "..", "keys", "file_registry_hmac.key")
STORAGE_ROOT      = os.path.dirname(__file__)


def _load_or_create_registry_key() -> bytes:
    os.makedirs(os.path.dirname(REGISTRY_KEY_FILE), exist_ok=True)
    if os.path.exists(REGISTRY_KEY_FILE):
        with open(REGISTRY_KEY_FILE, "rb") as f:
            return f.read()
    key = os.urandom(32)
    with open(REGISTRY_KEY_FILE, "wb") as f:
        f.write(key)
    return key


def _canonical_entries_bytes(entries: dict) -> bytes:
    """Serialise entries in canonical form so the HMAC is stable and reproducible."""
    return json.dumps(entries, sort_keys=True, separators=(",", ":")).encode("utf-8")


def _compute_registry_hmac(entries: dict, key: bytes) -> str:
    mac = hmac_lib.new(key, _canonical_entries_bytes(entries), hashlib.sha256)
    return mac.hexdigest()


def _normalise_registry_id(file_path: str, file_id: str | None = None) -> str:
    if file_id:
        return file_id.replace("\\", "/")

    abs_path = os.path.abspath(file_path)
    storage_abs = os.path.abspath(STORAGE_ROOT)
    if abs_path.startswith(storage_abs):
        rel = os.path.relpath(abs_path, storage_abs)
        return rel.replace("\\", "/")
    return os.path.basename(file_path)


def _load_registry(verify_hmac: bool = True) -> dict:
    if not os.path.exists(REGISTRY_FILE):
        return {"entries": {}, "hmac": ""}

    with open(REGISTRY_FILE, "r", encoding="utf-8") as f:
        data = json.load(f)

    entries = data.get("entries", {})
    stored_hmac = data.get("hmac", "")

    if verify_hmac and stored_hmac:
        key = _load_or_create_registry_key()
        computed = _compute_registry_hmac(entries, key)
        if not hmac_lib.compare_digest(computed, stored_hmac):
            raise ValueError("File registry integrity check failed (HMAC mismatch).")

    return {"entries": entries, "hmac": stored_hmac}


def _save_registry(entries: dict) -> None:
    os.makedirs(os.path.dirname(REGISTRY_FILE), exist_ok=True)
    key = _load_or_create_registry_key()
    mac = _compute_registry_hmac(entries, key)
    payload = {"entries": entries, "hmac": mac}
    with open(REGISTRY_FILE, "w", encoding="utf-8") as f:
        json.dump(payload, f, indent=2)


def register_file_baseline(file_path: str, session: dict, context: str = "", file_id: str | None = None) -> dict:
    """
    Compute and store the baseline SHA-256 hash for a file in the registry.
    Called immediately after a file is written to disk.
    """
    if not os.path.exists(file_path):
        raise FileNotFoundError(f"Cannot register baseline. File not found: {file_path}")

    reg = _load_registry(verify_hmac=True)
    entries = reg["entries"]
    registry_id = _normalise_registry_id(file_path, file_id=file_id)

    entries[registry_id] = {
        "sha256": hash_file(file_path),
        "registered_at": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
        "registered_by": session.get("user_id", "unknown"),
        "role": session.get("role", "unknown"),
        "context": context,
    }
    _save_registry(entries)
    return entries[registry_id]


def get_registry_entry(file_path: str | None = None, file_id: str | None = None) -> dict | None:
    """
    Retrieve a single registry entry by file path or explicit file_id.
    """
    if not file_path and not file_id:
        raise ValueError("Either file_path or file_id must be provided.")

    reg = _load_registry(verify_hmac=True)
    entries = reg["entries"]
    registry_id = _normalise_registry_id(file_path or "", file_id=file_id)
    return entries.get(registry_id)


def list_registry_entries() -> dict:
    """Return all registered baseline entries after HMAC verification."""
    reg = _load_registry(verify_hmac=True)
    return reg["entries"]


def verify_file_against_registry(file_path: str, file_id: str | None = None) -> tuple[bool, str, str]:
    """
    Compare the current file hash against the registered baseline.
    Returns (is_match, baseline_hash, current_hash).
    """
    if not os.path.exists(file_path):
        raise FileNotFoundError(f"File not found: {file_path}")

    entry = get_registry_entry(file_path=file_path, file_id=file_id)
    if entry is None:
        raise FileNotFoundError("No baseline hash registered for this file.")

    baseline = entry["sha256"]
    current = hash_file(file_path)
    return current == baseline, baseline, current
