"""
storage/audit_logger.py
-----------------------
Tamper-evident audit logging using HMAC-SHA256.

Every action performed in the system is recorded as a log entry protected
with an HMAC-SHA256 MAC. This ensures integrity (modifications invalidate
the MAC) and supports GDPR Article 30 accountability obligations.

Log format (one entry per line, pipe-delimited):
  timestamp | user_id | username | role | action | details | hmac
"""

import os
import json
import hashlib
import hmac as hmac_lib
from datetime import datetime, timezone

LOG_FILE      = os.path.join(os.path.dirname(__file__), "audit_logs", "audit.log")
HMAC_KEY_FILE = os.path.join(os.path.dirname(__file__), "..", "keys", "hmac.key")

SEPARATOR = " | "


def _load_or_create_hmac_key() -> bytes:
    """
    Load the HMAC key from disk, or generate and save a new 256-bit key on first run.
    """
    os.makedirs(os.path.dirname(HMAC_KEY_FILE), exist_ok=True)
    if os.path.exists(HMAC_KEY_FILE):
        with open(HMAC_KEY_FILE, "rb") as f:
            return f.read()
    key = os.urandom(32)
    with open(HMAC_KEY_FILE, "wb") as f:
        f.write(key)
    return key


def _compute_entry_hmac(entry_body: str, key: bytes) -> str:
    """Compute HMAC-SHA256 over an entry body string."""
    mac = hmac_lib.new(key, entry_body.encode("utf-8"), hashlib.sha256)
    return mac.hexdigest()


def log_action(session: dict, action: str, details: str = "") -> None:
    """
    Write a tamper-evident log entry for a user action.

    Parameters:
        session: the authenticated session dict (user_id, username, role)
        action:  a short action label e.g. 'ENCRYPT_FILE', 'SIGN_DATA'
        details: optional additional context e.g. filename, target user_id
    """
    os.makedirs(os.path.dirname(LOG_FILE), exist_ok=True)
    key = _load_or_create_hmac_key()

    timestamp = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
    entry_body = SEPARATOR.join([
        timestamp,
        session.get("user_id",  "unknown"),
        session.get("username", "unknown"),
        session.get("role",     "unknown"),
        action,
        details
    ])

    mac = _compute_entry_hmac(entry_body, key)

    with open(LOG_FILE, "a", encoding="utf-8") as f:
        f.write(entry_body + SEPARATOR + mac + "\n")


def read_log() -> list[dict]:
    """
    Read all audit log entries and return them as a list of dicts.
    Each dict contains the parsed fields and a 'valid' boolean indicating
    whether the HMAC is intact.
    """
    if not os.path.exists(LOG_FILE):
        return []

    key = _load_or_create_hmac_key()
    entries = []

    with open(LOG_FILE, "r", encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            if not line:
                continue

            parts = line.split(SEPARATOR)
            if len(parts) != 7:
                entries.append({"raw": line, "valid": False, "error": "malformed entry"})
                continue

            timestamp, user_id, username, role, action, details, stored_mac = parts
            entry_body = SEPARATOR.join([timestamp, user_id, username, role, action, details])
            computed_mac = _compute_entry_hmac(entry_body, key)

            entries.append({
                "timestamp": timestamp,
                "user_id":   user_id,
                "username":  username,
                "role":      role,
                "action":    action,
                "details":   details,
                "valid":     hmac_lib.compare_digest(computed_mac, stored_mac)
            })

    return entries


def verify_log_integrity() -> tuple[int, int]:
    """
    Verify all entries in the audit log.
    Returns (valid_count, invalid_count).
    """
    entries = read_log()
    valid   = sum(1 for e in entries if e.get("valid"))
    invalid = len(entries) - valid
    return valid, invalid
