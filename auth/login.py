"""
auth/login.py
-------------
Handles credential verification, role-based access control (RBAC),
login attempt limiting, and session timeout enforcement.
"""

import json
import os
import time
from argon2 import PasswordHasher
from argon2.exceptions import VerifyMismatchError, VerificationError, InvalidHashError

# File paths for user credentials and lockout state
USERS_FILE   = os.path.join(os.path.dirname(__file__), "..", "config", "users.json")
LOCKOUT_FILE = os.path.join(os.path.dirname(__file__), "..", "config", "lockout.json")

# Lockout policy: 5 failed attempts triggers a 5-minute lockout
MAX_ATTEMPTS        = 5
LOCKOUT_DURATION    = 5 * 60

# Session expires after 15 minutes of inactivity
SESSION_TIMEOUT_SECONDS = 15 * 60

# Argon2id password hasher configuration
ph = PasswordHasher(
    time_cost=3,
    memory_cost=65536,
    parallelism=2,
    hash_len=32,
    salt_len=16
)


# ── User store ────────────────────────────────────────────────────────────────

def load_users() -> dict:
    """Load the user credentials store from config/users.json."""
    if not os.path.exists(USERS_FILE):
        raise FileNotFoundError(f"Credentials file not found: {USERS_FILE}")
    with open(USERS_FILE, "r") as f:
        return json.load(f)


# ── Lockout management ────────────────────────────────────────────────────────

def _load_lockout() -> dict:
    """Load the lockout state from config/lockout.json."""
    if not os.path.exists(LOCKOUT_FILE):
        return {}
    with open(LOCKOUT_FILE, "r") as f:
        return json.load(f)


def _save_lockout(data: dict) -> None:
    """Persist the lockout state to config/lockout.json."""
    os.makedirs(os.path.dirname(LOCKOUT_FILE), exist_ok=True)
    with open(LOCKOUT_FILE, "w") as f:
        json.dump(data, f, indent=2)


def is_locked_out(username: str) -> tuple[bool, int]:
    """
    Check whether a username is currently locked out.
    Returns (locked: bool, seconds_remaining: int).
    """
    data    = _load_lockout()
    record  = data.get(username, {})
    lockout_until = record.get("lockout_until", 0)

    if lockout_until == 0:
        return False, 0

    remaining = int(lockout_until - time.time())
    if remaining > 0:
        return True, remaining

    # Lockout has expired -- clear it
    record["lockout_until"] = 0
    record["failed_attempts"] = 0
    data[username] = record
    _save_lockout(data)
    return False, 0


def _record_failed_attempt(username: str) -> tuple[int, bool]:
    """
    Increment the failed attempt counter for a username.
    Returns (attempts_so_far: int, just_locked_out: bool).
    Applies a lockout when MAX_ATTEMPTS is reached.
    """
    data   = _load_lockout()
    record = data.get(username, {"failed_attempts": 0, "lockout_until": 0})

    record["failed_attempts"] = record.get("failed_attempts", 0) + 1
    just_locked = False

    if record["failed_attempts"] >= MAX_ATTEMPTS:
        record["lockout_until"] = time.time() + LOCKOUT_DURATION
        just_locked = True

    data[username] = record
    _save_lockout(data)
    return record["failed_attempts"], just_locked


def _reset_attempts(username: str) -> None:
    """Reset the failed attempt counter on successful login."""
    data = _load_lockout()
    data[username] = {"failed_attempts": 0, "lockout_until": 0}
    _save_lockout(data)


# ── Authentication ────────────────────────────────────────────────────────────

def authenticate(username: str, password: str) -> dict | None:
    """
    Verify credentials against the stored Argon2id hash.

    Returns a session dictionary on success:
        {
            "username":    str,
            "user_id":     str,
            "role":        str,
            "last_active": float
        }

    Returns None on failure. The same return value is used for wrong username,
    wrong password, and lockout to prevent information leakage.
    """
    users = load_users()

    locked, remaining = is_locked_out(username)
    if locked:
        return None

    user_record = users.get(username)
    if user_record is None:
        # Dummy verify to prevent timing-based username enumeration
        try:
            ph.verify(
                "$argon2id$v=19$m=65536,t=3,p=2$invalidsalt1234$invalidhash123456789012345678901234",
                password
            )
        except Exception:
            pass
        _record_failed_attempt(username)
        return None

    try:
        ph.verify(user_record["password_hash"], password)
    except (VerifyMismatchError, VerificationError, InvalidHashError):
        _record_failed_attempt(username)
        return None

    _reset_attempts(username)

    return {
        "username":    username,
        "user_id":     user_record["user_id"],
        "role":        user_record["role"],
        "last_active": time.time()
    }


# ── Session management ────────────────────────────────────────────────────────

def check_session(session: dict) -> bool:
    """
    Check whether a session is still valid (not timed out).
    Returns True if active, False if expired.
    """
    if session is None:
        return False
    elapsed = time.time() - session.get("last_active", 0)
    return elapsed < SESSION_TIMEOUT_SECONDS


def refresh_session(session: dict) -> dict:
    """
    Update the last_active timestamp to reset the inactivity timer.
    Returns the updated session dict.
    """
    session["last_active"] = time.time()
    return session


def session_time_remaining(session: dict) -> int:
    """Return seconds remaining before session timeout. Returns 0 if expired."""
    if session is None:
        return 0
    elapsed   = time.time() - session.get("last_active", 0)
    remaining = SESSION_TIMEOUT_SECONDS - elapsed
    return max(0, int(remaining))


# ── RBAC ──────────────────────────────────────────────────────────────────────

def require_role(session: dict, allowed_roles: list[str]) -> bool:
    """
    Check whether the session's role is in the allowed list.
    Used as a role-based access control gate before sensitive operations.
    """
    return session.get("role") in allowed_roles
