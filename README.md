# 🔐 Secure Clinical Research Platform

A role-based web application for secure clinical and research data management — featuring AES-256-GCM encryption, RSA-PSS digital signatures, Argon2id authentication, and tamper-evident audit logging.

Built with [Streamlit](https://streamlit.io/) and Python.

---

## Features

- **Role-based access control** — separate dashboards for Researchers, Clinicians, and Auditors
- **End-to-end encryption** — AES-256-GCM with HKDF-derived keys protects all stored records
- **Digital signatures** — RSA-2048 PSS signatures for non-repudiation and record authorship verification
- **Cross-role record sharing** — researchers can securely share signed records with clinicians
- **Tamper-evident audit log** — every action is HMAC-protected; auditors can verify integrity
- **Brute-force protection** — Argon2id password hashing, 5-attempt lockout, 15-minute session timeout

---

## Tech Stack

| Layer | Technology |
|---|---|
| UI | Streamlit |
| Auth | Argon2id (`argon2-cffi`) |
| Encryption | AES-256-GCM, HKDF (`cryptography`) |
| Signatures | RSA-2048 PSS (`cryptography`) |
| Audit integrity | HMAC-SHA256 |

---

## Getting Started

### Prerequisites

- Python 3.10 or higher
- pip

### Installation

```bash
# Clone the repo
git clone https://github.com/YOUR_USERNAME/YOUR_REPO_NAME.git
cd YOUR_REPO_NAME

# (Optional) Create and activate a virtual environment
python -m venv .venv

# Windows
.\.venv\Scripts\Activate.ps1
# macOS / Linux
source .venv/bin/activate

# Install dependencies
pip install streamlit argon2-cffi cryptography
```

### Configuration

Two config files are required before first run — neither is committed to the repo for security reasons.

**1. User credentials** — copy the example and populate it:

```bash
cp config/users.json.example config/users.json
```

Edit `config/users.json` with your usernames and Argon2id-hashed passwords. You can generate hashes using `reset.py`.

**2. Shared research key** — generate a 32-byte key once:

```bash
python -c "import os; os.makedirs('config', exist_ok=True); open('config/shared_research.key','wb').write(os.urandom(32))"
```

This key enables the researcher → clinician record sharing feature.

### Run

```bash
streamlit run app.py
```

Open the URL printed in your terminal (default: `http://localhost:8501`).

---

## Project Structure

```
├── app.py                  # Streamlit UI and routing
├── auth/
│   └── login.py            # Argon2id auth, lockout, session management
├── crypto/
│   ├── encryption.py       # AES-256-GCM + HKDF
│   ├── hashing.py          # SHA-256 file hashing
│   ├── key_management.py   # RSA-2048 key generation and loading
│   └── signing.py          # RSA-PSS sign and verify
├── roles/
│   ├── researcher.py       # Encrypt, sign, and share records
│   ├── clinician.py        # Datasets and shared research access
│   └── auditor.py          # Audit log and integrity verification
├── storage/
│   ├── audit_logger.py     # HMAC-protected audit entries
│   └── file_registry.py    # File hash registration
├── config/
│   └── users.json.example  # Credential template (copy to users.json)
└── reset.py                # Wipe runtime state for a clean start
```

> `config/users.json`, `config/shared_research.key`, `keys/`, and all `storage/` runtime directories are gitignored and must be created locally.

---

## Resetting State

To wipe all encrypted data, signatures, audit logs, and generated keys for a clean run:

```bash
python reset.py

# Non-interactive
python reset.py --yes
```

This does **not** remove `config/users.json`. RSA key pairs are regenerated on next login.

---

## Security Notes

- Passwords are never stored in plaintext — only Argon2id hashes (`m=65536, t=3, p=2`)
- Private RSA keys are stored locally and never transmitted
- AES-GCM authentication tags detect any ciphertext tampering
- The shared research key should be distributed out-of-band in any real deployment
- This project is intended for educational/demonstration purposes — review before any production use

---

## Troubleshooting

| Issue | Fix |
|---|---|
| `ModuleNotFoundError` | Run `pip install streamlit argon2-cffi cryptography` |
| Import / path errors | Run `streamlit run app.py` from the project root |
| Shared research errors | Ensure `config/shared_research.key` exists and is exactly 32 bytes |
| Locked out of account | Wait 5 minutes, or delete `config/lockout.json` while the app is stopped |
| Port already in use | `streamlit run app.py --server.port 8502` |
