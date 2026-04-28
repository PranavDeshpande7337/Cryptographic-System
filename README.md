# Secure Clinical Research Platform

Streamlit app for role-based encrypted clinical/research data, digital signatures, shared research records, and tamper-evident audit logging.

The sections below cover setup, launch, test accounts, and a **marker verification** checklist aligned with the coursework rubric.

---

## Prerequisites

- **Python 3.10+** (3.11 or 3.12 are fine).
- Terminal: PowerShell on Windows, or bash on macOS/Linux.
- Network is only needed to **install** packages; running the app is local.

---

## 1. Installation

Use the project root (the folder that contains `app.py`, e.g. `MainCW`).

### Virtual environment (optional)

```bash
python -m venv .venv
```

**Windows (PowerShell):**

```powershell
.\.venv\Scripts\Activate.ps1
```

**macOS / Linux:**

```bash
source .venv/bin/activate
```

### Dependencies

```bash
pip install streamlit argon2-cffi cryptography
```

No `requirements.txt` is bundled; the line above matches what the code imports.

---

## 2. Configuration before first run

| Item | Purpose |
|------|---------|
| `config/users.json` | Accounts and Argon2id hashes |
| `config/shared_research.key` | 32-byte key for researcher → clinician sharing (**Share with Clinician** / **View Shared Research**) |

If `config/shared_research.key` is missing, generate it once from the project root:

```bash
python -c "import os; os.makedirs('config', exist_ok=True); open('config/shared_research.key','wb').write(os.urandom(32))"
```

After each user’s **first successful login**, an **RSA-2048** key pair is created under `keys/private/` and `keys/public/`.

---

## 3. Launch

```bash
streamlit run app.py
```

Run that command from the **project root** so imports and paths resolve.

- The terminal prints a URL (often `http://localhost:8501`).
- Use **Logout** in the sidebar to switch roles.

Stop the server with `Ctrl+C`.

---

## 4. Test credentials

Usernames and passwords match `Creds.txt`. The **User ID** column is from `config/users.json` and is needed for **shared research** and **signature verification** (clinician / auditor UIs).

| Role | Username | Password | User ID |
|------|----------|----------|---------|
| Researcher | `researcher_01` | `Research@123` | `usr_001` |
| Clinician | `clinician_01` | `Clinician@123` | `usr_002` |
| Auditor | `auditor_01` | `Auditor@123` | `usr_003` |

Demo-only credentials — not for production.

---

## 5. Behaviour that affects marking

| Topic | Detail |
|-------|--------|
| **Lockout** | Five failed logins for one username → **5 minutes** lockout; state in `config/lockout.json`. |
| **Session timeout** | **15 minutes** idle → session ends; sidebar shows remaining time. |
| **Decrypt failures** | Wrong password or tampered ciphertext should surface as an error (AES-GCM). |

If lockout blocks further tests: wait out the window, or delete `config/lockout.json` while the app is stopped.

---

## 6. Checklist

Suggested order where one flow depends on another (e.g. clinician shared view after researcher share).

### 6.1 Login and routing

| # | Action | Expected |
|---|--------|----------|
| L1 | Load app logged out | Login form (username / password). |
| L2 | Log in per credentials table | Dashboard matches role; sidebar shows user, role, session timer. |
| L3 | Log out → different role | Correct role dashboard. |
| L4 | Same username, wrong password ×5 | Errors then lockout messaging. |

### 6.2 Researcher

| # | Location | Action | Expected |
|---|----------|--------|----------|
| R1 | **Create Record** | Patient ID required; optional fields; **Save Record Securely** | Success + `.enc` name; file under `storage/encrypted_data/` (e.g. `usr_001_…`). |
| R2 | **View My Record** | Select file → **Open Record** | Fields + metadata (created by, timestamp). |
| R3 | **View My Record** | Stop the app, change one byte in the `.enc`, restart, **Open Record** | Decrypt / authentication failure. |
| R4 | **Sign Record** | Choose personal `.enc` → **Sign Record** | Success; `.sig` in `storage/signatures/` matching that `.enc`. |
| R5 | **Share with Clinician** | **Share Record** on a record | `*.shared.enc` in `storage/shared_records/`; `*.shared.enc.sig` in `storage/signatures/`. |

If share fails on missing shared key, see §2.

### 6.3 Clinician

| # | Page | Action | Expected |
|---|------|--------|----------|
| C1 | **Create Dataset** | At least one Patient ID; **Save Dataset Securely** | Success; `usr_002_dataset_*.enc` under `storage/encrypted_data/`. |
| C2 | **Retrieve Dataset** | Open a saved dataset | Decrypted table or text. |
| C3 | **My Datasets** | **Refresh List** | Lists that clinician’s `.enc` files. |
| C4 | **View Shared Research** (after R5) | Select shared file; Researcher ID `usr_001`; **Verify & Open** | Signer confirmed; record shown. |
| C5 | **View Shared Research** | Wrong researcher ID | Signature / verification error. |
| C6 | After C4 | **Use This Record in a Dataset** | **Create Dataset** opens with pre-filled row; save again to confirm import. |

### 6.4 Auditor

| # | Tab | Action | Expected |
|---|-----|--------|----------|
| A1 | **Audit Log** | **Load Audit Log** | Entries + valid/tampered from HMAC check. |
| A2 | **Log Integrity** | **Run Integrity Check** | Counts / all-intact message. |
| A3 | **Confirm Record Authorship** | Encrypted file + matching `.sig` + researcher `usr_001` | Success when pair matches that signer. |
| A4 | **Verify File Integrity** | File + password field + **Verify Against Registered Baseline** | Match if unchanged since registration; mismatch if file edited on disk. |

**A4:** The password field re-authenticates the current user; use `auditor_01` / `Auditor@123` when logged in as the auditor.

### 6.5 Resetting state between runs

```bash
python reset.py
```

Non-interactive:

```bash
python reset.py --yes
```

Clears encrypted data, shared files, signatures, audit log, file registry, generated RSA/HMAC keys, and `config/lockout.json`. **Does not** remove `config/users.json`. Next logins regenerate keys.

---

## 7. Repository layout

| Path | Contents |
|------|----------|
| `app.py` | Streamlit UI |
| `auth/login.py` | Argon2id, lockout, session timeout |
| `crypto/` | AES-GCM, HKDF, RSA-PSS, SHA-256, HMAC helpers |
| `roles/` | Researcher / clinician / auditor logic |
| `storage/` | Ciphertext, shared records, signatures, audit log, registry |
| `config/users.json` | Accounts |
| `config/shared_research.key` | Shared symmetric key for cross-role research files |

---

## 8. Troubleshooting

| Issue | Try |
|-------|-----|
| `ModuleNotFoundError` | `pip install streamlit argon2-cffi cryptography` in the active environment |
| Import / path errors | `streamlit run app.py` from project root |
| Shared research errors | `config/shared_research.key` present and **32 bytes** |
| Post–lockout login | Wait 5 minutes or remove `config/lockout.json` with app stopped |
| Port in use | `streamlit run app.py --server.port 8502` |

---
