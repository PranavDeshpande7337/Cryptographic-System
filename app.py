"""
app.py
------
Streamlit frontend for the Secure Clinical Research Platform.
"""

import os
import json
import streamlit as st

from auth.login import (
    authenticate, require_role, is_locked_out,
    check_session, refresh_session, session_time_remaining,
    MAX_ATTEMPTS, LOCKOUT_DURATION, SESSION_TIMEOUT_SECONDS,
    _load_lockout
)
from crypto.key_management import generate_key_pair, key_pair_exists
from roles.researcher import (
    create_and_encrypt_record, decrypt_research_record,
    list_research_records, sign_record, verify_record_signature,
    share_record_with_clinician
)
from roles.clinician import (
    create_and_encrypt_dataset, upload_patient_dataset,
    retrieve_patient_dataset, list_datasets,
    list_shared_records, view_shared_research
)
from roles.auditor import (
    view_audit_log, check_log_integrity,
    verify_signature, verify_file_hash, list_signatures,
    list_all_encrypted_files
)

ENCRYPTED_DIR = os.path.join(os.path.dirname(__file__), "storage", "encrypted_data")
SHARED_DIR    = os.path.join(os.path.dirname(__file__), "storage", "shared_records")
SIG_DIR       = os.path.join(os.path.dirname(__file__), "storage", "signatures")

st.set_page_config(
    page_title="Secure Clinical Research Platform",
    page_icon="🔐",
    layout="wide"
)


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def safe_error(e: Exception) -> str:
    msg = str(e)
    if isinstance(e, FileNotFoundError):
        return f"File not found: {msg}"
    if "InvalidTag" in type(e).__name__ or "InvalidTag" in msg:
        return "Access failed. The file may have been tampered with, or the password is incorrect."
    if isinstance(e, ValueError):
        return f"Error: {msg}"
    if isinstance(e, PermissionError):
        return "Permission denied accessing that file."
    return f"An unexpected error occurred: {msg}"


def check_and_refresh() -> bool:
    session = st.session_state.get("session")
    if not check_session(session):
        st.warning("⏱️ Your session has expired. Please log in again.")
        st.session_state.clear()
        st.rerun()
        return False
    refresh_session(session)
    return True


def sidebar_timer():
    session = st.session_state.get("session")
    if session:
        remaining = session_time_remaining(session)
        mins = remaining // 60
        secs = remaining % 60
        colour = "red" if remaining < 120 else "white"
        st.sidebar.markdown(
            f"<p style='font-size:15px; font-weight:bold; color:{colour};'>"
            f"⏱️ Session: {mins}m {secs}s</p>",
            unsafe_allow_html=True
        )
        if remaining == 0:
            st.session_state.clear()
            st.rerun()


# ---------------------------------------------------------------------------
# Login
# ---------------------------------------------------------------------------

def render_login():
    st.title("🔐 Secure Clinical Research Platform")
    st.markdown("Cross-border clinical data collaboration system")
    st.divider()

    col1, col2, col3 = st.columns([1, 2, 1])
    with col2:
        st.subheader("Login")
        username = st.text_input("Username", key="login_username")
        password = st.text_input("Password", type="password", key="login_password")

        if st.button("Login", use_container_width=True, type="primary"):
            if not username or not password:
                st.error("Please enter both username and password.")
                return

            locked, remaining = is_locked_out(username)
            if locked:
                mins = remaining // 60
                secs = remaining % 60
                st.error(f"🔒 Account locked. Try again in {mins}m {secs}s.")
                return

            session = authenticate(username, password)

            if session is None:
                locked, _ = is_locked_out(username)
                if locked:
                    st.error(f"🔒 Too many failed attempts. Account locked for {LOCKOUT_DURATION // 60} minutes.")
                else:
                    attempts = _load_lockout().get(username, {}).get("failed_attempts", 0)
                    left = MAX_ATTEMPTS - attempts
                    st.error(f"❌ Invalid credentials. {left} attempt(s) remaining before lockout.")
                return

            if not key_pair_exists(session["user_id"]):
                generate_key_pair(session["user_id"])

            st.session_state["session"]  = session
            st.session_state["password"] = password
            st.rerun()


# ---------------------------------------------------------------------------
# Researcher dashboard
# ---------------------------------------------------------------------------

def render_researcher():
    session  = st.session_state["session"]
    password = st.session_state["password"]

    st.title("🔬 Researcher Dashboard")
    st.caption(f"Logged in as **{session['username']}**")
    st.divider()

    tab1, tab2, tab3, tab4 = st.tabs([
        "📝 Create Record", "🔓 View My Record", "✍️ Sign Record",
        "📤 Share with Clinician"
    ])

    # ── Tab 1: Create & Encrypt ─────────────────────────────────────────────
    with tab1:
        st.subheader("Create & Protect a Research Record")
        st.caption("Your record will be securely stored so only you can access it with your password.")

        with st.form("create_record_form"):
            col1, col2 = st.columns(2)
            with col1:
                patient_id  = st.text_input("Patient ID *", placeholder="e.g. PAT-2024-001")
                age         = st.number_input("Age", min_value=0, max_value=150, value=0)
                diagnosis   = st.text_input("Diagnosis", placeholder="e.g. Hypertension")
            with col2:
                treatment   = st.text_input("Treatment / Medication", placeholder="e.g. Lisinopril 10mg")
                trial_phase = st.selectbox("Trial Phase", ["N/A", "Phase I", "Phase II", "Phase III", "Phase IV"])
                outcome     = st.selectbox("Outcome", ["Ongoing", "Improved", "Stable", "Deteriorated", "Withdrawn"])
            notes     = st.text_area("Clinical Notes", placeholder="Additional observations...")
            submitted = st.form_submit_button("🔐 Save Record Securely", type="primary", use_container_width=True)

        if submitted:
            if not patient_id.strip():
                st.error("Patient ID is required.")
            elif check_and_refresh():
                record = {
                    "patient_id":  patient_id.strip(),
                    "age":         age,
                    "diagnosis":   diagnosis,
                    "treatment":   treatment,
                    "trial_phase": trial_phase,
                    "outcome":     outcome,
                    "notes":       notes
                }
                try:
                    out = create_and_encrypt_record(session, password, record)
                    st.success(f"✅ Record saved: `{os.path.basename(out)}`")
                except Exception as e:
                    st.error(safe_error(e))

    # ── Tab 2: Decrypt Record ───────────────────────────────────────────────
    with tab2:
        st.subheader("View Your Research Record")
        st.caption("Access a record you previously saved. Your password is required to unlock it.")

        records = list_research_records(session) if check_session(session) else []
        if not records:
            st.info("No records found for your account.")
        else:
            selected = st.selectbox("Select record to view", records, key="dec_record_select")
            if st.button("🔓 Open Record", type="primary"):
                if check_and_refresh():
                    enc_path = os.path.join(ENCRYPTED_DIR, selected)
                    try:
                        record = decrypt_research_record(session, password, enc_path)
                        st.success("✅ Record unlocked successfully.")
                        st.divider()
                        skip = {"created_by", "timestamp"}
                        items = [(k, v) for k, v in record.items() if k not in skip]
                        cols = st.columns(2)
                        for i, (k, v) in enumerate(items):
                            with cols[i % 2]:
                                st.metric(k.replace("_", " ").title(), str(v))
                    except Exception as e:
                        st.error(safe_error(e))

    # ── Tab 3: Sign Record ──────────────────────────────────────────────────
    with tab3:
        st.subheader("Sign a Record for Non-Repudiation")
        st.caption(
            "Signing a record proves it came from you and has not been altered — "
            "you cannot later deny authorship. A clinician or auditor can independently "
            "verify your signature. You cannot verify your own."
        )

        records = list_research_records(session) if check_session(session) else []
        if not records:
            st.info("No records found. Create a record first.")
        else:
            selected_sign = st.selectbox("Select record to sign", records, key="sign_record_select")
            if st.button("✍️ Sign Record", type="primary"):
                if check_and_refresh():
                    enc_path = os.path.join(ENCRYPTED_DIR, selected_sign)
                    try:
                        sig_path = sign_record(session, enc_path)
                        st.success(f"✅ Record signed. Signature saved: `{os.path.basename(sig_path)}`")
                        st.info(
                            "ℹ️ A **clinician** or **auditor** can now confirm this record is "
                            "genuinely yours and has not been modified."
                        )
                    except Exception as e:
                        st.error(safe_error(e))

    # ── Tab 4: Share with Clinician ───────────────────────────────────────────
    with tab4:
        st.subheader("📤 Share a Record with a Clinician")

        records = list_research_records(session) if check_session(session) else []
        if not records:
            st.info("No records found. Create and sign a record first.")
        else:
            selected_share = st.selectbox("Select record to share", records, key="share_record_select")

            st.warning(
                "⚠️ The clinician will be able to read the contents of this record. "
                "Only share records appropriate for clinical use."
            )

            if st.button("📤 Share Record", type="primary"):
                if check_and_refresh():
                    enc_path = os.path.join(ENCRYPTED_DIR, selected_share)
                    try:
                        shared_enc, shared_sig = share_record_with_clinician(
                            session, password, enc_path
                        )
                        st.success(
                            f"✅ Record shared successfully!\n\n"
                            f"The clinician can now view this record and confirm it came from you (`{session['user_id']}`)."
                        )
                    except Exception as e:
                        st.error(safe_error(e))


# ---------------------------------------------------------------------------
# Clinician dashboard
# ---------------------------------------------------------------------------

def _empty_row() -> dict:
    """Return a blank dataset row using the shared researcher/clinician schema."""
    return {
        "patient_id":  "",
        "age":         0,
        "diagnosis":   "",
        "treatment":   "",
        "trial_phase": "N/A",
        "outcome":     "Ongoing",
        "notes":       "",
    }


def render_clinician():
    session  = st.session_state["session"]
    password = st.session_state["password"]

    st.title("🏥 Clinician Dashboard")
    st.caption(f"Logged in as **{session['username']}**")
    st.divider()

    # ── Shared state ────────────────────────────────────────────────────────
    if "clin_rows" not in st.session_state:
        st.session_state["clin_rows"] = [_empty_row()]

    # Sidebar-style pill navigation — lets us switch programmatically via session state
    PAGES = ["📝 Create Dataset", "🔓 Retrieve Dataset", "📋 My Datasets", "🔬 View Shared Research"]
    if "clin_page" not in st.session_state:
        st.session_state["clin_page"] = PAGES[0]

    # Render nav pills horizontally
    nav_cols = st.columns(len(PAGES))
    for col, page in zip(nav_cols, PAGES):
        is_active = st.session_state["clin_page"] == page
        if col.button(page, use_container_width=True,
                      type="primary" if is_active else "secondary"):
            st.session_state["clin_page"] = page
            st.rerun()

    st.divider()

    active = st.session_state["clin_page"]

    # ── Page: Create Dataset ─────────────────────────────────────────────────
    if active == PAGES[0]:
        _render_create_dataset(session, password)

    # ── Page: Retrieve Dataset ───────────────────────────────────────────────
    elif active == PAGES[1]:
        _render_retrieve_dataset(session, password)

    # ── Page: My Datasets ────────────────────────────────────────────────────
    elif active == PAGES[2]:
        _render_my_datasets(session)

    # ── Page: View Shared Research ───────────────────────────────────────────
    elif active == PAGES[3]:
        _render_view_shared(session)


# ── Clinician sub-pages ──────────────────────────────────────────────────────

TRIAL_PHASES = ["N/A", "Phase I", "Phase II", "Phase III", "Phase IV"]
OUTCOMES     = ["Ongoing", "Improved", "Stable", "Deteriorated", "Withdrawn"]


def _render_create_dataset(session, password):
    st.subheader("Create & Protect a Patient Dataset")
    st.caption("Patient data will be securely stored so only you can access it with your password.")

    # Banner shown after a merge redirect
    if st.session_state.pop("clin_imported", False):
        st.success(
            "✅ Research record imported — fields are pre-filled below. "
            "Review, add more patients if needed, then click Save."
        )

    col_add, col_clear = st.columns([1, 1])
    with col_add:
        if st.button("➕ Add Patient Row"):
            st.session_state["clin_rows"].append(_empty_row())
            st.rerun()
    with col_clear:
        if st.button("🗑️ Clear All Rows"):
            st.session_state["clin_rows"] = [_empty_row()]
            st.rerun()

    st.divider()

    rows = []
    for i, saved in enumerate(st.session_state["clin_rows"]):
        with st.container(border=True):
            st.markdown(f"**Patient {i + 1}**")

            c1, c2, c3, c4 = st.columns([2, 1, 2, 2])
            pid = c1.text_input(
                "Patient ID *", key=f"cpid_{i}",
                value=saved.get("patient_id", ""),
                placeholder="e.g. PAT-2024-001"
            )
            age_val = saved.get("age", 0)
            try:
                age_val = int(age_val)
            except (ValueError, TypeError):
                age_val = 0
            age = c2.number_input(
                "Age", key=f"cage_{i}",
                min_value=0, max_value=150, value=age_val
            )
            diag = c3.text_input(
                "Diagnosis", key=f"cdiag_{i}",
                value=saved.get("diagnosis", ""),
                placeholder="e.g. Hypertension"
            )
            treat = c4.text_input(
                "Treatment / Medication", key=f"ctreat_{i}",
                value=saved.get("treatment", ""),
                placeholder="e.g. Lisinopril 10mg"
            )

            c5, c6 = st.columns(2)
            saved_phase = saved.get("trial_phase", "N/A")
            phase_idx   = TRIAL_PHASES.index(saved_phase) if saved_phase in TRIAL_PHASES else 0
            trial_phase = c5.selectbox(
                "Trial Phase", TRIAL_PHASES,
                index=phase_idx, key=f"cphase_{i}"
            )
            saved_outcome = saved.get("outcome", "Ongoing")
            outcome_idx   = OUTCOMES.index(saved_outcome) if saved_outcome in OUTCOMES else 0
            outcome = c6.selectbox(
                "Outcome", OUTCOMES,
                index=outcome_idx, key=f"coutcome_{i}"
            )

            notes = st.text_area(
                "Clinical Notes", key=f"cnotes_{i}",
                value=saved.get("notes", ""),
                placeholder="Additional observations...",
                height=80
            )

        rows.append({
            "patient_id":  pid,
            "age":         age,
            "diagnosis":   diag,
            "treatment":   treat,
            "trial_phase": trial_phase,
            "outcome":     outcome,
            "notes":       notes,
        })

    st.divider()
    if st.button("🔐 Save Dataset Securely", type="primary", use_container_width=True):
        valid_rows = [r for r in rows if str(r.get("patient_id", "")).strip()]
        if not valid_rows:
            st.error("Please enter at least one patient with a Patient ID.")
        elif check_and_refresh():
            try:
                out = create_and_encrypt_dataset(session, password, valid_rows)
                st.success(f"✅ Dataset saved: `{os.path.basename(out)}`")
                st.session_state["clin_rows"] = [_empty_row()]
                st.rerun()
            except Exception as e:
                st.error(safe_error(e))


def _render_retrieve_dataset(session, password):
    st.subheader("Open a Patient Dataset")
    st.caption("Your password is required to unlock and view a saved dataset.")

    datasets = list_datasets(session) if check_session(session) else []
    if not datasets:
        st.info("No datasets found. Create one first.")
    else:
        selected = st.selectbox("Select dataset to open", datasets)

        # Clear cached result when the user picks a different file
        if st.session_state.get("_retrieved_file") != selected:
            st.session_state.pop("_retrieved_result", None)
            st.session_state["_retrieved_file"] = selected

        if st.button("🔓 Open Dataset", type="primary"):
            if check_and_refresh():
                try:
                    result = retrieve_patient_dataset(session, password, selected)
                    st.session_state["_retrieved_result"] = result
                except Exception as e:
                    st.session_state.pop("_retrieved_result", None)
                    st.error(safe_error(e))

        # Render from session_state so result survives reruns without flickering
        result = st.session_state.get("_retrieved_result")
        if result is not None:
            st.success("✅ Dataset unlocked.")
            st.divider()
            if isinstance(result, dict) and "records" in result:
                st.markdown(f"**Created by:** {result.get('created_by', 'N/A')}  "
                            f"**Timestamp:** {result.get('timestamp', 'N/A')}")
                import pandas as pd
                df = pd.DataFrame(result["records"])
                st.dataframe(
                    df,
                    use_container_width=True,
                    height=min(400, (len(df) + 1) * 35 + 10),
                    column_config={col: st.column_config.TextColumn(col, width="medium")
                                   for col in df.columns}
                )
            else:
                st.text_area("Dataset contents", str(result), height=300)


def _render_my_datasets(session):
    st.subheader("My Saved Datasets")
    if st.button("🔄 Refresh List"):
        check_and_refresh()
    datasets = list_datasets(session) if check_session(session) else []
    if not datasets:
        st.info("No datasets found.")
    else:
        for ds in datasets:
            enc_path = os.path.join(ENCRYPTED_DIR, ds)
            size_kb  = os.path.getsize(enc_path) / 1024 if os.path.exists(enc_path) else 0
            col1, col2 = st.columns([4, 1])
            with col1:
                st.code(ds)
            with col2:
                st.caption(f"{size_kb:.1f} KB")


def _render_view_shared(session):
    st.subheader("🔬 View Research Records Shared with You")

    shared = list_shared_records(session) if check_session(session) else []
    if not shared:
        st.info("No shared research records available. Ask a researcher to share a record.")
        return

    col1, col2 = st.columns(2)
    with col1:
        selected_shared = st.selectbox("Select shared record", shared, key="shared_select")
    with col2:
        guessed_uid = ""
        if selected_shared:
            parts = selected_shared.split("_")
            if len(parts) >= 2:
                guessed_uid = f"{parts[0]}_{parts[1]}"
        researcher_uid = st.text_input(
            "Researcher ID (who shared this record)",
            value=guessed_uid,
            placeholder="e.g. usr_001",
            key="shared_researcher_uid"
        )

    if st.button("🔓 Verify & Open Shared Record", type="primary"):
        if not researcher_uid.strip():
            st.error("Please enter the researcher's ID.")
        elif check_and_refresh():
            try:
                result = view_shared_research(session, selected_shared, researcher_uid.strip())
                st.session_state["shared_result"] = result
            except ValueError as e:
                st.error(f"🚫 {e}")
                st.session_state.pop("shared_result", None)
            except Exception as e:
                st.error(safe_error(e))
                st.session_state.pop("shared_result", None)

    # Display the opened record if we have one
    result = st.session_state.get("shared_result")
    if result:
        st.success(
            f"✅ Identity confirmed — record is genuinely from "
            f"`{result['verified_signer']}` and has not been altered."
        )
        st.divider()
        record = result["record"]
        meta_col1, meta_col2 = st.columns(2)
        meta_col1.info(f"**Created by:** {record.get('created_by', 'N/A')}")
        meta_col2.info(f"**Timestamp:** {record.get('timestamp', 'N/A')}")
        st.divider()
        skip  = {"created_by", "timestamp"}
        items = [(k, v) for k, v in record.items() if k not in skip]
        cols  = st.columns(2)
        for i, (k, v) in enumerate(items):
            with cols[i % 2]:
                st.metric(k.replace("_", " ").title(), str(v))
        st.divider()

        st.caption("Import this verified record directly into your dataset.")
        if st.button("➕ Use This Record in a Dataset", type="primary", key="merge_to_dataset"):
            new_row = {
                "patient_id":  str(record.get("patient_id", "")),
                "age":         record.get("age", 0),
                "diagnosis":   str(record.get("diagnosis", "")),
                "treatment":   str(record.get("treatment", "")),
                "trial_phase": str(record.get("trial_phase", "N/A")),
                "outcome":     str(record.get("outcome", "Ongoing")),
                "notes":       str(record.get("notes", "")),
            }
            existing  = st.session_state.get("clin_rows", [])
            non_blank = [r for r in existing if any(str(v).strip() for v in r.values())]
            st.session_state["clin_rows"]    = non_blank + [new_row]
            st.session_state["clin_imported"] = True
            st.session_state["clin_page"]    = "📝 Create Dataset"
            st.session_state.pop("shared_result", None)
            st.rerun()


# ---------------------------------------------------------------------------
# Auditor dashboard
# ---------------------------------------------------------------------------

def render_auditor():
    session = st.session_state["session"]

    st.title("🔍 Auditor Dashboard")
    st.caption(f"Logged in as **{session['username']}** · Read-only access")
    st.divider()

    tab1, tab2, tab3, tab4 = st.tabs([
        "📋 Audit Log", "🔒 Log Integrity", "✅ Confirm Record Authorship", "🧾 Verify File Integrity"
    ])

    # ── Tab 1: Audit Log ────────────────────────────────────────────────────
    with tab1:
        st.subheader("Audit Log")
        st.caption("A record of all actions taken on the platform.")
        if st.button("🔄 Load Audit Log", type="primary"):
            if check_and_refresh():
                entries = view_audit_log(session)
                if not entries:
                    st.info("Audit log is empty.")
                else:
                    valid_count   = sum(1 for e in entries if e.get("valid"))
                    invalid_count = len(entries) - valid_count

                    c1, c2, c3 = st.columns(3)
                    c1.metric("Total Entries", len(entries))
                    c2.metric("✅ Intact", valid_count)
                    c3.metric("❌ Tampered", invalid_count,
                              delta=f"{invalid_count} tampered" if invalid_count else None,
                              delta_color="inverse")

                    st.divider()
                    for e in entries:
                        if "error" in e:
                            st.error(f"Malformed entry: {e.get('raw', '')}")
                            continue
                        indicator = "🟢" if e["valid"] else "🔴"
                        with st.container(border=True):
                            col1, col2, col3, col4 = st.columns([2, 1, 2, 1])
                            col1.caption(e["timestamp"])
                            col2.write(f"**{e['username']}**")
                            col3.write(f"`{e['action']}`  {e['details']}")
                            col4.write(f"{indicator} {'OK' if e['valid'] else '**TAMPERED**'}")

    # ── Tab 2: Log Integrity ────────────────────────────────────────────────
    with tab2:
        st.subheader("Check Audit Log Integrity")
        st.write(
            "Each audit log entry is protected against tampering. "
            "This check confirms every entry is unchanged since it was recorded."
        )
        if st.button("🔒 Run Integrity Check", type="primary"):
            if check_and_refresh():
                valid, invalid = check_log_integrity(session)
                if invalid == 0:
                    st.success(f"✅ All {valid} log entries are intact. No tampering detected.")
                else:
                    st.error(f"❌ {invalid} tampered or malformed entries detected out of {valid + invalid} total.")

    # ── Tab 3: Confirm Record Authorship ─────────────────────────────────────
    with tab3:
        st.subheader("Confirm a Record's Authorship")
        st.markdown(
            """
            Verify that a specific researcher authored a record and that it has not been changed since they signed it.

            **As an independent auditor**, you confirm authorship using the researcher's public identity —
            you are a separate party from the signer, which is what makes this verification meaningful for audit purposes.
            """
        )

        all_enc_personal = sorted([f for f in os.listdir(ENCRYPTED_DIR) if f.endswith(".enc")]) \
                           if os.path.exists(ENCRYPTED_DIR) else []
        all_enc_shared   = sorted([f for f in os.listdir(SHARED_DIR) if f.endswith(".enc")]) \
                           if os.path.exists(SHARED_DIR) else []
        all_enc = (
            [f"encrypted_data/{f}" for f in all_enc_personal] +
            [f"shared_records/{f}" for f in all_enc_shared]
        )
        all_sig = sorted([f for f in os.listdir(SIG_DIR) if f.endswith(".sig")]) \
                  if os.path.exists(SIG_DIR) else []

        if not all_enc:
            st.info("No records found in storage.")
        elif not all_sig:
            st.info("No signed records found in storage.")
        else:
            col1, col2 = st.columns(2)
            with col1:
                sel_enc = st.selectbox("Record to check", all_enc, key="aud_vsig_enc")
            with col2:
                sel_sig = st.selectbox("Signature to check against", all_sig, key="aud_vsig_sig")

            signer_uid = st.text_input(
                "Researcher ID (the person who signed the record)",
                placeholder="e.g. usr_001",
                key="aud_vsig_uid"
            )

            if st.button("✅ Confirm Authorship", type="primary", key="aud_vsig_btn"):
                if not signer_uid.strip():
                    st.error("Please enter the researcher's ID.")
                elif check_and_refresh():
                    if sel_enc.startswith("shared_records/"):
                        enc_path = os.path.join(os.path.dirname(__file__), "storage",
                                                 sel_enc.replace("/", os.sep))
                    else:
                        enc_path = os.path.join(ENCRYPTED_DIR, sel_enc.split("/")[-1])
                    sig_path = os.path.join(SIG_DIR, sel_sig)
                    try:
                        result = verify_signature(session, enc_path, sig_path, signer_uid.strip())
                        if result:
                            st.success(
                                f"✅ Confirmed — `{sel_enc.split('/')[-1]}` was authored by "
                                f"`{signer_uid.strip()}` and has not been modified."
                            )
                        else:
                            st.error("❌ Could not confirm authorship — the record may have been tampered with or the wrong researcher ID was entered.")
                    except ValueError as e:
                        st.error(f"🚫 {e}")
                    except Exception as e:
                        st.error(safe_error(e))

    # ── Tab 4: Verify File Integrity ──────────────────────────────────────────
    with tab4:
        st.subheader("Verify File Integrity")
        st.caption("Confirm whether a stored file is unchanged.")

        all_enc_personal = sorted([f for f in os.listdir(ENCRYPTED_DIR) if f.endswith(".enc")]) \
                           if os.path.exists(ENCRYPTED_DIR) else []
        all_enc_shared   = sorted([f for f in os.listdir(SHARED_DIR) if f.endswith(".enc")]) \
                           if os.path.exists(SHARED_DIR) else []
        all_enc = (
            [f"encrypted_data/{f}" for f in all_enc_personal] +
            [f"shared_records/{f}" for f in all_enc_shared]
        )

        if not all_enc:
            st.info("No files found.")
        else:
            sel_file = st.selectbox("Select file to check", all_enc, key="aud_hash_file")

            if sel_file.startswith("shared_records/"):
                enc_path = os.path.join(SHARED_DIR, sel_file.split("/")[-1])
            else:
                enc_path = os.path.join(ENCRYPTED_DIR, sel_file.split("/")[-1])

            reauth_password = st.text_input(
                "Confirm your password",
                type="password",
                key="aud_hash_reauth",
                placeholder="Re-enter your password to continue"
            )

            if st.button("🧾 Verify Against Registered Baseline", type="primary", key="aud_verify_hash"):
                if not reauth_password.strip():
                    st.error("Please re-enter your password to verify this file.")
                elif check_and_refresh():
                    reauth_session = authenticate(session["username"], reauth_password)
                    if reauth_session is None or reauth_session.get("user_id") != session.get("user_id"):
                        st.error("🚫 Re-authentication failed. Integrity check not performed.")
                    else:
                        try:
                            result = verify_file_hash(session, enc_path, file_id=sel_file)
                            if result:
                                st.success("✅ File integrity verified.")
                            else:
                                st.error("❌ Integrity check failed — file may have been modified.")
                        except Exception as e:
                            st.error(safe_error(e))


# ---------------------------------------------------------------------------
# Main router
# ---------------------------------------------------------------------------

def main():
    with st.sidebar:
        st.markdown("### 🔐 Clinical Research Platform")
        st.divider()

        if "session" in st.session_state:
            session = st.session_state["session"]
            role_icons = {"researcher": "🔬", "clinician": "🏥", "auditor": "🔍"}
            icon = role_icons.get(session["role"], "👤")
            st.markdown(f"**{icon} {session['username']}**")
            st.caption(f"Role: {session['role'].capitalize()}")
            st.divider()
            sidebar_timer()
            st.divider()
            if st.button("🚪 Logout", use_container_width=True):
                st.session_state.clear()
                st.rerun()
        else:
            st.caption("Not logged in.")

    if "session" not in st.session_state:
        render_login()
        return

    session = st.session_state["session"]

    if not check_session(session):
        st.warning("⏱️ Your session has expired. Please log in again.")
        st.session_state.clear()
        st.rerun()
        return

    role = session["role"]
    if role == "researcher":
        render_researcher()
    elif role == "clinician":
        render_clinician()
    elif role == "auditor":
        render_auditor()
    else:
        st.error("Unknown role. Please contact your administrator.")


if __name__ == "__main__":
    main()