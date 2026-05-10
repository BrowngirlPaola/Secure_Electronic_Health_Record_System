"""
Vitalis EHR — Flask Route Blueprints (v3.0)
=============================================
All routes organized into blueprints:
  - auth_bp      → login, logout
  - dashboard_bp → role-specific dashboards (5 roles)
  - records_bp   → health records CRUD with FLAC + signatures
  - admin_bp     → user management, audit logs, suspicious activity, integrity, BTG review
  - lab_bp       → lab technician queue + result submission
  - api_bp       → encryption proof, signature verification endpoints
"""

from flask import (
    Blueprint, render_template, request, redirect,
    url_for, flash, session, abort, jsonify,
)

from auth import (
    login_required, role_required, login_user, logout_user,
    get_current_user, verify_password, hash_password,
    check_account_locked, record_failed_attempt, reset_failed_attempts,
    unlock_account,
)
from security import (
    log_audit_event, AuditAction, detect_suspicious_activity,
    get_suspicious_activities, get_audit_logs,
)
from encryption import encrypt_field, decrypt_field, get_encryption_proof
from models import UserModel, RecordModel, AuditLogModel, AssignmentModel
from utils import validate_password, validate_email, sanitize_input, get_role_display


# ═══════════════════════════════════════════════════════════════════
#  AUTH BLUEPRINT — /login, /logout
# ═══════════════════════════════════════════════════════════════════
auth_bp = Blueprint("auth_bp", __name__)


@auth_bp.route("/login", methods=["GET", "POST"])
def login():
    """Handle user authentication with session fingerprinting."""
    if request.method == "GET":
        return render_template("login.html")

    email = request.form.get("email", "").strip().lower()
    password = request.form.get("password", "")

    if not email or not password:
        return redirect(url_for("auth_bp.login", error=1))

    from app import get_supabase
    supabase = get_supabase()
    user_model = UserModel(supabase)

    # Check if account is locked
    if check_account_locked(supabase, email):
        log_audit_event(supabase, None, AuditAction.LOGIN_FAILED,
                        f"Login attempt on locked account: {email}", "warning")
        return redirect(url_for("auth_bp.login", locked=1))

    # Find user
    user = user_model.get_by_email(email)
    if not user or not verify_password(password, user.get("password_hash", "")):
        if user:
            is_now_locked = record_failed_attempt(supabase, email)
            log_audit_event(supabase, user["id"], AuditAction.LOGIN_FAILED,
                            f"Failed login for {email}", "warning")
            if is_now_locked:
                log_audit_event(supabase, user["id"], AuditAction.ACCOUNT_LOCKED,
                                f"Account locked after failed attempts", "critical")
                return redirect(url_for("auth_bp.login", locked=1))
        return redirect(url_for("auth_bp.login", error=1))

    # Prevent canary accounts from logging in
    if user.get("is_canary"):
        return redirect(url_for("auth_bp.login", error=1))

    # Successful login
    reset_failed_attempts(supabase, email)
    login_user(user)

    # Store session fingerprint (Feature 3: Hijacking Detection)
    from session_security import store_fingerprint
    fingerprint = store_fingerprint()

    log_audit_event(supabase, user["id"], AuditAction.LOGIN_SUCCESS,
                    f"User {email} logged in. Fingerprint: {fingerprint[:12]}...", "info")

    # Run suspicious activity detection
    detect_suspicious_activity(supabase, user["id"])

    # Redirect to role-specific dashboard
    return redirect(url_for(_dashboard_for_role(user["role"])))


@auth_bp.route("/logout")
@login_required
def logout():
    """Log out the current user."""
    from app import get_supabase
    user = get_current_user()
    if user:
        log_audit_event(get_supabase(), user["id"], AuditAction.LOGOUT,
                        f"User {user['email']} logged out", "info")
    logout_user()
    flash("You have been logged out.", "info")
    return redirect(url_for("auth_bp.login"))


def _dashboard_for_role(role: str) -> str:
    """Return the correct dashboard endpoint for a role."""
    return {
        "admin": "dashboard_bp.admin_dashboard",
        "doctor": "dashboard_bp.doctor_dashboard",
        "nurse": "dashboard_bp.nurse_dashboard",
        "lab_tech": "dashboard_bp.lab_dashboard",
        "patient": "dashboard_bp.patient_dashboard",
    }.get(role, "auth_bp.login")


# ═══════════════════════════════════════════════════════════════════
#  DASHBOARD BLUEPRINT — role-specific dashboards (5 roles)
# ═══════════════════════════════════════════════════════════════════
dashboard_bp = Blueprint("dashboard_bp", __name__)


@dashboard_bp.route("/dashboard/admin")
@role_required("admin")
def admin_dashboard():
    """Admin dashboard with system overview + security alerts."""
    from app import get_supabase
    from honeypot import get_honeypot_alerts
    from emergency_access import get_btg_stats
    from integrity import get_chain_summary

    supabase = get_supabase()
    user_model = UserModel(supabase)
    audit_model = AuditLogModel(supabase)

    role_counts = user_model.count_by_role()
    total_users = sum(role_counts.values())
    locked_accounts = user_model.get_locked_accounts()
    recent_logs = audit_model.get_recent(limit=10)
    honeypot_alerts = get_honeypot_alerts(supabase, limit=5)
    btg_stats = get_btg_stats(supabase)
    chain_status = get_chain_summary(supabase)

    return render_template("admin_dashboard.html",
                           user=get_current_user(),
                           total_users=total_users,
                           role_counts=role_counts,
                           locked_accounts=locked_accounts,
                           recent_logs=recent_logs,
                           honeypot_alerts=honeypot_alerts,
                           btg_stats=btg_stats,
                           chain_status=chain_status)


@dashboard_bp.route("/dashboard/doctor")
@role_required("doctor")
def doctor_dashboard():
    """Doctor dashboard — only assigned patients and their records."""
    from app import get_supabase
    supabase = get_supabase()
    user = get_current_user()
    record_model = RecordModel(supabase)
    assign_model = AssignmentModel(supabase)

    # Get assigned patients and their records
    assigned_patients = assign_model.get_patients_with_info(user["id"])
    patient_ids = assign_model.get_patients_for_doctor(user["id"])
    records = record_model.get_for_doctor(patient_ids)

    return render_template("doctor_dashboard.html",
                           user=user, records=records,
                           assigned_patients=assigned_patients)


@dashboard_bp.route("/dashboard/nurse")
@role_required("nurse")
def nurse_dashboard():
    """Nurse dashboard — only records created by this nurse."""
    from app import get_supabase
    supabase = get_supabase()
    user = get_current_user()
    record_model = RecordModel(supabase)

    records = record_model.get_created_by(user["id"])
    return render_template("nurse_dashboard.html",
                           user=user, records=records)


@dashboard_bp.route("/dashboard/lab")
@role_required("lab_tech")
def lab_dashboard():
    """Lab Technician dashboard — pending specimens queue."""
    from app import get_supabase
    supabase = get_supabase()
    record_model = RecordModel(supabase)

    pending = record_model.get_lab_queue()
    return render_template("lab_dashboard.html",
                           user=get_current_user(), pending=pending)


@dashboard_bp.route("/dashboard/patient")
@role_required("patient")
def patient_dashboard():
    """Patient dashboard — own records with FLAC applied."""
    from app import get_supabase
    supabase = get_supabase()
    user = get_current_user()
    record_model = RecordModel(supabase)

    records = record_model.get_by_patient(user["id"], decrypt=True, role="patient")
    return render_template("patient_dashboard.html",
                           user=user, records=records)


# ═══════════════════════════════════════════════════════════════════
#  RECORDS BLUEPRINT — Health Records CRUD with FLAC + Honeypot
# ═══════════════════════════════════════════════════════════════════
records_bp = Blueprint("records_bp", __name__)


@records_bp.route("/records")
@role_required("admin", "doctor", "nurse")
def list_records():
    """
    List health records — filtered by role:
      Admin  → all records
      Doctor → only assigned patients' records
      Nurse  → only records they created
    """
    from app import get_supabase
    supabase = get_supabase()
    record_model = RecordModel(supabase)
    assign_model = AssignmentModel(supabase)
    user = get_current_user()

    if user["role"] == "admin":
        records = record_model.get_all()
    elif user["role"] == "doctor":
        patient_ids = assign_model.get_patients_for_doctor(user["id"])
        records = record_model.get_for_doctor(patient_ids)
    elif user["role"] == "nurse":
        records = record_model.get_created_by(user["id"])
    else:
        records = []

    log_audit_event(supabase, user["id"], AuditAction.RECORD_VIEWED,
                    "Viewed records list", "info")
    return render_template("records.html", user=user, records=records)


@records_bp.route("/records/<record_id>")
@role_required("admin", "doctor", "nurse", "patient")
def view_record(record_id):
    """View a single record with FLAC + honeypot check."""
    from app import get_supabase
    from honeypot import check_honeypot_access
    from emergency_access import check_btg_active

    supabase = get_supabase()
    user = get_current_user()
    record_model = RecordModel(supabase)

    # First fetch without decryption to check permissions
    record_raw = record_model.get_by_id(record_id)
    if not record_raw:
        abort(404)

    # Patient can only view their own records
    if user["role"] == "patient" and record_raw.get("patient_id") != user["id"]:
        abort(403)

    # Doctor can only view assigned patients' records
    if user["role"] == "doctor":
        assign_model = AssignmentModel(supabase)
        if not assign_model.is_assigned(user["id"], record_raw.get("patient_id")):
            # Check for active BTG grant
            if check_btg_active(supabase, user["id"], record_id):
                flash("Emergency access active. This access is being monitored.", "warning")
            else:
                # Offer Break-the-Glass
                return render_template("break_the_glass.html",
                                       user=user, record_id=record_id)

    # Nurse can only view records they created
    if user["role"] == "nurse" and record_raw.get("created_by") != user["id"]:
        # Check for active BTG grant
        if check_btg_active(supabase, user["id"], record_id):
            flash("Emergency access active. This access is being monitored.", "warning")
        else:
            # Offer Break-the-Glass
            return render_template("break_the_glass.html",
                                   user=user, record_id=record_id)

    # Check honeypot (SILENT — user doesn't know)
    check_honeypot_access(supabase, record_id, user["id"])

    # Decrypt with FLAC applied based on role
    record = record_model.get_by_id(record_id, decrypt=True, role=user["role"])

    log_audit_event(supabase, user["id"], AuditAction.RECORD_DECRYPTED,
                    f"Decrypted record {record_id}", "info")

    return render_template("view_record.html", user=user, record=record)


@records_bp.route("/records/new", methods=["GET", "POST"])
@role_required("doctor", "nurse")
def new_record():
    """
    Create a new health record with digital signature.
    Doctor → patient dropdown shows only assigned patients.
    Nurse  → patient dropdown shows all patients.
    """
    from app import get_supabase
    supabase = get_supabase()
    user = get_current_user()
    user_model = UserModel(supabase)

    if request.method == "GET":
        if user["role"] == "doctor":
            # Doctor can only create records for assigned patients
            assign_model = AssignmentModel(supabase)
            assigned = assign_model.get_patients_with_info(user["id"])
            patients = [
                {"id": a["patient"]["id"],
                 "email": a["patient"]["email"],
                 "full_name": a["patient"]["full_name"]}
                for a in assigned if a.get("patient")
            ]
        else:
            # Nurse can create for any patient
            all_users = user_model.get_all()
            patients = [u for u in all_users if u["role"] == "patient" and not u.get("is_canary")]

        return render_template("new_record.html", user=user, patients=patients)

    # POST — create the record
    patient_id = request.form.get("patient_id", "")
    diagnosis = sanitize_input(request.form.get("diagnosis", ""))
    treatment = sanitize_input(request.form.get("treatment", ""))
    lab_results = sanitize_input(request.form.get("lab_results", ""))
    notes = sanitize_input(request.form.get("notes", ""))

    if not patient_id or not diagnosis:
        flash("Patient and diagnosis are required.", "error")
        return redirect(url_for("records_bp.new_record"))

    # Doctor: verify the patient is assigned before creating
    if user["role"] == "doctor":
        assign_model = AssignmentModel(supabase)
        if not assign_model.is_assigned(user["id"], patient_id):
            flash("You can only create records for your assigned patients.", "error")
            return redirect(url_for("records_bp.new_record"))

    record_model = RecordModel(supabase)
    record = record_model.create(
        patient_id=patient_id,
        created_by=user["id"],
        diagnosis=diagnosis,
        treatment=treatment,
        lab_results=lab_results,
        notes=notes,
    )

    log_audit_event(supabase, user["id"], AuditAction.RECORD_CREATED,
                    f"Created record for patient {patient_id} (digitally signed)", "info")

    flash("Health record created. Data encrypted with AES-256-CBC and digitally signed.", "success")
    return redirect(url_for("records_bp.list_records"))


@records_bp.route("/records/<record_id>/delete", methods=["POST"])
@role_required("admin")
def delete_record(record_id):
    """Delete a health record (admin only)."""
    from app import get_supabase
    supabase = get_supabase()
    user = get_current_user()
    record_model = RecordModel(supabase)

    record_model.delete(record_id)
    log_audit_event(supabase, user["id"], AuditAction.RECORD_DELETED,
                    f"Deleted record {record_id}", "warning")

    flash("Record deleted.", "info")
    return redirect(url_for("records_bp.list_records"))


@records_bp.route("/records/<record_id>/break-glass", methods=["POST"])
@role_required("doctor", "nurse")
def break_glass(record_id):
    """Process Break-the-Glass emergency access request."""
    from app import get_supabase
    from emergency_access import initiate_btg

    supabase = get_supabase()
    user = get_current_user()
    justification = request.form.get("justification", "").strip()

    if not justification or len(justification) < 10:
        flash("Justification must be at least 10 characters.", "error")
        return render_template("break_the_glass.html",
                               user=user, record_id=record_id)

    initiate_btg(supabase, user["id"], record_id, justification)

    flash(f"Emergency access granted for 30 minutes. This event has been logged at CRITICAL severity.", "warning")
    return redirect(url_for("records_bp.view_record", record_id=record_id))


@records_bp.route("/records/<record_id>/verify-signature")
@login_required
def verify_record_signature(record_id):
    """Verify the digital signature of a health record."""
    from app import get_supabase
    from signatures import verify_signature

    supabase = get_supabase()
    user = get_current_user()
    record_model = RecordModel(supabase)
    user_model = UserModel(supabase)

    # Get the record (decrypt to get plaintext for verification)
    record = record_model.get_by_id(record_id, decrypt=True)
    if not record:
        abort(404)

    # Get the author's public key
    author_id = record.get("created_by")
    author = user_model.get_by_id(author_id) if author_id else None
    public_key = author.get("public_key", "") if author else ""

    # Build the fields that were signed
    signed_fields = {
        "diagnosis": record.get("diagnosis", ""),
        "treatment": record.get("treatment", ""),
        "lab_results": record.get("lab_results", ""),
        "notes": record.get("notes", ""),
    }

    # Verify
    verification = verify_signature(
        signed_fields,
        record.get("signature", ""),
        public_key,
    )

    # Also verify lab signature if present
    lab_verification = None
    if record.get("lab_signature"):
        lab_tech_id = record.get("lab_signed_by")
        lab_tech = user_model.get_by_id(lab_tech_id) if lab_tech_id else None
        lab_public_key = lab_tech.get("public_key", "") if lab_tech else ""

        lab_verification = verify_signature(
            {"lab_results": record.get("lab_results", "")},
            record.get("lab_signature", ""),
            lab_public_key,
        )

    log_audit_event(supabase, user["id"], AuditAction.SIGNATURE_VERIFIED,
                    f"Verified signature on record {record_id}", "info")

    return render_template("signature_verification.html",
                           user=user, record=record, author=author,
                           verification=verification,
                           lab_verification=lab_verification)


# ═══════════════════════════════════════════════════════════════════
#  LAB BLUEPRINT — Lab Technician routes
# ═══════════════════════════════════════════════════════════════════
lab_bp = Blueprint("lab_bp", __name__)


@lab_bp.route("/lab/submit/<record_id>", methods=["GET", "POST"])
@role_required("lab_tech")
def submit_lab_results(record_id):
    """Lab Tech submits and signs lab results for a record."""
    from app import get_supabase
    supabase = get_supabase()
    user = get_current_user()
    record_model = RecordModel(supabase)

    record = record_model.get_by_id(record_id)
    if not record:
        abort(404)

    if request.method == "GET":
        return render_template("lab_submit.html", user=user, record=record)

    # POST — submit results
    lab_results = sanitize_input(request.form.get("lab_results", ""))
    if not lab_results:
        flash("Lab results are required.", "error")
        return redirect(url_for("lab_bp.submit_lab_results", record_id=record_id))

    record_model.submit_lab_results(record_id, user["id"], lab_results)

    log_audit_event(supabase, user["id"], AuditAction.LAB_RESULTS_SIGNED,
                    f"Lab results submitted and signed for record {record_id}", "info")

    flash("Lab results submitted and digitally signed. Chain of custody recorded.", "success")
    return redirect(url_for("dashboard_bp.lab_dashboard"))


# ═══════════════════════════════════════════════════════════════════
#  ADMIN BLUEPRINT — User management, Audit, Security, Integrity
# ═══════════════════════════════════════════════════════════════════
admin_bp = Blueprint("admin_bp", __name__)


@admin_bp.route("/users")
@role_required("admin")
def list_users():
    """List all users."""
    from app import get_supabase
    supabase = get_supabase()
    user_model = UserModel(supabase)

    users = user_model.get_all()
    return render_template("users.html", user=get_current_user(), users=users)


@admin_bp.route("/users/register", methods=["GET", "POST"])
@role_required("admin")
def register_user():
    """Admin registers a new user (RSA keys auto-generated)."""
    if request.method == "GET":
        return render_template("register.html", user=get_current_user())

    from app import get_supabase
    supabase = get_supabase()
    user_model = UserModel(supabase)

    email = request.form.get("email", "").strip().lower()
    password = request.form.get("password", "")
    full_name = sanitize_input(request.form.get("full_name", ""))
    role = request.form.get("role", "patient")

    # Validation
    if not validate_email(email):
        flash("Invalid email address.", "error")
        return redirect(url_for("admin_bp.register_user"))

    pw_check = validate_password(password)
    if not pw_check["valid"]:
        for err in pw_check["errors"]:
            flash(err, "error")
        return redirect(url_for("admin_bp.register_user"))

    if role not in ("admin", "doctor", "nurse", "lab_tech", "patient"):
        flash("Invalid role selected.", "error")
        return redirect(url_for("admin_bp.register_user"))

    existing = user_model.get_by_email(email)
    if existing:
        flash("A user with this email already exists.", "error")
        return redirect(url_for("admin_bp.register_user"))

    # Create user (RSA key pair generated automatically in models.py)
    new_user = user_model.create(email, password, full_name, role)
    admin = get_current_user()
    log_audit_event(supabase, admin["id"], AuditAction.USER_CREATED,
                    f"Admin created user {email} ({role}) with RSA key pair", "info")

    flash(f"User {email} created as {role}. RSA-2048 key pair generated.", "success")
    return redirect(url_for("admin_bp.list_users"))


@admin_bp.route("/users/<user_id>/delete", methods=["POST"])
@role_required("admin")
def delete_user(user_id):
    """Delete a user account."""
    from app import get_supabase
    supabase = get_supabase()
    user_model = UserModel(supabase)
    admin = get_current_user()

    target = user_model.get_by_id(user_id)
    if not target:
        abort(404)
    if target["id"] == admin["id"]:
        flash("You cannot delete your own account.", "error")
        return redirect(url_for("admin_bp.list_users"))

    user_model.delete(user_id)
    log_audit_event(supabase, admin["id"], AuditAction.USER_DELETED,
                    f"Admin deleted user {target['email']}", "warning")

    flash(f"User {target['email']} deleted.", "info")
    return redirect(url_for("admin_bp.list_users"))


@admin_bp.route("/users/<user_id>/unlock", methods=["POST"])
@role_required("admin")
def unlock_user(user_id):
    """Unlock a locked user account."""
    from app import get_supabase
    supabase = get_supabase()
    admin = get_current_user()

    unlock_account(supabase, user_id)
    log_audit_event(supabase, admin["id"], AuditAction.ACCOUNT_UNLOCKED,
                    f"Admin unlocked user {user_id}", "info")

    flash("Account unlocked successfully.", "success")
    # Redirect back to referrer (dashboard or users list)
    next_page = request.form.get("next", "")
    if next_page == "dashboard":
        return redirect(url_for("dashboard_bp.admin_dashboard"))
    return redirect(url_for("admin_bp.list_users"))


@admin_bp.route("/audit-logs")
@role_required("admin")
def audit_logs():
    """View audit log entries."""
    from app import get_supabase
    supabase = get_supabase()

    logs = get_audit_logs(supabase, limit=200)
    return render_template("audit_logs.html", user=get_current_user(), logs=logs)


@admin_bp.route("/audit-integrity")
@role_required("admin")
def audit_integrity():
    """Verify hash chain integrity of the audit log (Feature 1)."""
    from app import get_supabase
    from integrity import verify_audit_chain

    supabase = get_supabase()
    user = get_current_user()

    result = verify_audit_chain(supabase)

    log_audit_event(supabase, user["id"], AuditAction.INTEGRITY_CHECK,
                    f"Audit integrity check: {'PASSED' if result['valid'] else 'FAILED'} "
                    f"({result['verified']}/{result['total']} entries verified)", "info")

    return render_template("audit_integrity.html",
                           user=user, result=result)


@admin_bp.route("/suspicious")
@role_required("admin")
def suspicious_activity():
    """View suspicious activity alerts."""
    from app import get_supabase
    supabase = get_supabase()

    activities = get_suspicious_activities(supabase, limit=100)
    return render_template("suspicious.html", user=get_current_user(),
                           activities=activities)


@admin_bp.route("/btg-review")
@role_required("admin")
def btg_review():
    """Admin review queue for Break-the-Glass events (Feature 6)."""
    from app import get_supabase
    from emergency_access import get_btg_events

    supabase = get_supabase()
    events = get_btg_events(supabase, limit=50)
    return render_template("btg_review.html",
                           user=get_current_user(), events=events)


@admin_bp.route("/btg-review/<event_id>/mark-reviewed", methods=["POST"])
@role_required("admin")
def mark_btg_reviewed(event_id):
    """Mark a BTG event as reviewed."""
    from app import get_supabase
    from emergency_access import mark_btg_reviewed as do_mark

    supabase = get_supabase()
    admin = get_current_user()

    do_mark(supabase, event_id, admin["id"])
    flash("BTG event marked as reviewed.", "success")
    return redirect(url_for("admin_bp.btg_review"))


# ─── Doctor-Patient Assignment Management ───────────────────────

@admin_bp.route("/admin/assignments")
@role_required("admin")
def assignments():
    """View and manage doctor-patient assignments."""
    from app import get_supabase
    supabase = get_supabase()
    user_model = UserModel(supabase)
    assign_model = AssignmentModel(supabase)

    all_assignments = assign_model.get_all()
    all_users = user_model.get_all()
    doctors = [u for u in all_users if u["role"] == "doctor"]
    patients = [u for u in all_users if u["role"] == "patient" and not u.get("is_canary")]

    return render_template("assignments.html",
                           user=get_current_user(),
                           assignments=all_assignments,
                           doctors=doctors,
                           patients=patients)


@admin_bp.route("/admin/assignments/assign", methods=["POST"])
@role_required("admin")
def assign_patient():
    """Assign a patient to a doctor."""
    from app import get_supabase
    supabase = get_supabase()
    admin = get_current_user()
    assign_model = AssignmentModel(supabase)

    doctor_id = request.form.get("doctor_id", "")
    patient_id = request.form.get("patient_id", "")

    if not doctor_id or not patient_id:
        flash("Both doctor and patient must be selected.", "error")
        return redirect(url_for("admin_bp.assignments"))

    # Check if already assigned
    if assign_model.is_assigned(doctor_id, patient_id):
        flash("This patient is already assigned to this doctor.", "error")
        return redirect(url_for("admin_bp.assignments"))

    assign_model.assign(doctor_id, patient_id, admin["id"])
    log_audit_event(supabase, admin["id"], AuditAction.USER_CREATED,
                    f"Admin assigned patient {patient_id} to doctor {doctor_id}", "info")

    flash("Patient successfully assigned to doctor.", "success")
    return redirect(url_for("admin_bp.assignments"))


@admin_bp.route("/admin/assignments/<assignment_id>/unassign", methods=["POST"])
@role_required("admin")
def unassign_patient(assignment_id):
    """Remove a doctor-patient assignment."""
    from app import get_supabase
    supabase = get_supabase()
    admin = get_current_user()
    assign_model = AssignmentModel(supabase)

    assign_model.unassign(assignment_id)
    log_audit_event(supabase, admin["id"], AuditAction.USER_DELETED,
                    f"Admin removed assignment {assignment_id}", "info")

    flash("Assignment removed.", "info")
    return redirect(url_for("admin_bp.assignments"))


# ═══════════════════════════════════════════════════════════════════
#  API BLUEPRINT — Encryption Proof & AJAX endpoints
# ═══════════════════════════════════════════════════════════════════
api_bp = Blueprint("api_bp", __name__)


@api_bp.route("/encryption-proof", methods=["GET", "POST"])
@role_required("admin", "doctor")
def encryption_proof():
    """Encryption proof transparency page (admin and doctor only)."""
    proof = None
    if request.method == "POST":
        plaintext = request.form.get("plaintext",
                                     "Sample patient diagnosis: Type 2 Diabetes Mellitus")
        proof = get_encryption_proof(plaintext)

        from app import get_supabase
        user = get_current_user()
        log_audit_event(get_supabase(), user["id"], AuditAction.ENCRYPTION_PROOF,
                        "User ran encryption proof demo", "info")

    return render_template("encryption_proof.html",
                           user=get_current_user(), proof=proof)


@api_bp.route("/api/encrypt", methods=["POST"])
@login_required
def api_encrypt():
    """AJAX endpoint: encrypt a plaintext string and return proof data."""
    data = request.get_json()
    if not data or "plaintext" not in data:
        return jsonify({"error": "Missing plaintext"}), 400

    proof = get_encryption_proof(data["plaintext"])
    return jsonify(proof)
