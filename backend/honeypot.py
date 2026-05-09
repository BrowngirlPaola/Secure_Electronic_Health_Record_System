"""
Vitalis EHR — Honeypot / Canary Records
=========================================
Manages fake patient records that act as tripwires for insider threats.
If any user accesses a canary record, a critical alert fires silently —
because there is no legitimate clinical reason to view a fake patient's data.

This catches AUTHORIZED users behaving maliciously — something that
traditional RBAC cannot detect (the user technically has permission).

Standards Reference: MITRE ATT&CK T1530, NIST Cybersecurity Framework (Detect)

Usage:
    from honeypot import check_honeypot_access, create_canary_patient

    # On every record view:
    if check_honeypot_access(supabase, record_id, user_id):
        # Alert already fired — continue showing record (don't reveal it's fake)
        pass
"""

from datetime import datetime, timezone


# ─── Canary Patient Creation ─────────────────────────────────────────

# Realistic fake patient names (designed to blend in with real patients)
CANARY_PATIENTS = [
    {
        "email": "m.johnson.1987@patient.vitalis.ehr",
        "full_name": "Michael A. Johnson",
        "role": "patient",
    },
    {
        "email": "s.williams.1992@patient.vitalis.ehr",
        "full_name": "Sarah K. Williams",
        "role": "patient",
    },
]

# Realistic fake diagnoses for canary records
CANARY_DIAGNOSES = [
    "Suspected Type 2 Diabetes Mellitus with peripheral neuropathy. Fasting glucose 142 mg/dL. HbA1c pending.",
    "Mild persistent asthma with seasonal exacerbation. Peak flow 78% predicted. Maintenance inhaler compliance good.",
    "Routine post-operative follow-up: appendectomy (laparoscopic) 2 weeks ago. Incision healing well, no signs of infection.",
]

CANARY_TREATMENTS = [
    "Metformin 500mg BID, dietary counseling referral, follow-up in 3 months for HbA1c recheck.",
    "Continue fluticasone/salmeterol 250/50 BID. PRN albuterol. Review in 6 weeks.",
    "Continue current wound care protocol. Remove sutures at day 10. Resume normal activities gradually.",
]


def create_canary_patient(supabase_client, patient_data: dict) -> dict:
    """
    Create a realistic fake patient marked as a canary.
    The is_canary flag is invisible to normal user queries.

    Args:
        supabase_client: Supabase client
        patient_data: Dict with email, full_name, role

    Returns:
        Created user record
    """
    from auth import hash_password

    result = (
        supabase_client.table("users")
        .insert({
            "email": patient_data["email"],
            "password_hash": hash_password("CanaryDoNotLogin!2026"),
            "full_name": patient_data["full_name"],
            "role": "patient",
            "is_canary": True,
            "is_locked": True,  # Canary accounts can never log in
            "failed_attempts": 0,
        })
        .execute()
    )
    return result.data[0] if result.data else {}


def create_canary_records(supabase_client, canary_patient_id: str, created_by: str) -> list[dict]:
    """
    Create realistic encrypted health records for a canary patient.
    These records look completely normal in list views.

    Args:
        supabase_client: Supabase client
        canary_patient_id: UUID of the canary patient
        created_by: UUID of a doctor (for realistic created_by field)

    Returns:
        List of created record dicts
    """
    from encryption import encrypt_field

    records = []
    for i, (diag, treat) in enumerate(zip(CANARY_DIAGNOSES, CANARY_TREATMENTS)):
        result = (
            supabase_client.table("health_records")
            .insert({
                "patient_id": canary_patient_id,
                "created_by": created_by,
                "diagnosis": encrypt_field(diag),
                "treatment": encrypt_field(treat),
                "lab_results": encrypt_field("Pending lab work"),
                "notes": encrypt_field("Routine follow-up visit. No concerns."),
                "is_honeypot": True,
            })
            .execute()
        )
        if result.data:
            records.append(result.data[0])

    return records


# ─── Honeypot Access Detection ────��──────────────────────────────────

def check_honeypot_access(supabase_client, record_id: str, user_id: str) -> bool:
    """
    Check if a record is a honeypot. If yes, trigger a SILENT critical alert.

    IMPORTANT: The user is NOT informed that the record is fake.
    They see normal content. The alert fires in the background.

    Args:
        supabase_client: Supabase client
        record_id: UUID of the record being accessed
        user_id: UUID of the user accessing it

    Returns:
        True if the record IS a honeypot (alert was triggered)
        False if the record is legitimate
    """
    # Check if this record is marked as honeypot
    result = (
        supabase_client.table("health_records")
        .select("is_honeypot")
        .eq("id", record_id)
        .execute()
    )

    if not result.data or not result.data[0].get("is_honeypot"):
        return False

    # === HONEYPOT TRIGGERED ===
    _trigger_honeypot_alert(supabase_client, record_id, user_id)
    return True


def check_canary_patient_access(supabase_client, patient_id: str, user_id: str) -> bool:
    """
    Check if a patient is a canary. Used when filtering records by patient.

    Returns True if the patient IS a canary (alert triggered).
    """
    result = (
        supabase_client.table("users")
        .select("is_canary")
        .eq("id", patient_id)
        .execute()
    )

    if not result.data or not result.data[0].get("is_canary"):
        return False

    _trigger_honeypot_alert(supabase_client, None, user_id, patient_id=patient_id)
    return True


def _trigger_honeypot_alert(supabase_client, record_id: str | None,
                            user_id: str, patient_id: str | None = None) -> None:
    """
    Fire a silent critical alert when a honeypot is accessed.
    Logs to both audit_logs and suspicious_activities tables.
    """
    from flask import request

    ip = request.headers.get("X-Forwarded-For", request.remote_addr or "unknown")
    if "," in ip:
        ip = ip.split(",")[0].strip()

    details = f"HONEYPOT TRIGGERED: User accessed canary "
    if record_id:
        details += f"record {record_id}"
    elif patient_id:
        details += f"patient {patient_id}"

    # Log to suspicious_activities
    supabase_client.table("suspicious_activities").insert({
        "user_id": user_id,
        "activity_type": "honeypot_access",
        "description": details,
        "severity": "critical",
        "ip_address": ip,
        "created_at": datetime.now(timezone.utc).isoformat(),
    }).execute()

    # Also log to audit trail (will include hash chain via security.py)
    from security import log_audit_event, AuditAction
    log_audit_event(
        supabase_client,
        user_id=user_id,
        action=AuditAction.SUSPICIOUS_ACTIVITY,
        details=details,
        severity="critical",
    )


# ─── Admin Queries ───────────────────────────────────────────────────

def get_honeypot_alerts(supabase_client, limit: int = 50) -> list[dict]:
    """
    Fetch all honeypot trigger events for the admin dashboard.

    Returns list of alert dicts with user info joined.
    """
    result = (
        supabase_client.table("suspicious_activities")
        .select("*, users(email, full_name, role)")
        .eq("activity_type", "honeypot_access")
        .order("created_at", desc=True)
        .limit(limit)
        .execute()
    )
    return result.data or []


def get_canary_patients(supabase_client) -> list[dict]:
    """Get all canary patients (admin view for management)."""
    result = (
        supabase_client.table("users")
        .select("id, email, full_name, created_at")
        .eq("is_canary", True)
        .execute()
    )
    return result.data or []


def get_honeypot_records(supabase_client) -> list[dict]:
    """Get all honeypot records (admin view for management)."""
    result = (
        supabase_client.table("health_records")
        .select("id, patient_id, created_at")
        .eq("is_honeypot", True)
        .execute()
    )
    return result.data or []
