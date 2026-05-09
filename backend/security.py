"""
Vitalis EHR — Security & Audit Module
=======================================
Hash-chained audit logging, suspicious activity detection (SIEM-inspired),
and IP-based security tracking.

The audit trail uses a SHA-256 hash chain (Feature 1) — each entry's hash
includes the previous entry's hash, making tampering mathematically detectable.
"""

from datetime import datetime, timezone
from flask import request

from integrity import compute_chain_hash, get_previous_hash


# ─── Hash-Chained Audit Logging ─────────────────────────────────────

def log_audit_event(supabase_client, user_id: str | None, action: str,
                    details: str = "", severity: str = "info") -> None:
    """
    Write an immutable, hash-chained audit log entry.

    Each entry contains:
    - previous_hash: the chain_hash of the most recent preceding entry
    - chain_hash: SHA-256(previous_hash + canonical_entry_data)

    If any entry is later tampered with, all downstream hashes become invalid.

    Args:
        supabase_client: Supabase client instance
        user_id: UUID of the user performing the action (None for system events)
        action: Short action label (e.g., "LOGIN_SUCCESS", "RECORD_CREATED")
        details: Human-readable description
        severity: "info" | "warning" | "critical"
    """
    created_at = datetime.now(timezone.utc).isoformat()
    ip_address = _get_client_ip()

    entry_data = {
        "user_id": user_id or "",
        "action": action,
        "details": details,
        "severity": severity,
        "ip_address": ip_address,
        "created_at": created_at,
    }

    # Compute hash chain link
    previous_hash = get_previous_hash(supabase_client)
    chain_hash = compute_chain_hash(previous_hash, entry_data)

    supabase_client.table("audit_logs").insert({
        "user_id": user_id,
        "action": action,
        "details": details,
        "severity": severity,
        "ip_address": ip_address,
        "user_agent": request.headers.get("User-Agent", "")[:512],
        "chain_hash": chain_hash,
        "previous_hash": previous_hash,
        "created_at": created_at,
    }).execute()


# ─── Predefined Audit Actions ────────────────────────────────────────

class AuditAction:
    """Constants for audit log action types."""
    LOGIN_SUCCESS = "LOGIN_SUCCESS"
    LOGIN_FAILED = "LOGIN_FAILED"
    LOGOUT = "LOGOUT"
    ACCOUNT_LOCKED = "ACCOUNT_LOCKED"
    ACCOUNT_UNLOCKED = "ACCOUNT_UNLOCKED"
    USER_CREATED = "USER_CREATED"
    USER_DELETED = "USER_DELETED"
    RECORD_CREATED = "RECORD_CREATED"
    RECORD_VIEWED = "RECORD_VIEWED"
    RECORD_DECRYPTED = "RECORD_DECRYPTED"
    RECORD_DELETED = "RECORD_DELETED"
    ENCRYPTION_PROOF = "ENCRYPTION_PROOF"
    UNAUTHORIZED_ACCESS = "UNAUTHORIZED_ACCESS"
    SUSPICIOUS_ACTIVITY = "SUSPICIOUS_ACTIVITY"
    # Innovative features
    HONEYPOT_TRIGGERED = "HONEYPOT_TRIGGERED"
    BTG_ACCESS_GRANTED = "BTG_ACCESS_GRANTED"
    BTG_REVIEWED = "BTG_REVIEWED"
    SIGNATURE_VERIFIED = "SIGNATURE_VERIFIED"
    LAB_RESULTS_SIGNED = "LAB_RESULTS_SIGNED"
    SESSION_HIJACK_DETECTED = "SESSION_HIJACK_DETECTED"
    INTEGRITY_CHECK = "INTEGRITY_CHECK"


# ─── Suspicious Activity Detection ──────────────────────────────────

# Thresholds for SIEM-inspired anomaly detection
SUSPICIOUS_THRESHOLDS = {
    "rapid_login_attempts": 5,        # attempts in 5 minutes
    "off_hours_access": (22, 6),      # 10 PM – 6 AM
    "multiple_ip_logins": 3,          # unique IPs in 1 hour
    "bulk_record_access": 20,         # records viewed in 10 minutes
}


def detect_suspicious_activity(supabase_client, user_id: str) -> list[dict]:
    """
    Run anomaly detection checks against recent audit logs.
    Returns a list of flagged activities with severity.
    """
    flags = []

    # 1. Rapid login failures
    flags.extend(_check_rapid_login_failures(supabase_client, user_id))

    # 2. Off-hours access
    flags.extend(_check_off_hours_access())

    # 3. Bulk record access
    flags.extend(_check_bulk_record_access(supabase_client, user_id))

    # Log any flagged activities
    for flag in flags:
        log_audit_event(
            supabase_client,
            user_id=user_id,
            action=AuditAction.SUSPICIOUS_ACTIVITY,
            details=flag["description"],
            severity=flag["severity"],
        )
        # Also insert into suspicious_activities table for the dashboard
        supabase_client.table("suspicious_activities").insert({
            "user_id": user_id,
            "activity_type": flag["type"],
            "description": flag["description"],
            "severity": flag["severity"],
            "ip_address": _get_client_ip(),
            "created_at": datetime.now(timezone.utc).isoformat(),
        }).execute()

    return flags


def _check_rapid_login_failures(supabase_client, user_id: str) -> list[dict]:
    """Detect rapid consecutive login failures (brute force indicator)."""
    flags = []
    try:
        result = (
            supabase_client.table("audit_logs")
            .select("id")
            .eq("user_id", user_id)
            .eq("action", AuditAction.LOGIN_FAILED)
            .gte("created_at", _minutes_ago(5))
            .execute()
        )
        count = len(result.data) if result.data else 0
        if count >= SUSPICIOUS_THRESHOLDS["rapid_login_attempts"]:
            flags.append({
                "type": "rapid_login_failures",
                "description": f"{count} failed login attempts in the last 5 minutes",
                "severity": "critical",
            })
    except Exception:
        pass  # fail open — don't block auth on detection errors
    return flags


def _check_off_hours_access() -> list[dict]:
    """Flag logins outside normal business hours."""
    flags = []
    hour = datetime.now(timezone.utc).hour
    start, end = SUSPICIOUS_THRESHOLDS["off_hours_access"]
    if hour >= start or hour < end:
        flags.append({
            "type": "off_hours_access",
            "description": f"Access attempt at {hour:02d}:00 UTC (outside business hours)",
            "severity": "warning",
        })
    return flags


def _check_bulk_record_access(supabase_client, user_id: str) -> list[dict]:
    """Detect bulk patient record viewing (data exfiltration indicator)."""
    flags = []
    try:
        result = (
            supabase_client.table("audit_logs")
            .select("id")
            .eq("user_id", user_id)
            .eq("action", AuditAction.RECORD_VIEWED)
            .gte("created_at", _minutes_ago(10))
            .execute()
        )
        count = len(result.data) if result.data else 0
        if count >= SUSPICIOUS_THRESHOLDS["bulk_record_access"]:
            flags.append({
                "type": "bulk_record_access",
                "description": f"{count} records viewed in the last 10 minutes",
                "severity": "critical",
            })
    except Exception:
        pass
    return flags


def get_suspicious_activities(supabase_client, limit: int = 50) -> list[dict]:
    """Fetch recent suspicious activities for the dashboard."""
    result = (
        supabase_client.table("suspicious_activities")
        .select("*, users(email, full_name, role)")
        .order("created_at", desc=True)
        .limit(limit)
        .execute()
    )
    return result.data or []


def get_audit_logs(supabase_client, limit: int = 100) -> list[dict]:
    """Fetch recent audit log entries."""
    result = (
        supabase_client.table("audit_logs")
        .select("*, users(email, full_name, role)")
        .order("created_at", desc=True)
        .limit(limit)
        .execute()
    )
    return result.data or []


# ─── Helpers ─────────────────────────────────────────────────────────

def _get_client_ip() -> str:
    """Get client IP address, respecting X-Forwarded-For header."""
    if request.headers.get("X-Forwarded-For"):
        return request.headers["X-Forwarded-For"].split(",")[0].strip()
    return request.remote_addr or "unknown"


def _minutes_ago(minutes: int) -> str:
    """Return an ISO timestamp for N minutes ago."""
    from datetime import timedelta
    return (datetime.now(timezone.utc) - timedelta(minutes=minutes)).isoformat()
