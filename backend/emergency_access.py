"""
Vitalis EHR — Break-the-Glass Emergency Access Protocol
========================================================
When a Doctor/Nurse is denied access to a patient record they urgently
need in an emergency, the system offers a "Break the Glass" override
instead of a flat 403. The user must provide written justification,
then receives time-bounded temporary access (30 min default).

Every BTG event is logged at CRITICAL severity and enters an admin
review queue. This demonstrates the fundamental tension between
SECURITY and AVAILABILITY in healthcare settings.

Standards Reference: HIPAA 45 CFR 164.312(a)(2)(ii) — Emergency Access Procedure

Usage:
    from emergency_access import initiate_btg, check_btg_active

    # When access is denied:
    if check_btg_active(supabase, user_id, record_id):
        # User has active BTG grant — allow access
        pass
    else:
        # Show BTG form
        pass

    # When BTG form submitted:
    event = initiate_btg(supabase, user_id, record_id, justification)
"""

from datetime import datetime, timezone, timedelta
from flask import request


# Default BTG window: 30 minutes
BTG_WINDOW_MINUTES = 30


# ─── BTG Grant Management ────────────────────────────────────────────

def initiate_btg(supabase_client, user_id: str, record_id: str,
                 justification: str) -> dict:
    """
    Grant temporary emergency access to a restricted record.

    This function:
    1. Creates a BTG event with expiration time
    2. Logs a CRITICAL audit event
    3. Creates a suspicious activity entry for the admin dashboard

    Args:
        supabase_client: Supabase client
        user_id: UUID of the user requesting emergency access
        record_id: UUID of the record they need to access
        justification: Written reason for the emergency access

    Returns:
        The created BTG event dict, or empty dict on failure
    """
    now = datetime.now(timezone.utc)
    expires_at = now + timedelta(minutes=BTG_WINDOW_MINUTES)

    ip = _get_client_ip()

    # Create the BTG event
    result = (
        supabase_client.table("btg_events")
        .insert({
            "user_id": user_id,
            "record_id": record_id,
            "justification": justification,
            "ip_address": ip,
            "granted_at": now.isoformat(),
            "expires_at": expires_at.isoformat(),
            "reviewed": False,
        })
        .execute()
    )

    event = result.data[0] if result.data else {}

    # Log critical audit event
    from security import log_audit_event
    log_audit_event(
        supabase_client,
        user_id=user_id,
        action="BTG_ACCESS_GRANTED",
        details=f"Break-the-Glass: {justification[:200]}. Record: {record_id}. Expires: {expires_at.isoformat()}",
        severity="critical",
    )

    # Also flag as suspicious activity for dashboard visibility
    supabase_client.table("suspicious_activities").insert({
        "user_id": user_id,
        "activity_type": "break_the_glass",
        "description": f"Emergency access to record {record_id}: {justification[:200]}",
        "severity": "critical",
        "ip_address": ip,
        "created_at": now.isoformat(),
    }).execute()

    return event


def check_btg_active(supabase_client, user_id: str, record_id: str) -> bool:
    """
    Check if a user has an active (non-expired) BTG grant for a specific record.

    Args:
        supabase_client: Supabase client
        user_id: UUID of the user
        record_id: UUID of the record

    Returns:
        True if there is an active BTG grant (access should be allowed)
        False if no active grant exists
    """
    now = datetime.now(timezone.utc).isoformat()

    result = (
        supabase_client.table("btg_events")
        .select("id, expires_at")
        .eq("user_id", user_id)
        .eq("record_id", record_id)
        .gte("expires_at", now)
        .limit(1)
        .execute()
    )

    return bool(result.data)


def get_btg_remaining_time(supabase_client, user_id: str, record_id: str) -> int | None:
    """
    Get remaining minutes on an active BTG grant.

    Returns:
        Number of minutes remaining, or None if no active grant
    """
    now = datetime.now(timezone.utc)

    result = (
        supabase_client.table("btg_events")
        .select("expires_at")
        .eq("user_id", user_id)
        .eq("record_id", record_id)
        .gte("expires_at", now.isoformat())
        .order("expires_at", desc=True)
        .limit(1)
        .execute()
    )

    if not result.data:
        return None

    expires = datetime.fromisoformat(result.data[0]["expires_at"])
    remaining = (expires - now).total_seconds() / 60
    return max(0, int(remaining))


# ─── Admin Review ────────────────────────────────────────────────────

def get_btg_events(supabase_client, limit: int = 50,
                   unreviewed_only: bool = False) -> list[dict]:
    """
    Fetch BTG events for admin review queue.

    Args:
        supabase_client: Supabase client
        limit: Maximum events to return
        unreviewed_only: If True, only return events not yet reviewed

    Returns:
        List of BTG event dicts with user info joined
    """
    query = (
        supabase_client.table("btg_events")
        .select("*, users!btg_events_user_id_fkey(email, full_name, role)")
        .order("granted_at", desc=True)
        .limit(limit)
    )

    if unreviewed_only:
        query = query.eq("reviewed", False)

    result = query.execute()
    return result.data or []


def mark_btg_reviewed(supabase_client, event_id: str, admin_id: str) -> bool:
    """
    Mark a BTG event as reviewed by admin.

    Args:
        supabase_client: Supabase client
        event_id: UUID of the BTG event
        admin_id: UUID of the admin marking it reviewed

    Returns:
        True if successfully updated
    """
    now = datetime.now(timezone.utc).isoformat()

    result = (
        supabase_client.table("btg_events")
        .update({
            "reviewed": True,
            "reviewed_by": admin_id,
            "reviewed_at": now,
        })
        .eq("id", event_id)
        .execute()
    )

    if result.data:
        from security import log_audit_event
        log_audit_event(
            supabase_client,
            user_id=admin_id,
            action="BTG_REVIEWED",
            details=f"Admin reviewed BTG event {event_id}",
            severity="info",
        )

    return bool(result.data)


def get_btg_stats(supabase_client) -> dict:
    """
    Get BTG statistics for the admin dashboard.

    Returns:
        {
            "total": int,
            "unreviewed": int,
            "active": int,  # currently valid (not expired)
            "last_event": str or None  # ISO timestamp of most recent BTG
        }
    """
    all_events = (
        supabase_client.table("btg_events")
        .select("id, reviewed, expires_at, granted_at")
        .order("granted_at", desc=True)
        .execute()
    )

    events = all_events.data or []
    now = datetime.now(timezone.utc)

    total = len(events)
    unreviewed = sum(1 for e in events if not e.get("reviewed"))
    active = sum(
        1 for e in events
        if datetime.fromisoformat(e["expires_at"]) > now
    )
    last_event = events[0]["granted_at"] if events else None

    return {
        "total": total,
        "unreviewed": unreviewed,
        "active": active,
        "last_event": last_event,
    }


# ─── Helpers ─────────────────────────────────────────────────────────

def _get_client_ip() -> str:
    """Get client IP address, respecting X-Forwarded-For."""
    if request.headers.get("X-Forwarded-For"):
        return request.headers["X-Forwarded-For"].split(",")[0].strip()
    return request.remote_addr or "unknown"
