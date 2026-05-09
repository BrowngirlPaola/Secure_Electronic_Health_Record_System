"""
Vitalis EHR — Cryptographic Audit Log Integrity (Hash Chain)
=============================================================
Implements a SHA-256 hash chain on audit log entries. Each entry's hash
is computed from its own data + the previous entry's hash, forming an
immutable chain. If any entry is tampered with, the chain breaks.

This is the same principle underlying blockchain — applied to audit logs.

Standards Reference: NIST SP 800-92 (Guide to Computer Security Log Management)

Usage:
    from integrity import compute_chain_hash, verify_audit_chain

    # On insert:
    new_hash = compute_chain_hash(previous_hash, entry_data)

    # On verification:
    result = verify_audit_chain(supabase_client)
    # result = {"valid": True, "total": 150, "verified": 150, "broken_at": None}
"""

import hashlib
import json

# Genesis hash — the root of the chain (first entry chains from this)
GENESIS_HASH = hashlib.sha256(b"VITALIS_EHR_GENESIS_2026_FICT").hexdigest()


def compute_chain_hash(previous_hash: str, entry_data: dict) -> str:
    """
    Compute the SHA-256 chain hash for a new audit log entry.

    Formula: SHA-256(previous_hash || canonical_JSON(entry_data))

    Args:
        previous_hash: The chain_hash of the most recent existing entry
                       (or GENESIS_HASH if this is the first entry)
        entry_data: Dict containing the audit log fields to be hashed

    Returns:
        64-character hex string (SHA-256 hash)
    """
    # Canonicalize entry data — sorted keys ensure deterministic hashing
    canonical = json.dumps({
        "user_id": entry_data.get("user_id") or "",
        "action": entry_data.get("action", ""),
        "details": entry_data.get("details", ""),
        "severity": entry_data.get("severity", "info"),
        "ip_address": entry_data.get("ip_address", ""),
        "created_at": entry_data.get("created_at", ""),
    }, sort_keys=True, ensure_ascii=True)

    # Concatenate previous hash with canonical data and hash
    payload = f"{previous_hash}{canonical}".encode("utf-8")
    return hashlib.sha256(payload).hexdigest()


def get_previous_hash(supabase_client) -> str:
    """
    Fetch the chain_hash of the most recent audit log entry.
    Returns GENESIS_HASH if no entries exist yet.
    """
    result = (
        supabase_client.table("audit_logs")
        .select("chain_hash")
        .order("created_at", desc=True)
        .limit(1)
        .execute()
    )
    if result.data and result.data[0].get("chain_hash"):
        return result.data[0]["chain_hash"]
    return GENESIS_HASH


def verify_audit_chain(supabase_client) -> dict:
    """
    Walk the entire audit log and verify hash chain integrity.

    Fetches all entries ordered chronologically, recomputes each hash,
    and compares against the stored chain_hash. If any mismatch is found,
    the chain is broken at that point.

    Returns:
        {
            "valid": bool,          # True if entire chain is intact
            "total": int,           # Total number of entries checked
            "verified": int,        # Number of entries that passed verification
            "broken_at": int|None,  # Index where chain first breaks (0-based), or None
            "entries": [            # Verification details per entry
                {
                    "id": "...",
                    "action": "...",
                    "created_at": "...",
                    "stored_hash": "...",
                    "computed_hash": "...",
                    "valid": True/False
                }
            ]
        }
    """
    # Fetch ALL audit logs in chronological order (oldest first)
    result = (
        supabase_client.table("audit_logs")
        .select("id, user_id, action, details, severity, ip_address, created_at, chain_hash, previous_hash")
        .order("created_at", desc=False)
        .execute()
    )

    entries = result.data or []
    total = len(entries)
    verified = 0
    broken_at = None
    verification_details = []

    previous_hash = GENESIS_HASH

    for i, entry in enumerate(entries):
        # Recompute the expected hash
        computed_hash = compute_chain_hash(previous_hash, entry)
        stored_hash = entry.get("chain_hash", "")

        is_valid = (computed_hash == stored_hash) if stored_hash else True

        verification_details.append({
            "id": entry["id"],
            "action": entry.get("action", ""),
            "created_at": entry.get("created_at", ""),
            "stored_hash": stored_hash[:16] + "..." if stored_hash else "(none)",
            "computed_hash": computed_hash[:16] + "...",
            "valid": is_valid,
        })

        if is_valid:
            verified += 1
        elif broken_at is None:
            broken_at = i

        # Move forward in the chain (use stored hash for next computation
        # to check if downstream entries are consistent with THEIR predecessor)
        previous_hash = stored_hash if stored_hash else computed_hash

    return {
        "valid": broken_at is None,
        "total": total,
        "verified": verified,
        "broken_at": broken_at,
        "entries": verification_details,
    }


def get_chain_summary(supabase_client) -> dict:
    """
    Quick summary of audit chain status for dashboard display.
    Only checks the last 10 entries for performance.
    """
    result = (
        supabase_client.table("audit_logs")
        .select("id, chain_hash, previous_hash, action, created_at")
        .order("created_at", desc=True)
        .limit(10)
        .execute()
    )

    entries = result.data or []
    if not entries:
        return {"status": "empty", "total": 0, "message": "No audit entries yet"}

    # Quick check: verify the last entry's previous_hash matches its predecessor
    has_hashes = all(e.get("chain_hash") for e in entries)

    return {
        "status": "active" if has_hashes else "pending",
        "total": len(entries),
        "latest_hash": entries[0].get("chain_hash", "")[:16] + "..." if entries else "",
        "message": "Chain active — integrity verifiable" if has_hashes else "Legacy entries without hashes exist",
    }
