"""
Vitalis EHR — Session Fingerprinting & Hijacking Detection
============================================================
Creates a composite fingerprint from browser characteristics on login.
On every subsequent request, the fingerprint is recomputed and compared.
If it changes (session cookie used from different browser/device),
the session is immediately killed and a critical alert is logged.

This defeats session hijacking via cookie theft (XSS, MITM, physical access).

Standards Reference: OWASP Session Management Cheat Sheet, NIST SP 800-63B Section 7

Usage:
    # On login:
    from session_security import store_fingerprint

    store_fingerprint()

    # In app.before_request:
    from session_security import verify_fingerprint

    valid, reason = verify_fingerprint()
    if not valid:
        # Kill session, log alert
"""

import hashlib
from flask import request, session


def generate_fingerprint() -> str:
    """
    Create a SHA-256 fingerprint from browser/network characteristics.

    Components hashed:
    1. User-Agent — browser type and version
    2. Accept-Language — language preferences
    3. IP Subnet (/24) — network location (not exact IP, to handle NAT)

    The /24 subnet is used instead of exact IP because:
    - Mobile users may change IP within their carrier's subnet
    - Corporate NAT pools share a subnet
    - But a completely different subnet = different network = suspicious

    Returns:
        64-character hex string (SHA-256 hash)
    """
    components = [
        request.headers.get("User-Agent", "unknown"),
        request.headers.get("Accept-Language", "unknown"),
        _get_ip_subnet(),
    ]
    raw = "|".join(components).encode("utf-8")
    return hashlib.sha256(raw).hexdigest()


def store_fingerprint() -> str:
    """
    Compute and store the session fingerprint after successful login.
    Returns the fingerprint hash for logging purposes.
    """
    fingerprint = generate_fingerprint()
    session["_fingerprint"] = fingerprint
    session["_fingerprint_components"] = {
        "user_agent": request.headers.get("User-Agent", "")[:100],
        "accept_language": request.headers.get("Accept-Language", "")[:50],
        "ip_subnet": _get_ip_subnet(),
    }
    return fingerprint


def verify_fingerprint() -> tuple[bool, str]:
    """
    Verify that the current request's fingerprint matches the stored one.

    Returns:
        (is_valid: bool, reason: str)
        - (True, "") if fingerprints match or no fingerprint stored
        - (False, "explanation") if mismatch detected
    """
    stored = session.get("_fingerprint")
    if not stored:
        # No fingerprint stored — pre-existing session or unauthenticated
        return True, ""

    current = generate_fingerprint()
    if current != stored:
        # Fingerprint mismatch — possible session hijacking!
        stored_components = session.get("_fingerprint_components", {})
        reason = _build_mismatch_reason(stored_components)
        return False, reason

    return True, ""


def get_fingerprint_info() -> dict:
    """
    Get the current session's fingerprint info for display/debugging.
    Returns empty dict if no fingerprint stored.
    """
    stored = session.get("_fingerprint")
    if not stored:
        return {}

    return {
        "fingerprint_hash": stored[:16] + "...",
        "components": session.get("_fingerprint_components", {}),
        "current_match": generate_fingerprint() == stored,
    }


# ─── Helper Functions ────────────────────────────────────────────────

def _get_ip_subnet() -> str:
    """
    Extract the /24 subnet from the client IP.
    Example: "192.168.1.105" → "192.168.1.0/24"

    Uses /24 (first 3 octets) to allow for NAT variation while
    still detecting network changes.
    """
    ip = _get_client_ip()
    parts = ip.split(".")
    if len(parts) == 4:
        return f"{parts[0]}.{parts[1]}.{parts[2]}.0/24"
    # IPv6 or unexpected format — use full IP
    return ip


def _get_client_ip() -> str:
    """Get client IP, respecting X-Forwarded-For for proxied requests."""
    if request.headers.get("X-Forwarded-For"):
        return request.headers["X-Forwarded-For"].split(",")[0].strip()
    return request.remote_addr or "0.0.0.0"


def _build_mismatch_reason(stored_components: dict) -> str:
    """Build a human-readable reason for why the fingerprint mismatched."""
    current_ua = request.headers.get("User-Agent", "")[:100]
    current_lang = request.headers.get("Accept-Language", "")[:50]
    current_subnet = _get_ip_subnet()

    mismatches = []
    if stored_components.get("user_agent") != current_ua:
        mismatches.append("User-Agent changed")
    if stored_components.get("accept_language") != current_lang:
        mismatches.append("Accept-Language changed")
    if stored_components.get("ip_subnet") != current_subnet:
        mismatches.append(f"IP subnet changed ({stored_components.get('ip_subnet')} → {current_subnet})")

    if mismatches:
        return f"Session fingerprint mismatch: {', '.join(mismatches)}"
    return "Session fingerprint hash mismatch (computed hash differs)"
