"""
Vitalis EHR — Utility Functions
================================
Password validation (NIST SP 800-63B), input sanitisation,
and shared helper functions.
"""

import re
from datetime import datetime, timezone


# ─── NIST SP 800-63B Password Policy ────────────────────────────────

PASSWORD_RULES = {
    "min_length": 8,
    "require_uppercase": True,
    "require_lowercase": True,
    "require_digit": True,
    "require_special": True,
}


def validate_password(password: str) -> dict:
    """
    Validate a password against NIST SP 800-63B requirements.

    Returns:
        {
            "valid": bool,
            "errors": list[str],
            "strength": "Weak" | "Fair" | "Good" | "Strong",
            "score": int (0-5),
        }
    """
    errors = []
    checks = {
        "length": len(password) >= PASSWORD_RULES["min_length"],
        "uppercase": bool(re.search(r"[A-Z]", password)),
        "lowercase": bool(re.search(r"[a-z]", password)),
        "digit": bool(re.search(r"[0-9]", password)),
        "special": bool(re.search(r"[!@#$%^&*()_+\-=\[\]{};':\"\\|,.<>/?]", password)),
    }

    if not checks["length"]:
        errors.append(f"Password must be at least {PASSWORD_RULES['min_length']} characters.")
    if PASSWORD_RULES["require_uppercase"] and not checks["uppercase"]:
        errors.append("Password must contain at least one uppercase letter.")
    if PASSWORD_RULES["require_lowercase"] and not checks["lowercase"]:
        errors.append("Password must contain at least one lowercase letter.")
    if PASSWORD_RULES["require_digit"] and not checks["digit"]:
        errors.append("Password must contain at least one digit.")
    if PASSWORD_RULES["require_special"] and not checks["special"]:
        errors.append("Password must contain at least one special character.")

    score = sum(checks.values())
    if score <= 2:
        strength = "Weak"
    elif score <= 3:
        strength = "Fair"
    elif score == 4:
        strength = "Good"
    else:
        strength = "Strong"

    return {
        "valid": len(errors) == 0,
        "errors": errors,
        "strength": strength,
        "score": score,
    }


# ─── Email Validation ───────────────────────────────────────────────

def validate_email(email: str) -> bool:
    """Basic email format validation."""
    pattern = r"^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$"
    return bool(re.match(pattern, email))


# ─── Input Sanitisation ─────────────────────────────────────────────

def sanitize_input(text: str) -> str:
    """Strip dangerous characters from user input (XSS prevention)."""
    if not text:
        return ""
    # Remove HTML tags
    text = re.sub(r"<[^>]*>", "", text)
    # Escape critical characters
    text = text.replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;")
    return text.strip()


# ─── Date/Time Helpers ──────────────────────────────────────────────

def utc_now() -> str:
    """Return current UTC time as ISO 8601 string."""
    return datetime.now(timezone.utc).isoformat()


def format_datetime(iso_str: str, fmt: str = "%Y-%m-%d %H:%M") -> str:
    """Format an ISO datetime string for display."""
    try:
        dt = datetime.fromisoformat(iso_str)
        return dt.strftime(fmt)
    except (ValueError, TypeError):
        return iso_str or ""


# ─── Role Display Helpers ───────────────────────────────────────────

ROLE_DISPLAY = {
    "admin": {"label": "Administrator", "icon": "admin_panel_settings", "css": "role-admin"},
    "doctor": {"label": "Doctor", "icon": "stethoscope", "css": "role-doctor"},
    "nurse": {"label": "Nurse", "icon": "medical_services", "css": "role-nurse"},
    "lab_tech": {"label": "Lab Technician", "icon": "biotech", "css": "role-lab-tech"},
    "patient": {"label": "Patient", "icon": "person", "css": "role-patient"},
}


def get_role_display(role: str) -> dict:
    """Get display metadata for a role."""
    return ROLE_DISPLAY.get(role, {"label": role.title(), "icon": "person", "css": ""})
