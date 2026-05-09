"""
Vitalis EHR — Field-Level Access Control (FLAC)
================================================
Controls which fields within a health record are visible to each role.
Goes beyond record-level RBAC to implement per-column visibility —
the same concept as military classification (SECRET/TOP SECRET per paragraph).

Implements HIPAA's "Minimum Necessary" Rule (45 CFR 164.502(b)) at
maximum granularity.

Standards Reference: NIST SP 800-162 (Guide to ABAC), HIPAA 45 CFR 164.502(b)

Usage:
    from field_access import apply_field_access, get_access_summary

    # After decryption, before rendering:
    filtered_record = apply_field_access(decrypted_record, user_role)
"""

from config import Config


# ─── Access Level Definitions ────────────────────────────────────────

ACCESS_LEVELS = {
    "full": "Complete access — field shown in full",
    "masked": "Partially visible — first 3 and last 3 chars shown",
    "summary": "Truncated — first sentence only",
    "hidden": "Not visible — '[RESTRICTED]' placeholder shown",
}


# ─── Core FLAC Logic ─────────────────────────────────────────────────

def apply_field_access(record: dict, role: str) -> dict:
    """
    Apply field-level access control to a decrypted health record.

    Takes a record with plaintext fields and returns a copy where
    each field is filtered according to the role's access level
    in the FIELD_ACCESS_MATRIX.

    Args:
        record: Decrypted health record dict
        role: User's role string (e.g., "doctor", "nurse", "lab_tech")

    Returns:
        Filtered record dict with:
        - `_access_levels`: metadata showing access level per field
        - Fields transformed based on access level
    """
    matrix = Config.FIELD_ACCESS_MATRIX
    result = record.copy()

    access_metadata = {}

    for field, role_levels in matrix.items():
        level = role_levels.get(role, "hidden")
        access_metadata[field] = level

        if field not in result:
            continue

        value = result[field] or ""

        if level == "full":
            pass  # No transformation — show as-is
        elif level == "masked":
            result[field] = _mask_field(value)
        elif level == "summary":
            result[field] = _summarize_field(value)
        else:  # "hidden" or any unknown level
            result[field] = "[RESTRICTED — Insufficient clearance]"

    # Attach access level metadata for template rendering
    result["_access_levels"] = access_metadata
    return result


def get_access_summary(role: str) -> dict:
    """
    Get a summary of what a role can see for display purposes.

    Returns:
        {
            "role": "nurse",
            "fields": {
                "diagnosis": {"level": "masked", "description": "Partially visible..."},
                "treatment": {"level": "full", "description": "Complete access..."},
                ...
            }
        }
    """
    matrix = Config.FIELD_ACCESS_MATRIX
    fields = {}

    for field, role_levels in matrix.items():
        level = role_levels.get(role, "hidden")
        fields[field] = {
            "level": level,
            "description": ACCESS_LEVELS.get(level, "Unknown access level"),
        }

    return {"role": role, "fields": fields}


def can_view_field(role: str, field_name: str) -> bool:
    """Check if a role has any visibility (non-hidden) of a specific field."""
    matrix = Config.FIELD_ACCESS_MATRIX
    if field_name not in matrix:
        return True  # Non-controlled fields are visible by default
    level = matrix[field_name].get(role, "hidden")
    return level != "hidden"


def get_visible_fields(role: str) -> list[str]:
    """Get list of field names that are at least partially visible to a role."""
    matrix = Config.FIELD_ACCESS_MATRIX
    return [
        field for field, levels in matrix.items()
        if levels.get(role, "hidden") != "hidden"
    ]


# ─── Field Transformation Functions ─────────────────────────────────

def _mask_field(value: str) -> str:
    """
    Show first 3 and last 3 characters, mask the middle.
    Example: "Type 2 Diabetes Mellitus" → "Typ*******************tus"
    """
    if not value:
        return ""
    if len(value) <= 8:
        return value[:2] + "***" + value[-1:]
    return value[:3] + "*" * (len(value) - 6) + value[-3:]


def _summarize_field(value: str) -> str:
    """
    Truncate to the first sentence only.
    Example: "Patient has diabetes. Requires insulin." → "Patient has diabetes."
    """
    if not value:
        return ""
    # Find first sentence terminator
    for i, char in enumerate(value):
        if char in ".!?" and i > 0:
            return value[:i + 1]
    # No sentence terminator found — truncate at 80 chars
    if len(value) > 80:
        return value[:77] + "..."
    return value


# ─── Access Level Badge Helpers (for templates) ──────────────────────

LEVEL_BADGES = {
    "full": {"label": "FULL ACCESS", "icon": "lock_open", "css": "text-tertiary"},
    "masked": {"label": "MASKED", "icon": "visibility_off", "css": "text-amber-600"},
    "summary": {"label": "SUMMARY ONLY", "icon": "summarize", "css": "text-secondary"},
    "hidden": {"label": "RESTRICTED", "icon": "lock", "css": "text-error"},
}


def get_level_badge(level: str) -> dict:
    """Get display badge metadata for a field access level."""
    return LEVEL_BADGES.get(level, LEVEL_BADGES["hidden"])
