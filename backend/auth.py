"""
Vitalis EHR — Authentication & RBAC Module
============================================
Handles Supabase authentication, session management,
role-based access control, and brute-force lockout logic.
"""

import functools
from datetime import datetime, timezone

import bcrypt
from flask import session, redirect, url_for, request, flash, abort

from config import Config


# ─── Password Hashing (bcrypt) ───────────────────────────────────────

def hash_password(plain: str) -> str:
    """Hash a plaintext password with bcrypt (12 rounds)."""
    return bcrypt.hashpw(plain.encode("utf-8"), bcrypt.gensalt(12)).decode("utf-8")


def verify_password(plain: str, hashed: str) -> bool:
    """Verify a plaintext password against a bcrypt hash."""
    return bcrypt.checkpw(plain.encode("utf-8"), hashed.encode("utf-8"))


# ─── Session Helpers ─────────────────────────────────────────────────

def login_user(user: dict) -> None:
    """Store user data in Flask session after successful authentication."""
    session["user"] = {
        "id": user["id"],
        "email": user["email"],
        "full_name": user.get("full_name", ""),
        "role": user["role"],
        "logged_in_at": datetime.now(timezone.utc).isoformat(),
    }
    session.permanent = True


def logout_user() -> None:
    """Clear the Flask session."""
    session.clear()


def get_current_user() -> dict | None:
    """Return the current user dict from session, or None."""
    return session.get("user")


def is_authenticated() -> bool:
    """Check if a user is currently logged in."""
    return "user" in session


# ─── RBAC Decorators ─────────────────────────────────────────────────

def login_required(f):
    """Decorator: redirect to login if not authenticated."""
    @functools.wraps(f)
    def decorated(*args, **kwargs):
        if not is_authenticated():
            flash("Please log in to access this page.", "warning")
            return redirect(url_for("auth_bp.login"))
        return f(*args, **kwargs)
    return decorated


def role_required(*allowed_roles):
    """
    Decorator: restrict access to specific roles.

    Usage:
        @role_required("admin")
        @role_required("admin", "doctor")
    """
    def decorator(f):
        @functools.wraps(f)
        def decorated(*args, **kwargs):
            user = get_current_user()
            if not user:
                flash("Please log in to access this page.", "warning")
                return redirect(url_for("auth_bp.login"))
            if user["role"] not in allowed_roles:
                abort(403)
            return f(*args, **kwargs)
        return decorated
    return decorator


def has_permission(permission: str) -> bool:
    """Check if the current user has a specific permission."""
    user = get_current_user()
    if not user:
        return False
    role = user.get("role", "")
    return permission in Config.ROLE_PERMISSIONS.get(role, [])


# ─── Brute Force Lockout ─────────────────────────────────────────────

def check_account_locked(supabase_client, email: str) -> bool:
    """
    Check if an account is locked due to failed login attempts.
    Returns True if locked.
    """
    result = (
        supabase_client.table("users")
        .select("failed_attempts, is_locked")
        .eq("email", email)
        .execute()
    )
    if not result.data:
        return False
    return result.data[0].get("is_locked", False)


def record_failed_attempt(supabase_client, email: str) -> bool:
    """
    Increment failed login attempts. Lock account if >= MAX_LOGIN_ATTEMPTS.
    Returns True if the account is now locked.
    """
    result = (
        supabase_client.table("users")
        .select("id, failed_attempts")
        .eq("email", email)
        .execute()
    )
    if not result.data:
        return False

    user_id = result.data[0]["id"]
    attempts = (result.data[0].get("failed_attempts") or 0) + 1
    is_locked = attempts >= Config.MAX_LOGIN_ATTEMPTS

    supabase_client.table("users").update({
        "failed_attempts": attempts,
        "is_locked": is_locked,
        "locked_at": datetime.now(timezone.utc).isoformat() if is_locked else None,
    }).eq("id", user_id).execute()

    return is_locked


def reset_failed_attempts(supabase_client, email: str) -> None:
    """Reset the failed attempts counter after a successful login."""
    supabase_client.table("users").update({
        "failed_attempts": 0,
        "is_locked": False,
        "locked_at": None,
    }).eq("email", email).execute()


def unlock_account(supabase_client, user_id: str) -> None:
    """Admin action: unlock a locked account."""
    supabase_client.table("users").update({
        "failed_attempts": 0,
        "is_locked": False,
        "locked_at": None,
    }).eq("id", user_id).execute()
