"""
Vitalis EHR — Flask Application Entry Point
=============================================
Secure Electronic Health Record Transfer System
ICT University (FICT) — Final Year Project

Author:  Yong Paola Nabain
Supervisor: Dr. Fosso
Stack:  Flask + Supabase + AES-256-CBC

Run:
    python app.py              (development)
    gunicorn app:app           (production)
"""

import os
import sys

from flask import Flask, redirect, url_for, render_template
from flask_cors import CORS
from supabase import create_client, Client
from dotenv import load_dotenv

# Ensure backend modules are importable
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from config import get_config
from routes import auth_bp, dashboard_bp, records_bp, admin_bp, api_bp, lab_bp
from auth import get_current_user

load_dotenv()

# ─── Supabase Client (singleton) ────────────────────────────────────

_supabase: Client | None = None


def get_supabase() -> Client:
    """Return the Supabase client singleton."""
    global _supabase
    if _supabase is None:
        url = os.getenv("SUPABASE_URL", "")
        key = os.getenv("SUPABASE_SERVICE_ROLE_KEY", "") or os.getenv("SUPABASE_ANON_KEY", "")
        if not url or not key:
            raise RuntimeError(
                "SUPABASE_URL and SUPABASE_SERVICE_ROLE_KEY (or SUPABASE_ANON_KEY) "
                "must be set in .env"
            )
        _supabase = create_client(url, key)
    return _supabase


# ─── App Factory ─────────────────────────────────────────────────────

def create_app() -> Flask:
    """Create and configure the Flask application."""
    config = get_config()

    app = Flask(
        __name__,
        template_folder=os.path.join(os.path.dirname(__file__), "..", "frontend", "templates"),
        static_folder=os.path.join(os.path.dirname(__file__), "..", "frontend", "static"),
    )
    app.config.from_object(config)

    # CORS (for development — frontend served separately)
    CORS(app, supports_credentials=True)

    # ── Register Blueprints ──
    app.register_blueprint(auth_bp)
    app.register_blueprint(dashboard_bp)
    app.register_blueprint(records_bp)
    app.register_blueprint(admin_bp)
    app.register_blueprint(lab_bp)
    app.register_blueprint(api_bp)

    # ── Session Fingerprinting Middleware (Feature 3) ──
    @app.before_request
    def check_session_fingerprint():
        """
        Verify session fingerprint on every authenticated request.
        If mismatch detected → session hijacking → kill session immediately.
        """
        from session_security import verify_fingerprint
        from auth import is_authenticated, logout_user

        if not is_authenticated():
            return  # Skip for unauthenticated requests

        valid, reason = verify_fingerprint()
        if not valid:
            # Session hijacking detected!
            user = get_current_user()
            user_id = user["id"] if user else None

            # Log critical alert before killing session
            try:
                from security import log_audit_event, AuditAction
                log_audit_event(
                    get_supabase(), user_id,
                    AuditAction.SESSION_HIJACK_DETECTED,
                    f"Session terminated: {reason}",
                    "critical",
                )
            except Exception:
                pass  # Don't let logging failure prevent session kill

            logout_user()
            from flask import flash
            flash("Session terminated — security anomaly detected. Please log in again.", "error")
            return redirect(url_for("auth_bp.login"))

    # ── Context Processors ──
    @app.context_processor
    def inject_globals():
        """Make current_user and utility functions available in all templates."""
        from utils import get_role_display, format_datetime
        from field_access import get_level_badge
        return {
            "current_user": get_current_user(),
            "get_role_display": get_role_display,
            "format_datetime": format_datetime,
            "get_level_badge": get_level_badge,
        }

    # ── Root Route ──
    @app.route("/")
    def index():
        """Landing page or redirect to dashboard if logged in."""
        user = get_current_user()
        if user:
            dashboard_map = {
                "admin": "dashboard_bp.admin_dashboard",
                "doctor": "dashboard_bp.doctor_dashboard",
                "nurse": "dashboard_bp.nurse_dashboard",
                "lab_tech": "dashboard_bp.lab_dashboard",
                "patient": "dashboard_bp.patient_dashboard",
            }
            return redirect(url_for(dashboard_map.get(user["role"], "auth_bp.login")))
        return render_template("index.html")

    # ── Error Handlers ──
    @app.errorhandler(403)
    def forbidden(e):
        return render_template("error.html", code=403,
                               message="Access Denied — Insufficient privileges."), 403

    @app.errorhandler(404)
    def not_found(e):
        return render_template("error.html", code=404,
                               message="Page not found."), 404

    @app.errorhandler(500)
    def server_error(e):
        return render_template("error.html", code=500,
                               message="Internal server error."), 500

    return app


# ─── Run ─────────────────────────────────────────────────────────────

app = create_app()

if __name__ == "__main__":
    port = int(os.getenv("PORT", 5000))
    app.run(host="0.0.0.0", port=port, debug=app.config.get("DEBUG", False))
