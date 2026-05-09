"""
Vitalis EHR — Application Configuration
Loads environment variables and provides typed config for Flask + Supabase.
"""

import os
from dotenv import load_dotenv

load_dotenv()


class Config:
    """Base configuration — shared across all environments."""

    # Flask
    SECRET_KEY = os.getenv("FLASK_SECRET_KEY", os.urandom(32).hex())
    DEBUG = False
    TESTING = False

    # Supabase
    SUPABASE_URL = os.getenv("SUPABASE_URL", "")
    SUPABASE_ANON_KEY = os.getenv("SUPABASE_ANON_KEY", "")
    SUPABASE_SERVICE_ROLE_KEY = os.getenv("SUPABASE_SERVICE_ROLE_KEY", "")

    # AES-256-CBC encryption key (64 hex chars = 32 bytes)
    AES_ENCRYPTION_KEY = os.getenv("AES_ENCRYPTION_KEY", "")

    # Security — brute force lockout
    MAX_LOGIN_ATTEMPTS = 3
    LOCKOUT_MESSAGE = "Account locked after 3 failed attempts. Contact administrator."

    # Session
    SESSION_COOKIE_HTTPONLY = True
    SESSION_COOKIE_SAMESITE = "Lax"
    PERMANENT_SESSION_LIFETIME = 1800  # 30 minutes

    # RBAC — 5 roles with compartmentalized permissions
    ROLES = ("admin", "doctor", "nurse", "lab_tech", "patient")

    ROLE_PERMISSIONS = {
        "admin": [
            "view_dashboard", "manage_users", "view_users", "create_user",
            "delete_user", "unlock_user", "view_audit_logs", "view_suspicious",
            "view_encryption_proof", "view_records", "create_record",
            "delete_record", "view_integrity", "review_btg", "view_honeypot_alerts",
        ],
        "doctor": [
            "view_dashboard", "view_records", "create_record", "edit_record",
            "view_all_patients", "view_encryption_proof", "verify_signature",
            "break_the_glass",
        ],
        "nurse": [
            "view_dashboard", "view_records", "create_record",
            "view_created_records", "view_encryption_proof",
            "break_the_glass",
        ],
        "lab_tech": [
            "view_dashboard", "view_lab_queue", "submit_lab_results",
            "sign_lab_results",
        ],
        "patient": [
            "view_dashboard", "view_own_records",
        ],
    }

    # ─── Field-Level Access Control (FLAC) Matrix ─────────────────────
    # Controls which record fields are visible to each role.
    # Levels: "full" | "masked" | "summary" | "hidden"
    FIELD_ACCESS_MATRIX = {
        "diagnosis": {
            "admin": "full",
            "doctor": "full",
            "nurse": "masked",
            "lab_tech": "hidden",
            "patient": "full",
        },
        "treatment": {
            "admin": "full",
            "doctor": "full",
            "nurse": "full",
            "lab_tech": "hidden",
            "patient": "full",
        },
        "lab_results": {
            "admin": "full",
            "doctor": "full",
            "nurse": "full",
            "lab_tech": "full",
            "patient": "summary",
        },
        "notes": {
            "admin": "full",
            "doctor": "full",
            "nurse": "hidden",
            "lab_tech": "hidden",
            "patient": "hidden",
        },
    }

    # ─── Break-the-Glass Configuration ────────────────────────────────
    BTG_WINDOW_MINUTES = 30
    BTG_ALLOWED_ROLES = ("doctor", "nurse")


class DevelopmentConfig(Config):
    DEBUG = True


class ProductionConfig(Config):
    SESSION_COOKIE_SECURE = True
    SESSION_COOKIE_SAMESITE = "Strict"


class TestingConfig(Config):
    TESTING = True


config_by_name = {
    "development": DevelopmentConfig,
    "production": ProductionConfig,
    "testing": TestingConfig,
}


def get_config():
    """Return the config class matching FLASK_ENV."""
    env = os.getenv("FLASK_ENV", "development")
    return config_by_name.get(env, DevelopmentConfig)
