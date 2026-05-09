"""
Vitalis EHR — Data Models (Supabase Interface)
===============================================
Provides CRUD operations for each table via the Supabase client.
No ORM — direct Supabase Python SDK calls with typed helpers.

Tables (defined in Supabase dashboard):
  - users
  - health_records
  - audit_logs
  - suspicious_activities
"""

from datetime import datetime, timezone

from auth import hash_password
from encryption import encrypt_field, decrypt_field
from utils import utc_now


# ═══════════════════════════════════════════════════════════════════
#  USERS
# ═══════════════════════════════════════════════════════════════════

class UserModel:
    """CRUD operations for the users table."""

    def __init__(self, supabase):
        self.db = supabase

    def get_all(self) -> list[dict]:
        """Fetch all users (admin view)."""
        result = (
            self.db.table("users")
            .select("id, email, full_name, role, is_locked, failed_attempts, created_at")
            .order("created_at", desc=True)
            .execute()
        )
        return result.data or []

    def get_by_id(self, user_id: str) -> dict | None:
        """Fetch a single user by UUID."""
        result = (
            self.db.table("users")
            .select("*")
            .eq("id", user_id)
            .execute()
        )
        return result.data[0] if result.data else None

    def get_by_email(self, email: str) -> dict | None:
        """Fetch a single user by email address."""
        result = (
            self.db.table("users")
            .select("*")
            .eq("email", email)
            .execute()
        )
        return result.data[0] if result.data else None

    def create(self, email: str, password: str, full_name: str, role: str) -> dict:
        """Create a new user with hashed password and RSA key pair."""
        from signatures import generate_keypair, encrypt_private_key

        # Generate RSA-2048 key pair for digital signatures
        private_pem, public_pem = generate_keypair()
        encrypted_private = encrypt_private_key(private_pem)

        result = (
            self.db.table("users")
            .insert({
                "email": email,
                "password_hash": hash_password(password),
                "full_name": full_name,
                "role": role,
                "is_locked": False,
                "failed_attempts": 0,
                "public_key": public_pem,
                "private_key_enc": encrypted_private,
                "is_canary": False,
                "created_at": utc_now(),
            })
            .execute()
        )
        return result.data[0] if result.data else {}

    def delete(self, user_id: str) -> bool:
        """Delete a user by UUID."""
        result = (
            self.db.table("users")
            .delete()
            .eq("id", user_id)
            .execute()
        )
        return bool(result.data)

    def count_by_role(self) -> dict:
        """Count users grouped by role (5 roles)."""
        users = self.get_all()
        counts = {"admin": 0, "doctor": 0, "nurse": 0, "lab_tech": 0, "patient": 0}
        for u in users:
            role = u.get("role", "")
            if role in counts:
                counts[role] += 1
        return counts

    def get_locked_accounts(self) -> list[dict]:
        """Fetch all locked user accounts."""
        result = (
            self.db.table("users")
            .select("id, email, full_name, role, locked_at, failed_attempts")
            .eq("is_locked", True)
            .execute()
        )
        return result.data or []


# ═══════════════════════════════════════════════════════════════════
#  HEALTH RECORDS
# ═══════════════════════════════════════════════════════════════════

class RecordModel:
    """CRUD operations for the health_records table."""

    # Fields that are AES-256 encrypted in storage
    ENCRYPTED_FIELDS = ("diagnosis", "treatment", "lab_results", "notes")

    def __init__(self, supabase):
        self.db = supabase

    def get_all(self) -> list[dict]:
        """Fetch all records (admin/doctor view) — encrypted fields stay encrypted."""
        result = (
            self.db.table("health_records")
            .select("*, users!health_records_patient_id_fkey(email, full_name)")
            .order("created_at", desc=True)
            .execute()
        )
        return result.data or []

    def get_by_id(self, record_id: str, decrypt: bool = False,
                  role: str | None = None) -> dict | None:
        """
        Fetch a single record. Optionally decrypt and apply FLAC.

        Args:
            record_id: UUID of the record
            decrypt: If True, decrypt AES-256 fields
            role: If provided, apply Field-Level Access Control after decryption
        """
        result = (
            self.db.table("health_records")
            .select("*, users!health_records_patient_id_fkey(email, full_name)")
            .eq("id", record_id)
            .execute()
        )
        if not result.data:
            return None

        record = result.data[0]
        if decrypt:
            record = self._decrypt_record(record)
            if role:
                from field_access import apply_field_access
                record = apply_field_access(record, role)
        return record

    def get_by_patient(self, patient_id: str, decrypt: bool = False,
                       role: str | None = None) -> list[dict]:
        """Fetch all records for a specific patient with optional FLAC."""
        result = (
            self.db.table("health_records")
            .select("*")
            .eq("patient_id", patient_id)
            .order("created_at", desc=True)
            .execute()
        )
        records = result.data or []
        if decrypt:
            records = [self._decrypt_record(r) for r in records]
            if role:
                from field_access import apply_field_access
                records = [apply_field_access(r, role) for r in records]
        return records

    def get_for_doctor(self, patient_ids: list[str]) -> list[dict]:
        """Fetch records only for patients assigned to a doctor."""
        if not patient_ids:
            return []
        result = (
            self.db.table("health_records")
            .select("*, users!health_records_patient_id_fkey(email, full_name)")
            .in_("patient_id", patient_ids)
            .order("created_at", desc=True)
            .execute()
        )
        return result.data or []

    def get_created_by(self, user_id: str) -> list[dict]:
        """Fetch records created by a specific user (nurse view)."""
        result = (
            self.db.table("health_records")
            .select("*, users!health_records_patient_id_fkey(email, full_name)")
            .eq("created_by", user_id)
            .order("created_at", desc=True)
            .execute()
        )
        return result.data or []

    def get_lab_queue(self) -> list[dict]:
        """Fetch records pending lab results (for Lab Tech dashboard)."""
        result = (
            self.db.table("health_records")
            .select("id, patient_id, created_by, lab_signed_by, created_at, users!health_records_patient_id_fkey(email, full_name)")
            .is_("lab_signed_by", "null")
            .eq("is_honeypot", False)
            .order("created_at", desc=True)
            .execute()
        )
        return result.data or []

    def create(self, patient_id: str, created_by: str,
               diagnosis: str, treatment: str = "",
               lab_results: str = "", notes: str = "") -> dict:
        """
        Create a new health record with AES-256 encryption + RSA digital signature.

        All sensitive fields are encrypted before storage.
        The record is signed with the creator's RSA private key for non-repudiation.
        """
        # Sign the plaintext content before encryption
        signature = ""
        try:
            from signatures import sign_record, get_user_keys
            private_key, _ = get_user_keys(self.db, created_by)
            signature = sign_record({
                "diagnosis": diagnosis,
                "treatment": treatment,
                "lab_results": lab_results,
                "notes": notes,
            }, private_key)
        except Exception:
            pass  # If signing fails, record is still created (just unsigned)

        result = (
            self.db.table("health_records")
            .insert({
                "patient_id": patient_id,
                "created_by": created_by,
                "diagnosis": encrypt_field(diagnosis),
                "treatment": encrypt_field(treatment),
                "lab_results": encrypt_field(lab_results),
                "notes": encrypt_field(notes),
                "signature": signature,
                "signature_algorithm": "RSA-SHA256" if signature else "",
                "is_honeypot": False,
                "created_at": utc_now(),
            })
            .execute()
        )
        return result.data[0] if result.data else {}

    def submit_lab_results(self, record_id: str, lab_tech_id: str,
                           lab_results: str) -> dict:
        """
        Lab Technician submits and signs lab results for a record.
        Results are encrypted and digitally signed for chain of custody.
        """
        from signatures import sign_lab_results, get_user_keys

        # Sign the lab results with tech's private key
        lab_signature = ""
        try:
            private_key, _ = get_user_keys(self.db, lab_tech_id)
            lab_signature = sign_lab_results(lab_results, private_key)
        except Exception:
            pass

        result = (
            self.db.table("health_records")
            .update({
                "lab_results": encrypt_field(lab_results),
                "lab_signed_by": lab_tech_id,
                "lab_signature": lab_signature,
                "lab_signed_at": utc_now(),
            })
            .eq("id", record_id)
            .execute()
        )
        return result.data[0] if result.data else {}

    def delete(self, record_id: str) -> bool:
        """Delete a health record by UUID."""
        result = (
            self.db.table("health_records")
            .delete()
            .eq("id", record_id)
            .execute()
        )
        return bool(result.data)

    def _decrypt_record(self, record: dict) -> dict:
        """Decrypt all encrypted fields in a record dict."""
        decrypted = record.copy()
        for field in self.ENCRYPTED_FIELDS:
            if field in decrypted and decrypted[field]:
                try:
                    decrypted[field] = decrypt_field(decrypted[field])
                except Exception:
                    decrypted[field] = "[Decryption Error]"
        return decrypted


# ═══════════════════════════════════════════════════════════════════
#  AUDIT LOGS (read-only — writes via security.py)
# ═══════════════════════════════════════════════════════════════════

class AuditLogModel:
    """Read operations for the audit_logs table."""

    def __init__(self, supabase):
        self.db = supabase

    def get_recent(self, limit: int = 100) -> list[dict]:
        """Fetch recent audit log entries with user info."""
        result = (
            self.db.table("audit_logs")
            .select("*, users(email, full_name, role)")
            .order("created_at", desc=True)
            .limit(limit)
            .execute()
        )
        return result.data or []

    def get_by_user(self, user_id: str, limit: int = 50) -> list[dict]:
        """Fetch audit logs for a specific user."""
        result = (
            self.db.table("audit_logs")
            .select("*")
            .eq("user_id", user_id)
            .order("created_at", desc=True)
            .limit(limit)
            .execute()
        )
        return result.data or []

    def count_by_action(self) -> dict:
        """Count audit events by action type (for dashboard stats)."""
        result = self.db.table("audit_logs").select("action").execute()
        counts = {}
        for row in (result.data or []):
            action = row.get("action", "UNKNOWN")
            counts[action] = counts.get(action, 0) + 1
        return counts


# ═══════════════════════════════════════════════════════════════════
#  DOCTOR-PATIENT ASSIGNMENTS
# ═══════════════════════════════════════════════════════════════════

class AssignmentModel:
    """CRUD operations for the doctor_patient_assignments table."""

    def __init__(self, supabase):
        self.db = supabase

    def get_all(self) -> list[dict]:
        """Fetch all assignments with doctor and patient info (admin view)."""
        result = (
            self.db.table("doctor_patient_assignments")
            .select(
                "id, assigned_at, "
                "doctor:users!doctor_patient_assignments_doctor_id_fkey(id, email, full_name), "
                "patient:users!doctor_patient_assignments_patient_id_fkey(id, email, full_name), "
                "assigner:users!doctor_patient_assignments_assigned_by_fkey(email, full_name)"
            )
            .order("assigned_at", desc=True)
            .execute()
        )
        return result.data or []

    def get_patients_for_doctor(self, doctor_id: str) -> list[str]:
        """Return list of patient UUIDs assigned to a doctor."""
        result = (
            self.db.table("doctor_patient_assignments")
            .select("patient_id")
            .eq("doctor_id", doctor_id)
            .execute()
        )
        return [r["patient_id"] for r in (result.data or [])]

    def get_patients_with_info(self, doctor_id: str) -> list[dict]:
        """Return assigned patient details for a doctor."""
        result = (
            self.db.table("doctor_patient_assignments")
            .select(
                "id, assigned_at, "
                "patient:users!doctor_patient_assignments_patient_id_fkey(id, email, full_name)"
            )
            .eq("doctor_id", doctor_id)
            .order("assigned_at", desc=True)
            .execute()
        )
        return result.data or []

    def get_doctors_for_patient(self, patient_id: str) -> list[str]:
        """Return list of doctor UUIDs assigned to a patient."""
        result = (
            self.db.table("doctor_patient_assignments")
            .select("doctor_id")
            .eq("patient_id", patient_id)
            .execute()
        )
        return [r["doctor_id"] for r in (result.data or [])]

    def is_assigned(self, doctor_id: str, patient_id: str) -> bool:
        """Check if a doctor is assigned to a specific patient."""
        result = (
            self.db.table("doctor_patient_assignments")
            .select("id")
            .eq("doctor_id", doctor_id)
            .eq("patient_id", patient_id)
            .execute()
        )
        return bool(result.data)

    def assign(self, doctor_id: str, patient_id: str, assigned_by: str) -> dict:
        """Create a doctor-patient assignment."""
        result = (
            self.db.table("doctor_patient_assignments")
            .insert({
                "doctor_id": doctor_id,
                "patient_id": patient_id,
                "assigned_by": assigned_by,
            })
            .execute()
        )
        return result.data[0] if result.data else {}

    def unassign(self, assignment_id: str) -> bool:
        """Remove a doctor-patient assignment."""
        result = (
            self.db.table("doctor_patient_assignments")
            .delete()
            .eq("id", assignment_id)
            .execute()
        )
        return bool(result.data)
