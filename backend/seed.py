"""
Vitalis EHR — Database Seeder (v3.0)
=====================================
Seeds the Supabase database with:
  - 5 demo users (one per role) with RSA key pairs
  - 2 canary (honeypot) patients with fake records
  - Sample health records for testing

Run: python seed.py

Demo Credentials:
  admin       admin@vitalis.ehr          Admin@2026!
  doctor      dr.smith@vitalis.ehr       Doctor@2026!
  nurse       nurse.jones@vitalis.ehr    Nurse@2026!
  lab_tech    lab.wilson@vitalis.ehr     LabTech@2026!
  patient     patient.doe@vitalis.ehr    Patient@2026!
"""

import os
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from dotenv import load_dotenv
load_dotenv()

from supabase import create_client
from auth import hash_password
from encryption import encrypt_field
from signatures import generate_keypair, encrypt_private_key, sign_record


# ─── Demo Users ──────────────────────────────────────────────────────

DEMO_USERS = [
    {
        "email": "admin@vitalis.ehr",
        "password": "Admin@2026!",
        "full_name": "System Administrator",
        "role": "admin",
    },
    {
        "email": "dr.smith@vitalis.ehr",
        "password": "Doctor@2026!",
        "full_name": "Dr. Sarah Smith",
        "role": "doctor",
    },
    {
        "email": "nurse.jones@vitalis.ehr",
        "password": "Nurse@2026!",
        "full_name": "Nurse Michael Jones",
        "role": "nurse",
    },
    {
        "email": "lab.wilson@vitalis.ehr",
        "password": "LabTech@2026!",
        "full_name": "Lab Tech David Wilson",
        "role": "lab_tech",
    },
    {
        "email": "patient.doe@vitalis.ehr",
        "password": "Patient@2026!",
        "full_name": "Jane Doe",
        "role": "patient",
    },
]

# ─── Canary (Honeypot) Patients ──────────────────────────────────────

CANARY_PATIENTS = [
    {
        "email": "m.johnson.1987@patient.vitalis.ehr",
        "full_name": "Michael A. Johnson",
    },
    {
        "email": "s.williams.1992@patient.vitalis.ehr",
        "full_name": "Sarah K. Williams",
    },
]

CANARY_RECORDS = [
    {
        "diagnosis": "Suspected Type 2 Diabetes Mellitus with peripheral neuropathy. Fasting glucose 142 mg/dL.",
        "treatment": "Metformin 500mg BID, dietary counseling referral, follow-up in 3 months.",
        "lab_results": "HbA1c: 7.2%, Fasting glucose: 142 mg/dL, Lipid panel pending.",
        "notes": "Patient compliant with medication. No acute distress.",
    },
    {
        "diagnosis": "Mild persistent asthma with seasonal exacerbation. Peak flow 78% predicted.",
        "treatment": "Continue fluticasone/salmeterol 250/50 BID. PRN albuterol.",
        "lab_results": "Spirometry: FEV1 82% predicted. No eosinophilia.",
        "notes": "Routine follow-up. Inhaler technique reviewed.",
    },
]


def seed():
    """Main seeding function."""
    url = os.getenv("SUPABASE_URL")
    key = os.getenv("SUPABASE_SERVICE_ROLE_KEY")
    if not url or not key:
        print("ERROR: Set SUPABASE_URL and SUPABASE_SERVICE_ROLE_KEY in .env")
        sys.exit(1)

    # Check AES key
    aes_key = os.getenv("AES_ENCRYPTION_KEY")
    if not aes_key or len(aes_key) != 64:
        print("ERROR: Set AES_ENCRYPTION_KEY (64 hex chars) in .env")
        print("Generate one with: python -c \"import os; print(os.urandom(32).hex())\"")
        sys.exit(1)

    supabase = create_client(url, key)
    print("Connected to Supabase.\n")

    # ── Step 1: Create demo users with RSA key pairs ──
    print("=== Creating Demo Users ===")
    user_ids = {}
    for user in DEMO_USERS:
        existing = (
            supabase.table("users")
            .select("id")
            .eq("email", user["email"])
            .execute()
        )
        if existing.data:
            user_ids[user["role"]] = existing.data[0]["id"]
            print(f"  SKIP  {user['email']} (already exists)")
            continue

        # Generate RSA-2048 key pair
        private_pem, public_pem = generate_keypair()
        encrypted_private = encrypt_private_key(private_pem)

        result = supabase.table("users").insert({
            "email": user["email"],
            "password_hash": hash_password(user["password"]),
            "full_name": user["full_name"],
            "role": user["role"],
            "is_locked": False,
            "failed_attempts": 0,
            "public_key": public_pem,
            "private_key_enc": encrypted_private,
            "is_canary": False,
        }).execute()

        if result.data:
            user_ids[user["role"]] = result.data[0]["id"]
            print(f"  CREATE  {user['email']} ({user['role']}) + RSA keys generated")

    # ── Step 2: Create canary (honeypot) patients ──
    print("\n=== Creating Honeypot Patients ===")
    canary_ids = []
    for canary in CANARY_PATIENTS:
        existing = (
            supabase.table("users")
            .select("id")
            .eq("email", canary["email"])
            .execute()
        )
        if existing.data:
            canary_ids.append(existing.data[0]["id"])
            print(f"  SKIP  {canary['email']} (already exists)")
            continue

        result = supabase.table("users").insert({
            "email": canary["email"],
            "password_hash": hash_password("CanaryDoNotLogin!2026"),
            "full_name": canary["full_name"],
            "role": "patient",
            "is_locked": True,
            "failed_attempts": 0,
            "is_canary": True,
            "public_key": "",
            "private_key_enc": "",
        }).execute()

        if result.data:
            canary_ids.append(result.data[0]["id"])
            print(f"  CREATE  {canary['email']} (CANARY patient)")

    # ── Step 3: Create honeypot records for canary patients ──
    print("\n=== Creating Honeypot Records ===")
    doctor_id = user_ids.get("doctor")
    if doctor_id and canary_ids:
        for i, canary_id in enumerate(canary_ids):
            # Check if records already exist
            existing = (
                supabase.table("health_records")
                .select("id")
                .eq("patient_id", canary_id)
                .eq("is_honeypot", True)
                .execute()
            )
            if existing.data:
                print(f"  SKIP  Records for canary {i+1} (already exist)")
                continue

            record_data = CANARY_RECORDS[i % len(CANARY_RECORDS)]
            supabase.table("health_records").insert({
                "patient_id": canary_id,
                "created_by": doctor_id,
                "diagnosis": encrypt_field(record_data["diagnosis"]),
                "treatment": encrypt_field(record_data["treatment"]),
                "lab_results": encrypt_field(record_data["lab_results"]),
                "notes": encrypt_field(record_data["notes"]),
                "is_honeypot": True,
                "signature": "",
            }).execute()
            print(f"  CREATE  Honeypot record for canary patient {i+1}")

    # ── Step 4: Assign demo patient to demo doctor ──
    print("\n=== Doctor-Patient Assignments ===")
    patient_id = user_ids.get("patient")
    if doctor_id and patient_id:
        existing = (
            supabase.table("doctor_patient_assignments")
            .select("id")
            .eq("doctor_id", doctor_id)
            .eq("patient_id", patient_id)
            .execute()
        )
        if existing.data:
            print(f"  SKIP  Jane Doe already assigned to Dr. Smith")
        else:
            admin_id = user_ids.get("admin")
            supabase.table("doctor_patient_assignments").insert({
                "doctor_id": doctor_id,
                "patient_id": patient_id,
                "assigned_by": admin_id,
            }).execute()
            print(f"  CREATE  Assigned Jane Doe → Dr. Smith")

    # ── Step 5: Create sample real records ──
    print("\n=== Creating Sample Health Records ===")
    if doctor_id and patient_id:
        existing = (
            supabase.table("health_records")
            .select("id")
            .eq("patient_id", patient_id)
            .eq("is_honeypot", False)
            .execute()
        )
        if existing.data:
            print("  SKIP  Sample records (already exist)")
        else:
            # Create a signed record
            diagnosis = "Hypertension Stage 1. BP 142/92 mmHg. No end-organ damage."
            treatment = "Lisinopril 10mg daily. Lifestyle modifications: DASH diet, 30min exercise 5x/week."
            lab_results = "BMP: Normal. Lipid panel: LDL 145 mg/dL (elevated). eGFR > 60."
            notes = "Patient counseled on salt restriction and weight management goals."

            # Sign with doctor's key
            private_key, _ = None, None
            try:
                from signatures import get_user_keys
                private_key, _ = get_user_keys(supabase, doctor_id)
            except Exception:
                pass

            signature = ""
            if private_key:
                signature = sign_record({
                    "diagnosis": diagnosis,
                    "treatment": treatment,
                    "lab_results": lab_results,
                    "notes": notes,
                }, private_key)

            supabase.table("health_records").insert({
                "patient_id": patient_id,
                "created_by": doctor_id,
                "diagnosis": encrypt_field(diagnosis),
                "treatment": encrypt_field(treatment),
                "lab_results": encrypt_field(lab_results),
                "notes": encrypt_field(notes),
                "is_honeypot": False,
                "signature": signature,
                "signature_algorithm": "RSA-SHA256" if signature else "",
            }).execute()
            print("  CREATE  Signed health record for Jane Doe")

    # ── Summary ──
    print("\n" + "=" * 50)
    print("SEED COMPLETE")
    print("=" * 50)
    print("\nDemo Credentials:")
    print(f"{'Role':<12} {'Email':<32} {'Password'}")
    print("-" * 60)
    for u in DEMO_USERS:
        print(f"  {u['role']:<10} {u['email']:<30} {u['password']}")
    print(f"\nHoneypot patients: {len(canary_ids)} created")
    print("WARNING: Canary accounts are locked and cannot log in.")
    print("\nNext steps:")
    print("  1. Run: python app.py")
    print("  2. Login as admin@vitalis.ehr / Admin@2026!")
    print("  3. Test all 5 roles and security features")


if __name__ == "__main__":
    seed()
