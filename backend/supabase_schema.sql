-- ============================================================
-- Vitalis EHR — Supabase Database Schema (v3.0)
-- Run this in the Supabase SQL Editor to create all tables.
-- Includes: 6 innovative security features + 5 roles
-- ============================================================

-- Enable UUID extension (usually enabled by default in Supabase)
CREATE EXTENSION IF NOT EXISTS "uuid-ossp";


-- ─── USERS TABLE ────────────────────────────────────────────────────
-- 5 roles: admin, doctor, nurse, lab_tech, patient
-- Includes RSA key pair for digital signatures and canary flag for honeypots

CREATE TABLE IF NOT EXISTS users (
    id              UUID DEFAULT uuid_generate_v4() PRIMARY KEY,
    email           TEXT UNIQUE NOT NULL,
    password_hash   TEXT NOT NULL,
    full_name       TEXT NOT NULL DEFAULT '',
    role            TEXT NOT NULL CHECK (role IN ('admin', 'doctor', 'nurse', 'lab_tech', 'patient')),
    is_locked       BOOLEAN DEFAULT FALSE,
    failed_attempts INTEGER DEFAULT 0,
    locked_at       TIMESTAMPTZ,
    -- RSA-2048 Key Pair (Feature 5: Digital Signatures)
    public_key      TEXT DEFAULT '',           -- PEM-encoded RSA public key
    private_key_enc TEXT DEFAULT '',           -- RSA private key encrypted with system AES key
    -- Honeypot Flag (Feature 2: Canary Records)
    is_canary       BOOLEAN DEFAULT FALSE,     -- True = fake patient (honeypot tripwire)
    created_at      TIMESTAMPTZ DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_users_email ON users (email);
CREATE INDEX IF NOT EXISTS idx_users_role ON users (role);
CREATE INDEX IF NOT EXISTS idx_users_canary ON users (is_canary) WHERE is_canary = TRUE;


-- ─── HEALTH RECORDS TABLE ───────────────────────────────────────────
-- Sensitive fields encrypted with AES-256-CBC (Base64-encoded ciphertext).
-- Includes digital signature and lab chain-of-custody fields.

CREATE TABLE IF NOT EXISTS health_records (
    id                  UUID DEFAULT uuid_generate_v4() PRIMARY KEY,
    patient_id          UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    created_by          UUID NOT NULL REFERENCES users(id) ON DELETE SET NULL,
    -- Encrypted clinical fields (AES-256-CBC)
    diagnosis           TEXT NOT NULL,                -- AES-256-CBC encrypted
    treatment           TEXT DEFAULT '',              -- AES-256-CBC encrypted
    lab_results         TEXT DEFAULT '',              -- AES-256-CBC encrypted
    notes               TEXT DEFAULT '',              -- AES-256-CBC encrypted
    -- Digital Signature (Feature 5: Non-Repudiation)
    signature           TEXT DEFAULT '',              -- RSA-SHA256 signature of record content
    signature_algorithm TEXT DEFAULT 'RSA-SHA256',
    -- Lab Chain of Custody (Lab Technician role)
    lab_signed_by       UUID REFERENCES users(id) ON DELETE SET NULL,
    lab_signature       TEXT DEFAULT '',              -- RSA signature on lab results specifically
    lab_signed_at       TIMESTAMPTZ,
    -- Honeypot Flag (Feature 2: Canary Records)
    is_honeypot         BOOLEAN DEFAULT FALSE,        -- True = decoy record (tripwire)
    created_at          TIMESTAMPTZ DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_records_patient ON health_records (patient_id);
CREATE INDEX IF NOT EXISTS idx_records_created_by ON health_records (created_by);
CREATE INDEX IF NOT EXISTS idx_records_honeypot ON health_records (is_honeypot) WHERE is_honeypot = TRUE;


-- ─── AUDIT LOGS TABLE ──────────────────────────────────────────────
-- Immutable audit trail with SHA-256 hash chain (Feature 1).
-- Each entry's chain_hash = SHA-256(previous_hash + entry_data).
-- Tampering with any entry breaks all downstream hashes.

CREATE TABLE IF NOT EXISTS audit_logs (
    id              UUID DEFAULT uuid_generate_v4() PRIMARY KEY,
    user_id         UUID REFERENCES users(id) ON DELETE SET NULL,
    action          TEXT NOT NULL,
    details         TEXT DEFAULT '',
    severity        TEXT DEFAULT 'info' CHECK (severity IN ('info', 'warning', 'critical')),
    ip_address      TEXT DEFAULT '',
    user_agent      TEXT DEFAULT '',
    -- Hash Chain (Feature 1: Cryptographic Integrity)
    chain_hash      TEXT DEFAULT '',              -- SHA-256(previous_hash + canonical_entry_data)
    previous_hash   TEXT DEFAULT '',              -- chain_hash of the preceding entry
    created_at      TIMESTAMPTZ DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_audit_user ON audit_logs (user_id);
CREATE INDEX IF NOT EXISTS idx_audit_action ON audit_logs (action);
CREATE INDEX IF NOT EXISTS idx_audit_created ON audit_logs (created_at DESC);
CREATE INDEX IF NOT EXISTS idx_audit_severity ON audit_logs (severity);


-- ─── SUSPICIOUS ACTIVITIES TABLE ────────────────────────────────────
-- SIEM-inspired anomaly detection results + honeypot triggers.

CREATE TABLE IF NOT EXISTS suspicious_activities (
    id              UUID DEFAULT uuid_generate_v4() PRIMARY KEY,
    user_id         UUID REFERENCES users(id) ON DELETE SET NULL,
    activity_type   TEXT NOT NULL,                -- e.g., 'honeypot_access', 'rapid_login_failures', 'break_the_glass'
    description     TEXT DEFAULT '',
    severity        TEXT DEFAULT 'warning' CHECK (severity IN ('info', 'warning', 'critical')),
    ip_address      TEXT DEFAULT '',
    created_at      TIMESTAMPTZ DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_suspicious_user ON suspicious_activities (user_id);
CREATE INDEX IF NOT EXISTS idx_suspicious_type ON suspicious_activities (activity_type);
CREATE INDEX IF NOT EXISTS idx_suspicious_created ON suspicious_activities (created_at DESC);


-- ─── BREAK-THE-GLASS EVENTS TABLE ──────────────────────────────────
-- Feature 6: Emergency Access Protocol
-- Records every instance of emergency override with justification.

CREATE TABLE IF NOT EXISTS btg_events (
    id              UUID DEFAULT uuid_generate_v4() PRIMARY KEY,
    user_id         UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    record_id       UUID NOT NULL REFERENCES health_records(id) ON DELETE CASCADE,
    justification   TEXT NOT NULL,                -- Written reason for emergency access
    ip_address      TEXT DEFAULT '',
    granted_at      TIMESTAMPTZ DEFAULT NOW(),
    expires_at      TIMESTAMPTZ NOT NULL,         -- When temporary access expires
    reviewed        BOOLEAN DEFAULT FALSE,        -- Has admin reviewed this?
    reviewed_by     UUID REFERENCES users(id) ON DELETE SET NULL,
    reviewed_at     TIMESTAMPTZ
);

CREATE INDEX IF NOT EXISTS idx_btg_user ON btg_events (user_id);
CREATE INDEX IF NOT EXISTS idx_btg_record ON btg_events (record_id);
CREATE INDEX IF NOT EXISTS idx_btg_expires ON btg_events (expires_at);
CREATE INDEX IF NOT EXISTS idx_btg_unreviewed ON btg_events (reviewed) WHERE reviewed = FALSE;


-- ─── ACTIVE SESSIONS TABLE (Optional) ──────────────────────────────
-- Feature 3: Session Fingerprinting — tracks active sessions for
-- concurrent login detection and fingerprint storage.

CREATE TABLE IF NOT EXISTS active_sessions (
    id                  UUID DEFAULT uuid_generate_v4() PRIMARY KEY,
    user_id             UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    fingerprint_hash    TEXT NOT NULL,             -- SHA-256 session fingerprint
    ip_address          TEXT DEFAULT '',
    user_agent          TEXT DEFAULT '',
    created_at          TIMESTAMPTZ DEFAULT NOW(),
    last_active         TIMESTAMPTZ DEFAULT NOW(),
    is_active           BOOLEAN DEFAULT TRUE
);

CREATE INDEX IF NOT EXISTS idx_sessions_user ON active_sessions (user_id);
CREATE INDEX IF NOT EXISTS idx_sessions_active ON active_sessions (is_active) WHERE is_active = TRUE;


-- ─── DOCTOR-PATIENT ASSIGNMENTS TABLE ─────────────────────────────
-- Tracks which doctors are assigned to which patients.
-- Many-to-many: a patient can have multiple doctors, a doctor has multiple patients.
-- Only Admin can create/delete assignments.

CREATE TABLE IF NOT EXISTS doctor_patient_assignments (
    id              UUID DEFAULT uuid_generate_v4() PRIMARY KEY,
    doctor_id       UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    patient_id      UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    assigned_at     TIMESTAMPTZ DEFAULT NOW(),
    assigned_by     UUID REFERENCES users(id) ON DELETE SET NULL,
    UNIQUE(doctor_id, patient_id)
);

CREATE INDEX IF NOT EXISTS idx_assignments_doctor ON doctor_patient_assignments (doctor_id);
CREATE INDEX IF NOT EXISTS idx_assignments_patient ON doctor_patient_assignments (patient_id);


-- ─── ROW LEVEL SECURITY (RLS) ──────────────────────────────────────
-- Since we use service_role key from Flask, RLS is bypassed server-side.
-- These policies add defense-in-depth for any direct Supabase client access.

ALTER TABLE users ENABLE ROW LEVEL SECURITY;
ALTER TABLE health_records ENABLE ROW LEVEL SECURITY;
ALTER TABLE audit_logs ENABLE ROW LEVEL SECURITY;
ALTER TABLE suspicious_activities ENABLE ROW LEVEL SECURITY;
ALTER TABLE btg_events ENABLE ROW LEVEL SECURITY;
ALTER TABLE active_sessions ENABLE ROW LEVEL SECURITY;

-- Service role can do anything (our Flask backend uses this)
CREATE POLICY "Service role full access" ON users
    FOR ALL USING (auth.role() = 'service_role');

CREATE POLICY "Service role full access" ON health_records
    FOR ALL USING (auth.role() = 'service_role');

CREATE POLICY "Service role full access" ON audit_logs
    FOR ALL USING (auth.role() = 'service_role');

CREATE POLICY "Service role full access" ON suspicious_activities
    FOR ALL USING (auth.role() = 'service_role');

CREATE POLICY "Service role full access" ON btg_events
    FOR ALL USING (auth.role() = 'service_role');

CREATE POLICY "Service role full access" ON active_sessions
    FOR ALL USING (auth.role() = 'service_role');

ALTER TABLE doctor_patient_assignments ENABLE ROW LEVEL SECURITY;

CREATE POLICY "Service role full access" ON doctor_patient_assignments
    FOR ALL USING (auth.role() = 'service_role');


-- ─── NOTE ───────────────────────────────────────────────────────────
-- Do NOT seed data here. Use the Python seed.py script instead,
-- which properly hashes passwords, generates RSA keys, encrypts
-- fields, and creates honeypot records.
-- Run: python backend/seed.py
