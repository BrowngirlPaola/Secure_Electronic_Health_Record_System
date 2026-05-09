# Secure Electronic Health Record (EHR) Transfer System

## Version 3.0 — Security-First Architecture

**Student:** Yong Paola Nabain  
**Supervisor:** Dr. Fosso  
**Institution:** The ICT University — Faculty of Information and Communication Technology (FICT)  
**Programme:** Cybersecurity  
**Project Title:** Design and Implementation of a Secure Electronic Health Record Transfer System Using Advanced Encryption, Role-Based Access Control, and Innovative Cybersecurity Mechanisms  
**Date:** May 2026

---

## Abstract

This project implements a web-based Electronic Health Record (EHR) system that places **cybersecurity at its architectural core** — not as an afterthought. Beyond standard encryption and access control, the system introduces six innovative security mechanisms rarely found in healthcare applications: cryptographic audit log integrity via hash chains, honeypot/canary records for insider threat detection, session fingerprinting against hijacking attacks, field-level access control implementing HIPAA's "minimum necessary" rule at maximum granularity, RSA-2048 digital signatures for non-repudiation, and a Break-the-Glass emergency access protocol. Five distinct user roles (Admin, Doctor, Nurse, Lab Technician, Patient) each operate within strictly compartmentalized security boundaries, demonstrating that a system can be simultaneously secure, usable, and compliant with international healthcare data protection standards.

---

## 1. Project Overview

### 1.1 Purpose

This system enables healthcare personnel to securely create, store, access, and transfer electronic health records while enforcing:

- **6 layers of defense** against distinct threat categories
- **Strict access control** at both record and field levels
- **Cryptographic guarantees** of data confidentiality, integrity, and authenticity
- **Tamper-evident audit trails** with mathematical proof of integrity
- **Active deception defenses** against insider threats
- **Emergency access protocols** balancing security with clinical availability

### 1.2 What Makes This Different

| Standard EHR System | Vitalis EHR (This Project) |
|---|---|
| Password hashing + login lockout | + Session fingerprinting to detect hijacking |
| Record-level access control | + **Field-level** access control (per-column visibility) |
| Basic audit logging | + **Hash-chained** tamper-evident audit trail |
| Static 403 for unauthorized access | + **Break-the-Glass** emergency override with accountability |
| Trust all authorized users equally | + **Honeypot records** that catch malicious insiders |
| `created_by` metadata for authorship | + **RSA digital signatures** for mathematical non-repudiation |
| 3-4 roles | **5 roles** with compartmentalized field visibility |

### 1.3 Engineering Principles

| Principle | Application |
|---|---|
| **DRY** | Shared CSS/JS, reusable encryption functions, base template inheritance |
| **KISS** | Each module has one responsibility — no over-engineering |
| **Separation of Concerns** | Models, routes, auth, encryption, security all in separate files |
| **Least Privilege** | Every user sees ONLY what their role + field access permits |
| **Defense in Depth** | 6 independent security layers — compromise of one doesn't break others |
| **Fail Securely** | Failed login → locked; stolen session → killed; unauthorized → 403 |
| **Zero Trust** | Verify every request — session fingerprint checked on EVERY request |

---

## 2. Security Architecture (Centerpiece)

### 2.1 Philosophy: Defense in Depth with 6 Layers

```
┌─────────────────────────────────────────────────────────────────────┐
│  LAYER 6: CRYPTOGRAPHIC INTEGRITY                                    │
│  Hash-chained audit logs, RSA signatures, AES-256 encryption         │
├─────────────────────────────────────────────────────────────────────┤
│  LAYER 5: FIELD-LEVEL ACCESS CONTROL                                 │
│  Per-column visibility matrix — roles see different fields            │
├─────────────────────────────────────────────────────────────────────┤
│  LAYER 4: RECORD-LEVEL AUTHORIZATION (RBAC)                          │
│  Role-based access decorators + Break-the-Glass override             │
├─────────────────────────────────────────────────────────────────────┤
│  LAYER 3: AUTHENTICATION & IDENTITY                                  │
│  Bcrypt hashing, brute-force lockout, NIST password policy           │
├─────────────────────────────────────────────────────────────────────┤
│  LAYER 2: SESSION SECURITY                                           │
│  Session fingerprinting, hijack detection, auto-termination          │
├─────────────────────────────────────────────────────────────────────┤
│  LAYER 1: DECEPTION & MONITORING                                     │
│  Honeypot records, suspicious activity detection, SIEM-inspired      │
└─────────────────────────────────────────────────────────────────────┘
```

### 2.2 Threat Model

| Threat | Attack Vector | Defense Layer | Mechanism |
|--------|--------------|---------------|-----------|
| **Credential theft** | Phishing, keylogger | Layer 3 | Bcrypt + lockout after 3 attempts |
| **Session hijacking** | XSS, MITM, cookie theft | Layer 2 | Session fingerprinting (auto-kill on mismatch) |
| **Privilege escalation** | URL manipulation, API abuse | Layer 4 | `@role_required` decorator on every route |
| **Data exfiltration by insider** | Authorized user snooping | Layer 1 | Honeypot canary records trigger silent alerts |
| **Audit log tampering** | DBA covers their tracks | Layer 6 | SHA-256 hash chain — tampered entries are mathematically detectable |
| **Record forgery** | Someone edits `created_by` | Layer 6 | RSA-2048 digital signature proves authorship |
| **Excessive data exposure** | Nurse seeing diagnosis details | Layer 5 | Field-level access matrix masks/hides fields per role |
| **Emergency denial of care** | Rigid access = patient harm | Layer 4 | Break-the-Glass protocol with time-bound override |
| **Weak passwords** | Brute force, dictionary attack | Layer 3 | NIST SP 800-63B enforcement |
| **Bulk data scraping** | Automated record viewing | Layer 1 | Suspicious activity detector (SIEM rules) |

### 2.3 System Architecture Diagram

```
┌──────────────────────────────────────────────────────────────┐
│                    WEB BROWSER (Client)                        │
│            Tailwind CSS + Material Symbols + Inter             │
└────────────────────────┬─────────────────────────────────────┘
                         │ HTTPS
┌────────────────────────▼─────────────────────────────────────┐
│                FLASK APPLICATION LAYER                         │
│                                                               │
│  ┌──────────────┐  ┌──────────────┐  ┌───────────────────┐  │
│  │  routes.py   │  │   auth.py    │  │  encryption.py    │  │
│  │  (Blueprints)│  │  (RBAC+Lock) │  │  (AES-256-CBC)    │  │
│  └──────────────┘  └──────────────┘  └───────────────────┘  │
│                                                               │
│  ┌──────────────┐  ┌──────────────┐  ┌───────────────────┐  │
│  │ security.py  │  │ integrity.py │  │  signatures.py    │  │
│  │ (Audit+SIEM) │  │ (Hash Chain) │  │  (RSA-2048)       │  │
│  └──────────────┘  └──────────────┘  └───────────────────┘  │
│                                                               │
│  ┌──────────────┐  ┌──────────────┐  ┌───────────────────┐  │
│  │ honeypot.py  │  │field_access.py│ │session_security.py│  │
│  │ (Canaries)   │  │   (FLAC)     │  │ (Fingerprinting)  │  │
│  └──────────────┘  └──────────────┘  └───────────────────┘  │
│                                                               │
│  ┌──────────────┐  ┌──────────────────────────────────────┐  │
│  │emergency_    │  │           models.py                   │  │
│  │access.py     │  │  (User, Record, AuditLog, BTG)       │  │
│  │(Break Glass) │  └──────────────────────────────────────┘  │
│  └──────────────┘                                            │
└────────────────────────┬─────────────────────────────────────┘
                         │ Supabase Python SDK (REST API)
┌────────────────────────▼─────────────────────────────────────┐
│              SUPABASE (Hosted PostgreSQL)                      │
│                                                               │
│  ┌────────┐ ┌───────────────┐ ┌───────────┐ ┌────────────┐  │
│  │ users  │ │health_records │ │audit_logs │ │btg_events  │  │
│  │        │ │(AES encrypted)│ │(hash chain)│ │            │  │
│  └────────┘ └───────────────┘ └───────────┘ └────────────┘  │
│  ┌───────────────────────┐ ┌──────────────────────────────┐  │
│  │suspicious_activities  │ │    active_sessions            │  │
│  └───────────────────────┘ └──────────────────────────────┘  │
└──────────────────────────────────────────────────────────────┘
```

---

## 3. User Roles & Permissions

The system defines **five (5)** distinct user roles. Each role has strictly compartmentalized permissions following the **Principle of Least Privilege** and **HIPAA Minimum Necessary Rule**.

### 3.1 Role-Based Access Control (RBAC) Matrix

| Permission                   | Admin | Doctor | Nurse | Lab Tech | Patient |
|------------------------------|:-----:|:------:|:-----:|:--------:|:-------:|
| Create users                 |  ✅  |   ❌   |  ❌  |    ❌    |   ❌   |
| Delete users                 |  ✅  |   ❌   |  ❌  |    ❌    |   ❌   |
| Unlock locked accounts       |  ✅  |   ❌   |  ❌  |    ❌    |   ❌   |
| View all health records      |  ✅  |   ✅   |  ❌  |    ❌    |   ❌   |
| Create health records        |  ❌  |   ✅   |  ✅  |    ❌    |   ❌   |
| Edit health records          |  ❌  |   ✅   |  ❌  |    ❌    |   ❌   |
| Delete health records        |  ✅  |   ❌   |  ❌  |    ❌    |   ❌   |
| Submit lab results           |  ❌  |   ❌   |  ❌  |    ✅    |   ❌   |
| View lab queue only          |  ❌  |   ❌   |  ❌  |    ✅    |   ❌   |
| View own records only        |  ❌  |   ❌   |  ❌  |    ❌    |   ✅   |
| View self-created records    |  ❌  |   ❌   |  ✅  |    ❌    |   ❌   |
| View audit logs              |  ✅  |   ❌   |  ❌  |    ❌    |   ❌   |
| View security dashboard      |  ✅  |   ❌   |  ❌  |    ❌    |   ❌   |
| Review BTG events            |  ✅  |   ❌   |  ❌  |    ❌    |   ❌   |
| Break-the-Glass access       |  ❌  |   ✅   |  ✅  |    ❌    |   ❌   |
| Verify audit integrity       |  ✅  |   ❌   |  ❌  |    ❌    |   ❌   |
| View encryption proof        |  ✅  |   ✅   |  ❌  |    ❌    |   ❌   |

### 3.2 Field-Level Access Control (FLAC) Matrix

Controls which fields are visible within a record, per role:

| Field | Admin | Doctor | Nurse | Lab Tech | Patient |
|-------|:-----:|:------:|:-----:|:--------:|:-------:|
| `diagnosis` | Full | Full | Masked | **Hidden** | Full |
| `treatment` | Full | Full | Full | **Hidden** | Full |
| `lab_results` | Full | Full | Full | **Full** | Summary |
| `notes` | Full | Full | Hidden | **Hidden** | Hidden |
| `signature` | Full | Full | View only | Hidden | Hidden |

**Access Levels:**
- **Full** — complete plaintext visible
- **Masked** — first 3 and last 3 characters shown, rest replaced with `***`
- **Summary** — truncated to first sentence only
- **Hidden** — field not rendered at all (shows "[RESTRICTED — Insufficient clearance]")

### 3.3 Lab Technician — Unique Security Profile

The Lab Technician demonstrates **data compartmentalization**:

| Security Constraint | Implementation | Concept |
|---|---|---|
| Result-only field access | FLAC matrix hides diagnosis, treatment, notes entirely | Need-to-know basis |
| Chain of custody signing | RSA signature required before results are visible to doctors | Evidence integrity |
| Result immutability | Signed results cannot be modified — only addendums allowed | Write-once audit trail |
| Time-bounded submission | Configurable window (24h) for result entry after lab order | Time-based access control |

---

## 4. Core Functional Requirements

### 4.1 Authentication System

- **F1.1** — User login with email and password
- **F1.2** — Passwords hashed using **bcrypt** (12 rounds) — never stored in plain text
- **F1.3** — Session management using Flask signed sessions (cookie-based, HMAC-signed)
- **F1.4** — **Failed login attempt tracking** — account locked after **3 consecutive failed attempts**
- **F1.5** — Locked accounts can only be unlocked by Admin
- **F1.6** — Login timestamp and IP address recorded on every authentication event
- **F1.7** — Redirect unauthorized users to login page automatically
- **F1.8** — **Session fingerprinting** — composite hash of User-Agent + Accept-Language + IP subnet verified on every request
- **F1.9** — Session automatically killed if fingerprint mismatch detected (hijacking defense)

### 4.2 Role-Based Access Control (RBAC)

- **F2.1** — Every route protected by `@role_required` decorator
- **F2.2** — Users cannot access pages outside their role — returns 403 Forbidden
- **F2.3** — Sidebar navigation dynamically shows only permitted links per role
- **F2.4** — Admin is the only role that can create new user accounts
- **F2.5** — Role assigned at account creation and cannot be changed by the user
- **F2.6** — **Field-Level Access Control** applied to every record view based on role
- **F2.7** — **Break-the-Glass** protocol available for Doctors and Nurses when emergency access needed

### 4.3 Health Record Management

- **F3.1** — Doctors and Nurses can create health records for patients
- **F3.2** — Health records contain: diagnosis, treatment, lab_results, notes
- **F3.3** — All record fields encrypted with **AES-256-CBC** before saving to database
- **F3.4** — Records decrypted on-the-fly only for authorized users during viewing
- **F3.5** — **Field-level filtering** applied after decryption based on viewer's role
- **F3.6** — Patients can only view records where they are the subject
- **F3.7** — Doctors can view all records in the system
- **F3.8** — Nurses can only view records they personally created
- **F3.9** — Lab Technicians can only view/submit the `lab_results` field
- **F3.10** — Admin can delete records but cannot create them
- **F3.11** — Each record stores: patient, creator, timestamp, encrypted fields, **digital signature**
- **F3.12** — Lab results require technician's digital signature before becoming visible to clinicians

### 4.4 AES-256-CBC Encryption

- **F4.1** — All sensitive health record fields encrypted using **AES-256-CBC**
- **F4.2** — A unique **Initialization Vector (IV)** generated for every encryption operation
- **F4.3** — IV prepended to ciphertext (first 16 bytes), then Base64 encoded for storage
- **F4.4** — Encryption key stored securely in environment variable (never hardcoded)
- **F4.5** — Decryption only happens at the application layer — database stores only ciphertext
- **F4.6** — Empty fields handled gracefully (no crash on decrypt of empty string)

### 4.5 Digital Signatures (RSA-2048)

- **F5.1** — RSA-2048 key pair generated for each user at account creation
- **F5.2** — Public key stored in `users` table (readable for verification)
- **F5.3** — Private key stored encrypted with system AES key (protected at rest)
- **F5.4** — Record creation triggers digital signature of canonical plaintext content
- **F5.5** — Signature stored with the record (Base64 encoded)
- **F5.6** — Verification page shows: signature, public key, verification result
- **F5.7** — Lab results additionally signed by Lab Technician for chain of custody

### 4.6 Audit Logging (Hash-Chained)

- **F6.1** — Every significant action logged automatically:
  - User login / logout
  - Record created, viewed, decrypted, deleted
  - Failed login attempts
  - Unauthorized access attempts
  - Honeypot record accessed
  - Break-the-Glass events
  - Account locked / unlocked
- **F6.2** — Each log entry records: user, action, details, severity, IP address, user-agent, timestamp
- **F6.3** — **Hash chain**: each entry contains SHA-256 hash of `(previous_hash + entry_data)`
- **F6.4** — Chain integrity verifiable at any time — a single tampered entry breaks the chain
- **F6.5** — Audit logs visible only to Admin
- **F6.6** — Logs stored in `audit_logs` table — cannot be deleted through the UI (tamper-evident)
- **F6.7** — Admin can run integrity verification showing green (valid) or red (broken) for each link

### 4.7 Honeypot / Canary Records

- **F7.1** — System contains realistic-looking fake patient records (canary records)
- **F7.2** — Canary records appear indistinguishable from real records in all list views
- **F7.3** — Accessing a canary record triggers immediate critical security alert
- **F7.4** — Alert logged with: who accessed, when, from where, which canary
- **F7.5** — Admin dashboard shows honeypot alert panel
- **F7.6** — Canary patients seeded with realistic names and encrypted records

### 4.8 Break-the-Glass Emergency Access

- **F8.1** — When Doctor/Nurse is denied access to a record they don't normally have permission for
- **F8.2** — Instead of flat 403, system presents "Break the Glass" form
- **F8.3** — User must enter written justification for emergency access
- **F8.4** — Temporary access granted for **30 minutes** (configurable)
- **F8.5** — Event logged with critical severity, IP, justification text
- **F8.6** — Admin receives alert and can review all BTG events
- **F8.7** — Admin marks BTG events as reviewed/legitimate or flags for investigation
- **F8.8** — Expired BTG access requires re-justification

### 4.9 Suspicious Activity Detection (SIEM-Inspired)

- **F9.1** — Rule-based detection of anomalous user behavior
- **F9.2** — Triggers on: 5+ failed logins in 5 minutes, off-hours access (22:00-06:00), bulk record viewing (20+ in 10 minutes)
- **F9.3** — Suspicious events stored in `suspicious_activities` table with severity
- **F9.4** — Admin dashboard shows real-time suspicious activity panel
- **F9.5** — No machine learning — pure deterministic rule-based logic

### 4.10 User Management (Admin Only)

- **F10.1** — Admin can create new users with assigned roles
- **F10.2** — Admin can view all registered users
- **F10.3** — Admin can unlock locked accounts
- **F10.4** — Admin can delete user accounts (except self)
- **F10.5** — User list displays: name, email, role, account status, date joined
- **F10.6** — Duplicate email addresses rejected at registration
- **F10.7** — Password strength enforcement (NIST SP 800-63B) at registration

---

## 5. Advanced Cybersecurity Features (Innovations)

These six features elevate the project from a standard EHR system to a **defense-worthy cybersecurity application** demonstrating deep understanding of security concepts.

---

### 5.1 Cryptographic Audit Log Integrity (Hash Chain)

**Threat Addressed:** Insider threat — a compromised database administrator silently deleting or modifying audit log entries to cover their tracks.

**Mechanism:**
```
Entry[0].chain_hash = SHA-256(GENESIS_HASH + Entry[0].data)
Entry[1].chain_hash = SHA-256(Entry[0].chain_hash + Entry[1].data)
Entry[N].chain_hash = SHA-256(Entry[N-1].chain_hash + Entry[N].data)
```

If any entry is modified, deleted, or reordered, all subsequent hashes become invalid.

**Cybersecurity Concepts Demonstrated:**
- Cryptographic hash functions (SHA-256) and their collision resistance
- Blockchain/hash-chain principle applied to a practical problem
- Tamper detection (integrity, not confidentiality)
- Defense against insider threats with database access
- Immutable audit trails

**Standards Reference:** NIST SP 800-92 (Guide to Computer Security Log Management)

**Implementation:** `backend/integrity.py` — `compute_chain_hash()` and `verify_audit_chain()` functions

---

### 5.2 Honeypot / Canary Records

**Threat Addressed:** Authorized insiders misusing their legitimate access — a doctor browsing records of patients not in their care, or an employee selling patient data.

**Mechanism:**
- Seed database with realistic fake patients and encrypted records marked `is_honeypot=True`
- Canary records appear identical to real records in all list views
- On access: silent critical alert fires (the user is NOT informed it's a trap)
- Admin sees "who accessed the honeypot, when, from where"

**Cybersecurity Concepts Demonstrated:**
- Deception-based defense (honeypots/honeytokens)
- Insider threat detection beyond access control
- MITRE ATT&CK framework awareness (T1530: Data from Cloud Storage)
- The principle that authorization alone is insufficient

**Standards Reference:** MITRE ATT&CK, NIST Cybersecurity Framework (Detect function)

**Implementation:** `backend/honeypot.py` — `check_honeypot_access()` called on every record view

---

### 5.3 Session Fingerprinting & Hijacking Detection

**Threat Addressed:** Session hijacking via stolen cookies (XSS attacks, man-in-the-middle, physical access to browser).

**Mechanism:**
```
fingerprint = SHA-256(User-Agent | Accept-Language | IP_Subnet/24)
```
- Computed on login and stored in session
- Recomputed on every authenticated request
- Mismatch → session immediately killed + critical alert logged

**Cybersecurity Concepts Demonstrated:**
- Session hijacking attack vectors
- OWASP Session Management Cheat Sheet compliance
- Browser fingerprinting techniques
- Real-time threat response (automatic session termination)
- Zero-trust verification on every request

**Standards Reference:** OWASP Session Management Cheat Sheet, NIST SP 800-63B Section 7

**Implementation:** `backend/session_security.py` — `@app.before_request` middleware

---

### 5.4 Field-Level Access Control (FLAC)

**Threat Addressed:** Excessive data exposure — users seeing more information than their job function requires (violation of HIPAA's "minimum necessary" rule).

**Mechanism:**
- Configurable access matrix: `{field: {role: "full"|"masked"|"summary"|"hidden"}}`
- Applied AFTER decryption, BEFORE rendering
- Masked fields show: `"Dia***tes"` (first 3 + last 3 chars)
- Hidden fields show: `"[RESTRICTED — Insufficient clearance]"`

**Cybersecurity Concepts Demonstrated:**
- Attribute-Based Access Control (ABAC) vs. simple RBAC
- HIPAA "Minimum Necessary" Rule (45 CFR 164.502(b))
- Data classification and labeling (like military SECRET/TOP SECRET)
- The distinction between authentication, authorization, and information filtering

**Standards Reference:** HIPAA 45 CFR 164.502(b), NIST SP 800-162 (ABAC Guide)

**Implementation:** `backend/field_access.py` — `apply_field_access(record, role)` function

---

### 5.5 Digital Signatures for Non-Repudiation

**Threat Addressed:** Record forgery — an attacker modifying record content AND the `created_by` field to frame another practitioner, or denying they wrote a specific record.

**Mechanism:**
```
signature = RSA-SHA256.sign(canonical_JSON(record_fields), author_private_key)
verify   = RSA-SHA256.verify(canonical_JSON(record_fields), signature, author_public_key)
```
- Key pair generated per user (RSA-2048)
- Private key stored encrypted with system AES key
- Signature = mathematical proof that THIS doctor wrote THIS content

**Cybersecurity Concepts Demonstrated:**
- Asymmetric cryptography (RSA-2048)
- Digital signature generation and verification workflow
- Non-repudiation as a legal/security property
- Public Key Infrastructure (PKI) concepts
- Difference between encryption (confidentiality) and signing (integrity + authenticity)

**Standards Reference:** NIST SP 800-89 (Recommendation for Obtaining Assurances for Digital Signature Applications)

**Implementation:** `backend/signatures.py` — `sign_record()` and `verify_signature()` functions

---

### 5.6 Break-the-Glass Emergency Access Protocol

**Threat Addressed:** Rigid access control causing clinical harm — patient arrives unconscious in ER, attending doctor needs allergy history but isn't the assigned physician.

**Mechanism:**
- 403 response → replaced with "Break the Glass" form for Doctors/Nurses
- User enters written justification → 30-minute temporary access granted
- Critical alert fires immediately
- Admin reviews all BTG events in a dedicated queue
- Expired access requires re-justification

**Cybersecurity Concepts Demonstrated:**
- The fundamental security vs. availability trade-off in healthcare
- HIPAA emergency access procedure compliance
- Compensating controls (relax one control, strengthen monitoring)
- Time-bounded access tokens
- Accountability replacing prevention (you CAN access, but you WILL be reviewed)
- Risk-based vs. rule-based access control

**Standards Reference:** HIPAA 45 CFR 164.312(a)(2)(ii) — Emergency Access Procedure

**Implementation:** `backend/emergency_access.py` — `initiate_btg()` and `check_btg_active()` functions

---

## 6. Database Schema

### 6.1 Table: `users`

| Column | Type | Description |
|--------|------|-------------|
| id | UUID (PK) | Unique user identifier |
| email | TEXT (UNIQUE) | Login email address |
| password_hash | TEXT | Bcrypt-hashed password (12 rounds) |
| full_name | TEXT | User display name |
| role | TEXT | `admin` / `doctor` / `nurse` / `lab_tech` / `patient` |
| is_locked | BOOLEAN | Account lockout status |
| failed_attempts | INTEGER | Consecutive failed login count |
| locked_at | TIMESTAMPTZ | When account was locked |
| public_key | TEXT | RSA-2048 public key (PEM format) |
| private_key_enc | TEXT | RSA private key encrypted with system AES key |
| is_canary | BOOLEAN | True if this is a honeypot user |
| created_at | TIMESTAMPTZ | Account creation timestamp |

### 6.2 Table: `health_records`

| Column | Type | Description |
|--------|------|-------------|
| id | UUID (PK) | Unique record identifier |
| patient_id | UUID (FK → users) | The patient this record belongs to |
| created_by | UUID (FK → users) | The practitioner who created it |
| diagnosis | TEXT | AES-256-CBC encrypted diagnosis |
| treatment | TEXT | AES-256-CBC encrypted treatment plan |
| lab_results | TEXT | AES-256-CBC encrypted lab results |
| notes | TEXT | AES-256-CBC encrypted clinical notes |
| signature | TEXT | RSA-SHA256 digital signature (Base64) |
| signature_algorithm | TEXT | `RSA-SHA256` |
| lab_signed_by | UUID (FK → users) | Lab technician who signed results |
| lab_signature | TEXT | RSA signature on lab results specifically |
| lab_signed_at | TIMESTAMPTZ | When lab results were signed |
| is_honeypot | BOOLEAN | True if this is a canary record |
| created_at | TIMESTAMPTZ | Record creation timestamp |

### 6.3 Table: `audit_logs`

| Column | Type | Description |
|--------|------|-------------|
| id | UUID (PK) | Unique log entry ID |
| user_id | UUID (FK → users) | Who performed the action |
| action | TEXT | Action label (e.g., `LOGIN_SUCCESS`, `RECORD_CREATED`) |
| details | TEXT | Human-readable description |
| severity | TEXT | `info` / `warning` / `critical` |
| ip_address | TEXT | Client IP address |
| user_agent | TEXT | Browser User-Agent string |
| chain_hash | TEXT | SHA-256 hash (this entry + previous hash) |
| previous_hash | TEXT | Hash of the previous entry in the chain |
| created_at | TIMESTAMPTZ | When the event occurred |

### 6.4 Table: `suspicious_activities`

| Column | Type | Description |
|--------|------|-------------|
| id | UUID (PK) | Unique alert ID |
| user_id | UUID (FK → users) | User who triggered the alert |
| activity_type | TEXT | Type (e.g., `rapid_login_failures`, `honeypot_access`) |
| description | TEXT | Human-readable alert text |
| severity | TEXT | `warning` / `critical` |
| ip_address | TEXT | Source IP |
| created_at | TIMESTAMPTZ | When detected |

### 6.5 Table: `btg_events`

| Column | Type | Description |
|--------|------|-------------|
| id | UUID (PK) | Unique BTG event ID |
| user_id | UUID (FK → users) | Who broke the glass |
| record_id | UUID (FK → health_records) | Which record was accessed |
| justification | TEXT | Written reason for emergency access |
| ip_address | TEXT | Source IP at time of BTG |
| granted_at | TIMESTAMPTZ | When access was granted |
| expires_at | TIMESTAMPTZ | When temporary access expires |
| reviewed | BOOLEAN | Has admin reviewed this event? |
| reviewed_by | UUID (FK → users) | Admin who reviewed |
| reviewed_at | TIMESTAMPTZ | When review occurred |

### 6.6 Table: `active_sessions` (Optional)

| Column | Type | Description |
|--------|------|-------------|
| id | UUID (PK) | Session ID |
| user_id | UUID (FK → users) | Logged-in user |
| fingerprint_hash | TEXT | SHA-256 session fingerprint |
| ip_address | TEXT | Login IP |
| user_agent | TEXT | Login browser |
| created_at | TIMESTAMPTZ | Session start |
| last_active | TIMESTAMPTZ | Last request time |
| is_active | BOOLEAN | Whether session is still valid |

---

## 7. Project File Structure

```
Secure_Electronic_Health_Record_System/
│
├── backend/
│   ├── app.py                    # Flask app factory + session fingerprint middleware
│   ├── config.py                 # Configuration (env vars, FIELD_ACCESS_MATRIX, roles)
│   ├── auth.py                   # Authentication, session mgmt, RBAC decorators, lockout
│   ├── encryption.py             # AES-256-CBC encrypt/decrypt with unique IVs
│   ├── security.py               # Audit logging (hash-chained) + suspicious detection
│   ├── models.py                 # Supabase CRUD models with FLAC + signature integration
│   ├── routes.py                 # All Flask route blueprints
│   ├── utils.py                  # Password validation (NIST), input sanitization, helpers
│   ├── integrity.py              # Hash chain computation and verification
│   ├── honeypot.py               # Canary record management and alert triggers
│   ├── session_security.py       # Session fingerprinting and hijack detection
│   ├── field_access.py           # Field-level access control logic
│   ├── signatures.py             # RSA-2048 digital signature generation/verification
│   ├── emergency_access.py       # Break-the-Glass protocol
│   ├── seed.py                   # Database seeder (demo users + canary records)
│   ├── supabase_schema.sql       # Complete database schema (all tables)
│   ├── requirements.txt          # Python dependencies
│   ├── .env.example              # Environment variable template
│   ├── .gitignore                # Prevents .env from being committed
│   └── __init__.py               # Package marker
│
├── frontend/
│   ├── templates/
│   │   ├── index.html                    # Landing page
│   │   ├── login.html                    # Secure login
│   │   ├── register.html                 # User registration (admin)
│   │   ├── admin_dashboard.html          # Admin system overview
│   │   ├── doctor_dashboard.html         # Doctor clinical portal
│   │   ├── nurse_dashboard.html          # Nurse ward dashboard
│   │   ├── lab_dashboard.html            # Lab Technician workspace
│   │   ├── patient_dashboard.html        # Patient health portal
│   │   ├── records.html                  # Health records list
│   │   ├── new_record.html              # Create health record
│   │   ├── users.html                    # User management
│   │   ├── audit_logs.html              # Audit log viewer
│   │   ├── audit_integrity.html          # Hash chain verification page
│   │   ├── suspicious.html              # Suspicious activity monitor
│   │   ├── encryption_proof.html         # Encryption transparency demo
│   │   ├── signature_verification.html   # Digital signature proof
│   │   ├── break_the_glass.html          # BTG emergency access form
│   │   ├── btg_review.html             # Admin BTG review queue
│   │   ├── lab_submit.html              # Lab result submission
│   │   └── error.html                   # Error pages (403, 404, 500)
│   └── static/
│       ├── css/vitalis.css               # Design system stylesheet
│       └── js/vitalis.js                 # Shared JavaScript utilities
│
├── SecureEHR_MVP_Specification.md        # This document
└── README.md                             # Project readme
```

---

## 8. Technology Stack

| Layer | Technology | Purpose |
|-------|-----------|---------|
| **Backend Framework** | Python 3 + Flask 3.1 | Web application server |
| **Database** | Supabase (hosted PostgreSQL) | Data storage via REST API |
| **DB Interface** | Supabase Python SDK | Query builder (no raw SQL) |
| **Authentication** | Bcrypt + Flask Sessions | Password hashing + session cookies |
| **Symmetric Encryption** | AES-256-CBC (`cryptography` lib) | Health record field encryption |
| **Asymmetric Crypto** | RSA-2048 (`cryptography` lib) | Digital signatures |
| **Hash Functions** | SHA-256 (`hashlib`) | Audit chain + session fingerprinting |
| **Token Auth** | PyJWT | JWT token handling |
| **Frontend** | HTML5 + Tailwind CSS (CDN) | Responsive UI framework |
| **Icons** | Material Symbols Outlined | Icon system |
| **Typography** | Google Fonts (Inter) | Clinical-grade legibility |
| **Templating** | Jinja2 | Dynamic HTML rendering |
| **Production Server** | Gunicorn | WSGI server |
| **CORS** | Flask-CORS | Cross-origin request handling |
| **Environment** | python-dotenv | Secure config management |

---

## 9. Software Engineering Principles

| Principle | Implementation |
|-----------|--------------|
| **DRY** | Shared `vitalis.css`/`vitalis.js` across all pages; `encrypt()`/`decrypt()` defined once; FLAC matrix in single config |
| **KISS** | Each module has one responsibility — `integrity.py` does only hash chains, `honeypot.py` does only canary logic |
| **Separation of Concerns** | 14 backend modules each handling a distinct domain |
| **Least Privilege** | 5-role RBAC + field-level filtering = maximum restriction |
| **Defense in Depth** | 6 independent layers — compromise of one doesn't compromise others |
| **Fail Securely** | Failed auth → locked; stolen session → killed; tampered log → detected |
| **Zero Trust** | Session fingerprint verified on every single request |
| **Immutability** | Audit logs hash-chained; signed lab results cannot be modified |

---

## 10. Non-Functional Requirements

| Requirement | Description |
|-------------|-------------|
| **Security** | 6-layer defense: encryption, RBAC, FLAC, signatures, session fingerprinting, honeypots |
| **Usability** | Clean, medical-grade UI with Tailwind CSS — intuitive navigation per role |
| **Maintainability** | Modular architecture — each security feature in its own file |
| **Scalability** | Supabase (hosted PostgreSQL) with indexes on all query paths |
| **Reliability** | Graceful error handling on all routes — no unhandled crashes |
| **Compliance** | HIPAA (minimum necessary, emergency access), NIST (800-63B, 800-92, 800-89) |
| **Portability** | Runs on any OS with Python 3.10+ and internet access (Supabase is cloud) |
| **Auditability** | Every action logged with cryptographic integrity guarantee |

---

## 11. MVP Deliverables Checklist

### Must Have (Core MVP) ✅

- [ ] User login with bcrypt password hashing
- [ ] 5-role RBAC (Admin, Doctor, Nurse, Lab Tech, Patient)
- [ ] AES-256-CBC encryption of all health record fields
- [ ] Create, view, delete health records
- [ ] Lab Technician result submission workflow
- [ ] Audit logging of all actions
- [ ] Admin dashboard with system statistics
- [ ] User management by admin
- [ ] Failed login tracking and account lockout (3 attempts)
- [ ] Admin can unlock locked accounts
- [ ] Password strength enforcement (NIST SP 800-63B)

### Innovative Cybersecurity Features 🔥

- [ ] Hash-chained audit log with integrity verification page
- [ ] Honeypot/canary records with silent alerting
- [ ] Session fingerprinting and automatic hijack detection
- [ ] Field-Level Access Control (FLAC) matrix
- [ ] RSA-2048 digital signatures on health records
- [ ] Lab Tech chain-of-custody signing
- [ ] Break-the-Glass emergency access protocol
- [ ] BTG admin review queue

### Should Have (Defense Quality) 🎯

- [ ] Security dashboard showing failed logins and locked accounts
- [ ] IP address logging on all audit entries
- [ ] Suspicious activity detection (SIEM rules)
- [ ] Graceful error pages (403, 404, 500)
- [ ] Encryption proof/transparency page
- [ ] Signature verification page
- [ ] Input validation and XSS prevention

### Nice to Have (Bonus) ⭐

- [ ] Search/filter records by patient name
- [ ] Export audit logs
- [ ] Active session monitoring
- [ ] Lab workstation IP binding

---

## 12. Defense Demonstration Plan

### 15 Live Demonstrations (~40 minutes)

| # | Demo Title | What to Show Live | Cybersecurity Concept | Time |
|---|-----------|-------------------|----------------------|------|
| 1 | **Role-Based Access Control** | Login as all 5 roles — show different dashboards, navigation, permissions | RBAC, Least Privilege | 3 min |
| 2 | **Brute Force Protection** | Enter wrong password 3 times → account locked → admin unlocks | Authentication hardening | 2 min |
| 3 | **AES-256 Encryption Proof** | Create a record → open Encryption Proof page → show ciphertext vs plaintext, IV, algorithm | Symmetric encryption, CBC mode | 3 min |
| 4 | **Hash Chain Integrity** | Show audit integrity page (all green ✓). Open Supabase SQL editor, tamper with one log entry. Reload → chain breaks at exact entry (red ✗) | Tamper detection, hash chains, blockchain principle | 4 min |
| 5 | **Digital Signature Verification** | Create a record as Doctor → open signature verification page → show RSA signature, public key, "Verified ✓" badge | Asymmetric crypto, non-repudiation | 3 min |
| 6 | **Lab Chain of Custody** | Lab Tech submits results with digital signature → Doctor sees "Verified by Lab" badge on results | Chain of custody, separation of duties | 3 min |
| 7 | **Honeypot Alert** | Login as Doctor, browse records, click a canary record. Login as Admin → show honeypot alert triggered with details | Deception defense, insider threat | 3 min |
| 8 | **Field-Level Access** | View the SAME record as Doctor (full), Nurse (masked diagnosis), Lab Tech (only lab results), Patient (no notes) | ABAC, data minimization, HIPAA | 3 min |
| 9 | **Session Fingerprinting** | Login normally, show stored fingerprint hash. Explain: if someone steals the cookie and uses it from a different browser → session killed | Session hijacking prevention | 3 min |
| 10 | **Break-the-Glass** | Login as Nurse → try restricted record → BTG form appears → enter justification → gain temporary access. Login as Admin → show BTG in review queue | Emergency access, HIPAA compliance | 3 min |
| 11 | **Suspicious Activity** | Show the suspicious activity panel with detected anomalies | SIEM concepts, behavioral detection | 2 min |
| 12 | **Password Policy** | Try registering with "123", "Password1" → show rejection messages. Use strong password → show acceptance with strength meter | NIST SP 800-63B | 2 min |
| 13 | **Comprehensive Audit Trail** | Show full audit log — all prior demo actions captured with severity, IP, timestamps, hash links | Accountability, digital forensics | 2 min |
| 14 | **Authorization Boundary** | As Lab Tech, manually enter `/users` URL → 403. As Patient, try `/audit-logs` → 403 | Authorization bypass testing | 2 min |
| 15 | **Database Encryption** | Open Supabase table view → show `health_records` → all fields contain Base64 ciphertext, not plaintext | Data protection at rest | 2 min |

**Total demonstration time: ~40 minutes** — fits comfortably in a 60-minute defense with 20 minutes for Q&A.

### Defense Q&A Preparation

Examiners will likely ask about:

| Likely Question | Prepared Answer |
|---|---|
| "What if the AES key is compromised?" | All records become readable, but digital signatures still prove authorship — and audit chain shows who accessed what |
| "Can the hash chain be rebuilt after tampering?" | Only if you have the genesis hash AND all original entries. Any gap or modification is detectable |
| "Why not use blockchain directly?" | Blockchain adds distributed consensus overhead. For a single-institution system, a hash chain provides the same integrity guarantee at zero infrastructure cost |
| "What prevents the admin from being the attacker?" | Honeypot alerts, hash chain integrity (admin can't silently erase), and separation of duties (admin can't CREATE records) |
| "How does Break-the-Glass prevent abuse?" | Every BTG event is logged at critical severity, requires written justification, and goes to a review queue. Accountability replaces prevention |

---

## 13. References

| Standard | Relevance |
|----------|-----------|
| NIST SP 800-63B | Digital Identity Guidelines — password policy |
| NIST SP 800-92 | Guide to Computer Security Log Management — audit integrity |
| NIST SP 800-89 | Recommendation for Digital Signature Applications |
| NIST SP 800-162 | Guide to Attribute-Based Access Control (ABAC) |
| NIST Cybersecurity Framework | Identify, Protect, Detect, Respond, Recover |
| OWASP Session Management Cheat Sheet | Session fingerprinting, cookie security |
| OWASP Top 10 (2021) | A01:Broken Access Control, A02:Cryptographic Failures |
| HIPAA 45 CFR 164.312(a)(2)(ii) | Emergency Access Procedure |
| HIPAA 45 CFR 164.502(b) | Minimum Necessary Rule |
| MITRE ATT&CK T1530 | Data from Cloud Storage (insider threat) |
| CAP/CLIA Regulations | Clinical laboratory chain of custody |

---

*Document prepared for FICT Final Year Project Defense — The ICT University*  
*Version 3.0 — May 2026*  
*Security-First Architecture with 6 Innovative Cybersecurity Mechanisms*
