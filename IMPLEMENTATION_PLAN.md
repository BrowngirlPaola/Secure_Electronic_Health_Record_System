# Vitalis EHR — Implementation Plan & Progress Tracker

**Student:** Yong Paola Nabain
**Supervisor:** Dr. Fosso
**Started:** 2026-05-09
**Last Updated:** 2026-05-10

---

## Current Status: Phase 1 COMPLETE — Moving to Phase 2 (Dynamic Admin Dashboard)

---

## Phase 1: Fix RBAC Routing, Doctor-Patient Assignment & Template Boundaries (COMPLETE)

### Problem A — Routing Violations
Multiple routing and template issues violate the RBAC matrix defined in the specification (Section 3.1). Roles can see navigation links and access pages they shouldn't, and some pages show the wrong sidebar for the logged-in user.

### Problem B — Doctor-Patient Assignment (NEW)
Doctors currently see ALL patient records in the system. Per business requirement, **every patient must be assigned to a doctor**, and doctors may **only view records of their assigned patients**. This requires:
- A new `doctor_patient_assignments` junction table (many-to-many: a patient can have multiple doctors, a doctor has multiple patients)
- Admin UI to assign/unassign patients to doctors
- Doctor record access filtered to assigned patients only
- Record creation restricted to assigned patients only

### Issues Identified

| # | Issue | Spec Rule | Current Bug | Fix |
|---|-------|-----------|-------------|-----|
| 1 | `/records` shows ALL records to Nurse | F3.8: Nurse only sees self-created | Nurse sees every record in the system | Filter by `created_by == user.id` for nurse |
| 2 | `/records` shows ALL records to Doctor | NEW: Doctor sees only assigned patients | Doctor sees every patient's records | Filter by doctor-patient assignment |
| 3 | `/records/new` allows Admin | F3.10: Admin can delete but NOT create | `@role_required("admin", "doctor", "nurse")` | Remove `"admin"` from decorator |
| 4 | `/records/new` — Doctor can create for ANY patient | NEW: Only assigned patients | Patient dropdown shows all patients | Filter dropdown to assigned patients |
| 5 | `/encryption-proof` open to ALL roles | Spec 3.1: Only Admin and Doctor | `@login_required` (any role) | Change to `@role_required("admin", "doctor")` |
| 6 | All shared templates show Admin sidebar | F2.3: Nav shows only permitted links per role | Hardcoded admin nav in records, users, etc. | Create shared sidebar partial |
| 7 | No doctor-patient assignment table | NEW requirement | Table doesn't exist | Create `doctor_patient_assignments` table |
| 8 | No admin UI to assign patients | NEW requirement | No assignment page | Create assignment page + route |

### Tasks

**1A — Database: Doctor-Patient Assignments**
- [x] **1A.1** Create SQL for `doctor_patient_assignments` table (doctor_id, patient_id, assigned_at, assigned_by)
- [x] **1A.2** Run SQL in Supabase
- [x] **1A.3** Update `supabase_schema.sql` with the new table
- [x] **1A.4** Add `AssignmentModel` to `models.py` with: `get_by_doctor()`, `get_by_patient()`, `assign()`, `unassign()`, `get_all()`
- [x] **1A.5** Update `seed.py` to assign the demo patient (Jane Doe) to the demo doctor (Dr. Smith)

**1B — Route Fixes**
- [x] **1B.1** Fix `/records/new` — remove `"admin"` from `@role_required`, filter patient dropdown to assigned patients (for doctor) or all patients (for nurse)
- [x] **1B.2** Fix `/records` list — Doctor sees only assigned patients' records; Nurse sees only self-created records; Admin sees all
- [x] **1B.3** Fix `/records/<id>` view — Doctor can only view assigned patients' records (or BTG); Nurse can only view self-created (or BTG)
- [x] **1B.4** Fix `/encryption-proof` — change to `@role_required("admin", "doctor")`
- [x] **1B.5** Add admin route: `/admin/assignments` — view/manage doctor-patient assignments
- [x] **1B.6** Add admin route: `/admin/assignments/assign` (POST) — assign patient to doctor
- [x] **1B.7** Add admin route: `/admin/assignments/<id>/unassign` (POST) — remove assignment

**1C — Sidebar & Templates**
- [x] **1C.1** Add Assignments nav link to all admin sidebar templates (11 templates)
- [x] **1C.2** Add `assignments.html` template for admin assignment management
- [x] **1C.3** Fix doctor dashboard to show only assigned patients' records
- [x] **1C.4** Fix nurse dashboard to show only self-created records

**1D — Testing**
- [x] **1D.1** Test: Admin sees all records, can delete but NOT create (403 on /records/new)
- [x] **1D.2** Test: Doctor sees ONLY assigned patients' records, can create for assigned patients only
- [x] **1D.3** Test: Nurse sees ONLY self-created records, can create for any patient
- [x] **1D.4** Test: Lab Tech sees ONLY pending queue, cannot access /records (403)
- [x] **1D.5** Test: Patient sees ONLY own records, cannot access /records (403)
- [x] **1D.6** Test: Every unauthorized route returns 403
- [x] **1D.7** Test: Sidebar shows Assignments link for admin role

**1E — Commit**
- [ ] **1E.1** Commit all Phase 1 changes with descriptive message
- [ ] **1E.2** Push to GitHub
- [ ] **1E.3** Update this plan — mark Phase 1 complete

### Acceptance Criteria
- Admin: Dashboard, Users, Register, Records (view all/delete only — NO create), Assignments, Audit Logs, Integrity, Suspicious, BTG Review, Encryption Proof
- Doctor: Dashboard, Records (view ONLY assigned patients + create for assigned patients), New Record, Encryption Proof, Verify Signature
- Nurse: Dashboard, Records (ONLY self-created + BTG), New Record (any patient)
- Lab Tech: Dashboard (pending queue only), Submit Results
- Patient: Dashboard (own records only)
- Every other combination returns 403
- Sidebar shows ONLY the links for the logged-in role
- Every patient assigned to at least one doctor before their records are accessible

### Updated Permission Matrix (with Doctor-Patient Assignment)

| Permission                          | Admin | Doctor | Nurse | Lab Tech | Patient |
|-------------------------------------|:-----:|:------:|:-----:|:--------:|:-------:|
| View all records                    |  YES  |   NO   |  NO   |    NO    |   NO    |
| View assigned patients' records     |  N/A  |  YES   |  N/A  |   N/A    |  N/A    |
| View self-created records only      |  N/A  |  N/A   |  YES  |   N/A    |  N/A    |
| View own records only               |  N/A  |  N/A   |  N/A  |   N/A    |  YES    |
| Create records (assigned patients)  |  NO   |  YES   |  N/A  |    NO    |   NO    |
| Create records (any patient)        |  NO   |  N/A   |  YES  |    NO    |   NO    |
| Delete records                      |  YES  |   NO   |  NO   |    NO    |   NO    |
| Assign patients to doctors          |  YES  |   NO   |  NO   |    NO    |   NO    |
| Submit lab results                  |  NO   |   NO   |  NO   |   YES    |   NO    |
| View encryption proof               |  YES  |  YES   |  NO   |    NO    |   NO    |

---

## Phase 2: Dynamic Admin Dashboard (Data-Driven)

### Problem
`admin_dashboard.html` currently has hardcoded static data (24 users, 187 records, etc.) instead of using the Jinja variables already passed by the route (`total_users`, `role_counts`, `locked_accounts`, `recent_logs`, `honeypot_alerts`, `btg_stats`, `chain_status`).

### Tasks
- [ ] **2.1** Replace all hardcoded stats with `{{ total_users }}`, `{{ role_counts.doctor }}`, etc.
- [ ] **2.2** Replace hardcoded locked accounts section with loop over `{{ locked_accounts }}`
- [ ] **2.3** Replace hardcoded security events table with loop over `{{ recent_logs }}`
- [ ] **2.4** Add honeypot alerts panel using `{{ honeypot_alerts }}`
- [ ] **2.5** Add hash chain status indicator using `{{ chain_status }}`
- [ ] **2.6** Add BTG pending count from `{{ btg_stats }}`
- [ ] **2.7** Add doctor-patient assignment stats
- [ ] **2.8** Update Security Status sidebar with real feature status
- [ ] **2.9** Test with real data — verify all stats update correctly
- [ ] **2.10** Commit & push

---

## Phase 3: Dynamic Doctor, Nurse & Patient Dashboards

### Tasks
- [ ] **3.1** `doctor_dashboard.html` — Show ONLY assigned patients and their records
- [ ] **3.2** `nurse_dashboard.html` — Show ONLY records created by this nurse
- [ ] **3.3** `patient_dashboard.html` — Show own health data with FLAC applied
- [ ] **3.4** Make each record row clickable -> links to `/records/<id>`
- [ ] **3.5** Doctor dashboard shows "My Patients" panel (assigned patients list)
- [ ] **3.6** Test FLAC: same record viewed as Doctor (full) vs Nurse (masked diagnosis) vs Patient (no notes)
- [ ] **3.7** Commit & push

---

## Phase 4: Records List & View Record (Dynamic)

### Tasks
- [ ] **4.1** `records.html` — Replace hardcoded table with loop over `{{ records }}`
- [ ] **4.2** Ensure records are correctly filtered per role before reaching template
- [ ] **4.3** `view_record.html` — Verify FLAC badges render correctly
- [ ] **4.4** Test honeypot record access triggers silent alert
- [ ] **4.5** Test Break-the-Glass flow end-to-end (nurse accesses non-created record)
- [ ] **4.6** Commit & push

---

## Phase 5: User Management & Registration (Dynamic)

### Tasks
- [ ] **5.1** `users.html` — Replace hardcoded user table with loop over `{{ users }}`
- [ ] **5.2** Add real delete/unlock buttons with form POST actions
- [ ] **5.3** `register.html` — Ensure form POSTs to correct route, 5 role options, password validation
- [ ] **5.4** `assignments.html` — Admin assigns patients to doctors (dropdown + table)
- [ ] **5.5** Test: create user -> appears in list -> login works -> RSA keys generated
- [ ] **5.6** Test: assign patient to doctor -> doctor sees patient in dashboard
- [ ] **5.7** Test: delete user -> removed from list
- [ ] **5.8** Commit & push

---

## Phase 6: Audit Logs & Suspicious Activity (Dynamic)

### Tasks
- [ ] **6.1** `audit_logs.html` — Replace hardcoded table with loop over `{{ logs }}`
- [ ] **6.2** Show severity badges (info=blue, warning=amber, critical=red)
- [ ] **6.3** Show hash chain link indicators
- [ ] **6.4** `suspicious.html` — Replace with loop over `{{ activities }}`
- [ ] **6.5** Test: perform actions -> verify they appear in audit log with correct severity
- [ ] **6.6** Commit & push

---

## Phase 7: Security Feature Pages (Verify & Polish)

### Tasks
- [ ] **7.1** `audit_integrity.html` — Verify chain valid/broken display works
- [ ] **7.2** `signature_verification.html` — Verify valid/invalid display works
- [ ] **7.3** `break_the_glass.html` — Test BTG form submission end-to-end
- [ ] **7.4** `btg_review.html` — Test mark-as-reviewed works
- [ ] **7.5** `lab_submit.html` — Test lab result submission + digital signing
- [ ] **7.6** `encryption_proof.html` — Make dynamic if still hardcoded
- [ ] **7.7** Full end-to-end security feature test
- [ ] **7.8** Commit & push

---

## Phase 8: Login & Landing Page Polish

### Tasks
- [ ] **8.1** `login.html` — Ensure error/locked flash messages display correctly
- [ ] **8.2** `index.html` — Landing page with project description and login button
- [ ] **8.3** `error.html` — Verify 403/404/500 pages render correctly with back links
- [ ] **8.4** Commit & push

---

## Phase 9: Full Integration Testing & Defense Prep

### Tasks
- [ ] **9.1** Run through all 15 defense demonstrations from the spec (Section 12)
- [ ] **9.2** Fix any issues found during demo rehearsal
- [ ] **9.3** Verify all 6 innovative features work end-to-end
- [ ] **9.4** Test doctor-patient assignment across all demo scenarios
- [ ] **9.5** Final commit & push
- [ ] **9.6** Update this plan with COMPLETED status on all items

---

## Git Commit Log

| Date | Phase | Commit Message | Status |
|------|-------|----------------|--------|
| 2026-05-09 | Setup | Initial backend modules, schema, seed, 21 templates | Done (uncommitted) |
| 2026-05-10 | Phase 1 | Fix RBAC routing + doctor-patient assignments + admin assignment UI | Complete |
| | Phase 2 | Dynamic admin dashboard with real data | Pending |
| | Phase 3 | Dynamic role dashboards (doctor, nurse, patient) | Pending |
| | Phase 4 | Dynamic records list & view with FLAC | Pending |
| | Phase 5 | Dynamic user management + assignment UI | Pending |
| | Phase 6 | Dynamic audit logs & suspicious activity | Pending |
| | Phase 7 | Verify & polish all 6 security features | Pending |
| | Phase 8 | Login & landing page polish | Pending |
| | Phase 9 | Full integration testing & defense prep | Pending |

---

## Architecture Decision: Doctor-Patient Assignments

**Why a junction table (not a column)?**
- A patient can have multiple doctors (primary care, specialist, surgeon)
- A doctor handles multiple patients
- This is a many-to-many relationship
- A junction table also tracks WHO assigned and WHEN — audit trail

**Table: `doctor_patient_assignments`**
| Column | Type | Description |
|--------|------|-------------|
| id | UUID (PK) | Assignment ID |
| doctor_id | UUID (FK -> users) | The assigned doctor |
| patient_id | UUID (FK -> users) | The assigned patient |
| assigned_at | TIMESTAMPTZ | When assignment was created |
| assigned_by | UUID (FK -> users) | Admin who made the assignment |

**Impact on existing routes:**
- `dashboard_bp.doctor_dashboard` — query assignments table to get patient list, then fetch their records
- `records_bp.list_records` (doctor) — filter to assigned patients' records
- `records_bp.new_record` (doctor) — patient dropdown shows only assigned patients
- `records_bp.view_record` (doctor) — verify patient is assigned before allowing access
- New admin routes for assignment management

---

## Notes
- Each phase must be fully tested before committing
- Every commit message references what was fixed/added
- The spec (SecureEHR_MVP_Specification.md Section 3.1) is the source of truth for permissions
- Doctor-patient assignment is an additional constraint ON TOP of the spec's RBAC
- No phase should be skipped — they build on each other
- After each phase: update this plan, commit, push
