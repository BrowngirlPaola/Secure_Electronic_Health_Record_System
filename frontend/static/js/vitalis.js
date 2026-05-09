/**
 * Vitalis EHR — Shared JavaScript Utilities
 * Design Language: Clinical Precision & Tonal Depth
 * Architecture: KISS & DRY principles
 */

'use strict';

/* ============================================================
   1. URL Error Params → Flash Alerts
   ============================================================ */
(function initAlerts() {
  const params = new URLSearchParams(window.location.search);
  const alerts = {
    'error':   'alert-invalid',
    'locked':  'alert-locked',
    'success': 'alert-success',
  };
  Object.entries(alerts).forEach(([param, id]) => {
    if (params.get(param) === '1') {
      const el = document.getElementById(id);
      if (el) el.classList.add('show');
    }
  });
})();

/* ============================================================
   2. Password Toggle (show/hide)
   ============================================================ */
function initPasswordToggle(buttonId = 'togglePassword', inputId = 'passwordInput', iconId = 'eyeIcon') {
  const btn   = document.getElementById(buttonId);
  const input = document.getElementById(inputId);
  const icon  = document.getElementById(iconId);
  if (!btn || !input || !icon) return;

  btn.addEventListener('click', () => {
    const isPassword = input.type === 'password';
    input.type = isPassword ? 'text' : 'password';
    icon.textContent = isPassword ? 'visibility_off' : 'visibility';
    btn.setAttribute('aria-label', isPassword ? 'Hide password' : 'Show password');
  });
}

/* ============================================================
   3. Password Strength Meter (NIST SP 800-63B)
   ============================================================ */
function checkPasswordStrength(password) {
  let score = 0;
  const checks = {
    length:    password.length >= 8,
    uppercase: /[A-Z]/.test(password),
    lowercase: /[a-z]/.test(password),
    number:    /[0-9]/.test(password),
    special:   /[!@#$%^&*()_+\-=\[\]{};':"\\|,.<>\/?]/.test(password),
  };
  score = Object.values(checks).filter(Boolean).length;
  const label  = score <= 2 ? 'Weak' : score <= 3 ? 'Fair' : score === 4 ? 'Good' : 'Strong';
  const cssKey = score <= 2 ? 'weak' : score <= 3 ? 'medium' : 'strong';
  return { score, checks, label, cssKey };
}

function initStrengthMeter(inputId = 'passwordInput', barId = 'strengthBar', labelId = 'strengthLabel') {
  const input = document.getElementById(inputId);
  const bar   = document.getElementById(barId);
  const label = document.getElementById(labelId);
  if (!input) return;

  const reqItems = {
    length:    document.getElementById('req-length'),
    uppercase: document.getElementById('req-upper'),
    lowercase: document.getElementById('req-lower'),
    number:    document.getElementById('req-number'),
    special:   document.getElementById('req-special'),
  };

  input.addEventListener('input', () => {
    const { checks, label: lbl, cssKey } = checkPasswordStrength(input.value);
    if (bar) { bar.className = 'strength-bar ' + cssKey; }
    if (label) { label.textContent = lbl; label.className = 'text-xs font-bold ' + (cssKey === 'strong' ? 'text-tertiary' : cssKey === 'medium' ? 'text-amber-600' : 'text-error'); }
    Object.entries(reqItems).forEach(([key, el]) => {
      if (!el) return;
      const met = checks[key];
      el.classList.toggle('met', met);
      el.classList.toggle('text-on-tertiary-fixed-variant', met);
      el.classList.toggle('text-secondary', !met);
      const icon = el.querySelector('.req-icon');
      if (icon) icon.textContent = met ? 'check_circle' : 'radio_button_unchecked';
    });
  });
}

/* ============================================================
   4. Login Form Validation
   ============================================================ */
function initLoginForm(formId = 'loginForm') {
  const form = document.getElementById(formId);
  if (!form) return;

  form.addEventListener('submit', function (e) {
    e.preventDefault();
    let valid = true;
    const email    = document.getElementById('emailInput');
    const password = document.getElementById('passwordInput');
    const emailErr = document.getElementById('emailError');
    const passErr  = document.getElementById('passwordError');

    if (emailErr) emailErr.classList.add('hidden');
    if (passErr)  passErr.classList.add('hidden');

    if (!email || !email.value || !email.value.includes('@')) {
      if (emailErr) emailErr.classList.remove('hidden');
      if (email) email.focus();
      valid = false;
    }
    if (!password || !password.value) {
      if (passErr) passErr.classList.remove('hidden');
      if (valid && password) password.focus();
      valid = false;
    }
    if (valid) this.submit();
  });
}

/* ============================================================
   5. Record Form Validation (new_record.html)
   ============================================================ */
function initRecordForm(formId = 'recordForm') {
  const form = document.getElementById(formId);
  if (!form) return;

  // Live date update in preview
  const dateEl = document.getElementById('prev-date');
  if (dateEl) dateEl.textContent = new Date().toLocaleDateString('en-CA');

  // Patient select preview
  const sel = document.getElementById('patientSelect');
  if (sel) sel.addEventListener('change', () => {
    const prev = document.getElementById('prev-patient');
    if (prev) prev.textContent = sel.value || '—';
  });

  form.addEventListener('submit', function (e) {
    e.preventDefault();
    const patient   = document.getElementById('patientSelect');
    const diagnosis = document.getElementById('diagnosis');
    const patErr    = document.getElementById('patientErr');
    const diagErr   = document.getElementById('diagErr');

    let valid = true;
    if (patErr)  patErr.classList.add('hidden');
    if (diagErr) diagErr.classList.add('hidden');

    if (!patient?.value) {
      if (patErr) patErr.classList.remove('hidden');
      valid = false;
    }
    if (!diagnosis?.value.trim()) {
      if (diagErr) diagErr.classList.remove('hidden');
      valid = false;
    }
    if (valid) this.submit();
  });
}

/* ============================================================
   6. Register Form — Role Card Selection
   ============================================================ */
function initRoleCards() {
  const cards = document.querySelectorAll('.role-card');
  const input = document.getElementById('roleInput');
  cards.forEach(card => {
    card.addEventListener('click', () => {
      cards.forEach(c => c.classList.remove('selected'));
      card.classList.add('selected');
      const role = card.dataset.role;
      if (input) input.value = role;
    });
    card.addEventListener('keydown', e => {
      if (e.key === 'Enter' || e.key === ' ') { e.preventDefault(); card.click(); }
    });
  });
}

/* ============================================================
   7. User Search Filter (users.html)
   ============================================================ */
function filterUsers(query) {
  const input = query !== undefined ? query : (document.getElementById('searchInput')?.value || '');
  const rows  = document.querySelectorAll('[data-user-row]');
  const q     = input.toLowerCase().trim();
  rows.forEach(row => {
    const text = row.textContent.toLowerCase();
    row.style.display = (!q || text.includes(q)) ? '' : 'none';
  });
  // Update visible count
  const countEl = document.getElementById('visibleCount');
  if (countEl) {
    const visible = document.querySelectorAll('[data-user-row]:not([style*="none"])').length;
    countEl.textContent = visible;
  }
}

/* ============================================================
   8. Audit Log Filter (audit_logs.html)
   ============================================================ */
function filterLogs(query) {
  const rows = document.querySelectorAll('[data-log-row]');
  const q    = (query || '').toLowerCase().trim();
  rows.forEach(row => {
    const text = row.textContent.toLowerCase();
    row.style.display = (!q || text.includes(q)) ? '' : 'none';
  });
}

/* ============================================================
   9. Encrypt Preview Animation (encryption_proof.html)
   ============================================================ */
function initEncryptAnimation() {
  const btn = document.getElementById('runProofBtn');
  if (!btn) return;
  btn.addEventListener('click', function () {
    const spinner = document.getElementById('proofSpinner');
    const result  = document.getElementById('proofResult');
    if (spinner) spinner.classList.remove('hidden');
    if (result)  result.classList.add('opacity-50');
    setTimeout(() => {
      if (spinner) spinner.classList.add('hidden');
      if (result)  result.classList.remove('opacity-50');
    }, 800);
  });
}

/* ============================================================
   10. Timestamp Formatter — "X minutes ago"
   ============================================================ */
function timeAgo(dateStr) {
  const now  = new Date();
  const past = new Date(dateStr);
  const diff = Math.floor((now - past) / 1000);
  if (diff < 60)   return `${diff}s ago`;
  if (diff < 3600) return `${Math.floor(diff / 60)}m ago`;
  if (diff < 86400) return `${Math.floor(diff / 3600)}h ago`;
  return `${Math.floor(diff / 86400)}d ago`;
}

function initTimestamps() {
  document.querySelectorAll('[data-timestamp]').forEach(el => {
    el.textContent = timeAgo(el.dataset.timestamp);
    el.title = el.dataset.timestamp; // full date on hover
  });
}

/* ============================================================
   11. Confirm Delete Dialog
   ============================================================ */
function confirmDelete(message = 'Are you sure you want to delete this record? This action cannot be undone.') {
  return window.confirm(message);
}

/* ============================================================
   12. Active Sidebar Link
   ============================================================ */
function initActiveSidebar() {
  const current = window.location.pathname.split('/').pop() || 'index.html';
  document.querySelectorAll('.nav-link').forEach(link => {
    const href = (link.getAttribute('href') || '').split('/').pop();
    if (href === current) {
      link.classList.add('active');
    }
  });
}

/* ============================================================
   13. Toast Notification (lightweight)
   ============================================================ */
function showToast(message, type = 'info', duration = 4000) {
  const colors = {
    info:    'bg-secondary-container text-on-secondary-container',
    success: 'bg-tertiary-fixed text-on-tertiary-fixed-variant',
    error:   'bg-error-container text-on-error-container',
    warning: 'bg-amber-100 text-amber-900',
  };
  const icons = { info: 'info', success: 'check_circle', error: 'error', warning: 'warning' };
  const toast = document.createElement('div');
  toast.className = `fixed bottom-6 right-6 z-[9999] flex items-center gap-3 px-5 py-3 rounded-2xl tonal-shadow text-sm font-medium ${colors[type] || colors.info}`;
  toast.innerHTML = `<span class="material-symbols-outlined text-base" style="font-variation-settings:'FILL' 1;">${icons[type] || 'info'}</span>${message}`;
  document.body.appendChild(toast);
  setTimeout(() => toast.remove(), duration);
}

/* ============================================================
   Auto-init on DOM ready
   ============================================================ */
document.addEventListener('DOMContentLoaded', () => {
  initAlerts();
  initPasswordToggle();
  initStrengthMeter();
  initLoginForm();
  initRecordForm();
  initRoleCards();
  initActiveSidebar();
  initTimestamps();
  initEncryptAnimation();
});
