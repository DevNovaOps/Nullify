/* ══════════════════════════════════════════════════════════════════════
   SETTINGS PAGE — Tab Switching, Password Toggle, Delete Modal
   ══════════════════════════════════════════════════════════════════════ */

document.addEventListener('DOMContentLoaded', () => {

    // ── Tab Switching ──
    const tabs = document.querySelectorAll('.settings-tab');
    const panels = document.querySelectorAll('.settings-panel');

    tabs.forEach(tab => {
        tab.addEventListener('click', (e) => {
            e.preventDefault();
            const target = tab.dataset.tab;

            tabs.forEach(t => t.classList.remove('active'));
            panels.forEach(p => p.classList.remove('active'));

            tab.classList.add('active');
            const panel = document.getElementById('panel-' + target);
            if (panel) panel.classList.add('active');

            // Close mobile sidebar
            const sidebar = document.getElementById('settings-sidebar');
            if (sidebar) sidebar.classList.remove('open');
        });
    });

    // ── Mobile Sidebar Toggle ──
    const mobileToggle = document.querySelector('.settings-mobile-toggle');
    const sidebar = document.getElementById('settings-sidebar');
    const sidebarClose = document.getElementById('settings-sidebar-close');

    if (mobileToggle && sidebar) {
        mobileToggle.addEventListener('click', () => {
            sidebar.classList.toggle('open');
        });
    }

    if (sidebarClose && sidebar) {
        sidebarClose.addEventListener('click', () => {
            sidebar.classList.remove('open');
        });
    }

    // ── Edit Profile Toggle ──
    const editBtn = document.getElementById('edit-profile-btn');
    const cancelBtn = document.getElementById('cancel-edit-btn');
    const viewMode = document.getElementById('profile-view-mode');
    const editMode = document.getElementById('profile-edit-mode');

    if (editBtn && viewMode && editMode) {
        editBtn.addEventListener('click', () => {
            viewMode.classList.add('hidden');
            editMode.classList.remove('hidden');
            editBtn.classList.add('hidden');
        });
    }

    if (cancelBtn && viewMode && editMode && editBtn) {
        cancelBtn.addEventListener('click', () => {
            editMode.classList.add('hidden');
            viewMode.classList.remove('hidden');
            editBtn.classList.remove('hidden');
        });
    }

    // ── Password Visibility Toggle ──
    document.querySelectorAll('.password-eye-btn').forEach(btn => {
        btn.addEventListener('click', () => {
            const targetId = btn.dataset.target;
            const input = document.getElementById(targetId);
            if (!input) return;

            if (input.type === 'password') {
                input.type = 'text';
                btn.innerHTML = '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M17.94 17.94A10.07 10.07 0 0 1 12 20c-7 0-11-8-11-8a18.45 18.45 0 0 1 5.06-5.94M9.9 4.24A9.12 9.12 0 0 1 12 4c7 0 11 8 11 8a18.5 18.5 0 0 1-2.16 3.19m-6.72-1.07a3 3 0 1 1-4.24-4.24"/><line x1="1" y1="1" x2="23" y2="23"/></svg>';
            } else {
                input.type = 'password';
                btn.innerHTML = '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M1 12s4-8 11-8 11 8 11 8-4 8-11 8-11-8-11-8z"/><circle cx="12" cy="12" r="3"/></svg>';
            }
        });
    });

    // ── Password Match Feedback (Security tab) ──
    const newPw = document.getElementById('sec-new-password');
    const confirmPw = document.getElementById('sec-confirm-password');
    const feedback = document.getElementById('sec-password-match-feedback');

    if (newPw && confirmPw && feedback) {
        const check = () => {
            const val1 = newPw.value;
            const val2 = confirmPw.value;

            if (!val2) {
                feedback.textContent = '';
                feedback.className = 'password-match-feedback';
                return;
            }

            if (val1 === val2) {
                feedback.innerHTML = '✓ Passwords match';
                feedback.className = 'password-match-feedback match';
            } else {
                feedback.innerHTML = '✗ Passwords do not match';
                feedback.className = 'password-match-feedback mismatch';
            }
        };

        newPw.addEventListener('input', check);
        confirmPw.addEventListener('input', check);
    }

    // ── Delete Account Modal ──
    const deleteBtn = document.getElementById('delete-account-btn');
    const modal = document.getElementById('delete-modal-overlay');
    const cancelDelete = document.getElementById('cancel-delete-btn');

    if (deleteBtn && modal) {
        deleteBtn.addEventListener('click', () => {
            modal.classList.add('open');
        });
    }

    if (cancelDelete && modal) {
        cancelDelete.addEventListener('click', () => {
            modal.classList.remove('open');
        });
    }

    if (modal) {
        modal.addEventListener('click', (e) => {
            if (e.target === modal) {
                modal.classList.remove('open');
            }
        });

        document.addEventListener('keydown', (e) => {
            if (e.key === 'Escape' && modal.classList.contains('open')) {
                modal.classList.remove('open');
            }
        });
    }
});
