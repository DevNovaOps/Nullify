/**
 * Auth Pages — Password validation, password match, OTP input handling
 * Nullify SecureAuth™
 */

document.addEventListener('DOMContentLoaded', () => {

    // ═══════════════════════════════════════════════════════════════
    //  PASSWORD REQUIREMENTS CHECKER
    // ═══════════════════════════════════════════════════════════════

    const passwordInputs = document.querySelectorAll('#login-password, #register-password, #new-password');

    passwordInputs.forEach(input => {
        const reqContainer = input.closest('.form-group')?.querySelector('.password-requirements');
        if (!reqContainer) return;

        input.addEventListener('input', () => {
            const val = input.value;
            const reqs = reqContainer.querySelectorAll('.req-item');

            reqs.forEach(req => {
                const type = req.dataset.req;
                let met = false;

                switch (type) {
                    case 'length':
                        met = val.length >= 8;
                        break;
                    case 'uppercase':
                        met = /[A-Z]/.test(val);
                        break;
                    case 'number':
                        met = /[0-9]/.test(val);
                        break;
                    case 'special':
                        met = /[!@#$%^&*()_+\-=\[\]{};':"\\|,.<>\/?]/.test(val);
                        break;
                }

                req.classList.toggle('met', met);
            });
        });

        // Also trigger on focus to show initial state
        input.addEventListener('focus', () => {
            reqContainer.style.opacity = '1';
        });
    });


    // ═══════════════════════════════════════════════════════════════
    //  REAL-TIME PASSWORD MATCH CHECKER (Register & Reset pages)
    // ═══════════════════════════════════════════════════════════════

    const registerPassword = document.getElementById('register-password');
    const registerConfirm = document.getElementById('register-confirm');
    const matchFeedback = document.getElementById('password-match-feedback');

    if (registerPassword && registerConfirm && matchFeedback) {
        const checkMatch = () => {
            const pw = registerPassword.value;
            const cpw = registerConfirm.value;

            if (cpw.length === 0) {
                matchFeedback.textContent = '';
                matchFeedback.className = 'password-match-feedback';
                return;
            }

            if (pw === cpw) {
                matchFeedback.innerHTML = `
                    <svg class="match-icon" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.5" stroke-linecap="round" stroke-linejoin="round">
                        <polyline points="20,6 9,17 4,12"/>
                    </svg>
                    Passwords match
                `;
                matchFeedback.className = 'password-match-feedback match';
            } else {
                matchFeedback.innerHTML = `
                    <svg class="match-icon" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.5" stroke-linecap="round" stroke-linejoin="round">
                        <line x1="18" y1="6" x2="6" y2="18"/>
                        <line x1="6" y1="6" x2="18" y2="18"/>
                    </svg>
                    Passwords do not match
                `;
                matchFeedback.className = 'password-match-feedback mismatch';
            }
        };

        registerConfirm.addEventListener('input', checkMatch);
        registerPassword.addEventListener('input', checkMatch);
    }

    // Also handle set-new-password page match checking
    const newPassword = document.getElementById('new-password');
    const confirmNewPassword = document.getElementById('confirm-new-password');
    const newMatchFeedback = document.getElementById('new-password-match-feedback');

    if (newPassword && confirmNewPassword && newMatchFeedback) {
        const checkNewMatch = () => {
            const pw = newPassword.value;
            const cpw = confirmNewPassword.value;

            if (cpw.length === 0) {
                newMatchFeedback.textContent = '';
                newMatchFeedback.className = 'password-match-feedback';
                return;
            }

            if (pw === cpw) {
                newMatchFeedback.innerHTML = `
                    <svg class="match-icon" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.5" stroke-linecap="round" stroke-linejoin="round">
                        <polyline points="20,6 9,17 4,12"/>
                    </svg>
                    Passwords match
                `;
                newMatchFeedback.className = 'password-match-feedback match';
            } else {
                newMatchFeedback.innerHTML = `
                    <svg class="match-icon" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.5" stroke-linecap="round" stroke-linejoin="round">
                        <line x1="18" y1="6" x2="6" y2="18"/>
                        <line x1="6" y1="6" x2="18" y2="18"/>
                    </svg>
                    Passwords do not match
                `;
                newMatchFeedback.className = 'password-match-feedback mismatch';
            }
        };

        confirmNewPassword.addEventListener('input', checkNewMatch);
        newPassword.addEventListener('input', checkNewMatch);
    }


    // ═══════════════════════════════════════════════════════════════
    //  OTP INPUT — Auto-advance, paste handling, backspace
    // ═══════════════════════════════════════════════════════════════

    const otpGroup = document.getElementById('otp-input-group');

    if (otpGroup) {
        const otpInputs = otpGroup.querySelectorAll('.otp-input');

        otpInputs.forEach((input, index) => {
            // Auto-advance on input
            input.addEventListener('input', (e) => {
                const val = e.target.value;

                // Only allow digits
                e.target.value = val.replace(/[^0-9]/g, '');

                if (e.target.value.length === 1) {
                    input.classList.add('filled');
                    // Move to next input
                    if (index < otpInputs.length - 1) {
                        otpInputs[index + 1].focus();
                    }
                } else {
                    input.classList.remove('filled');
                }
            });

            // Backspace — go to previous
            input.addEventListener('keydown', (e) => {
                if (e.key === 'Backspace' && !input.value && index > 0) {
                    otpInputs[index - 1].focus();
                    otpInputs[index - 1].value = '';
                    otpInputs[index - 1].classList.remove('filled');
                }
                // Arrow keys navigation
                if (e.key === 'ArrowLeft' && index > 0) {
                    otpInputs[index - 1].focus();
                }
                if (e.key === 'ArrowRight' && index < otpInputs.length - 1) {
                    otpInputs[index + 1].focus();
                }
            });

            // Select all on focus
            input.addEventListener('focus', () => {
                input.select();
            });
        });

        // Handle paste — distribute across all boxes
        otpInputs[0].addEventListener('paste', (e) => {
            e.preventDefault();
            const pastedData = (e.clipboardData || window.clipboardData).getData('text').trim();
            const digits = pastedData.replace(/[^0-9]/g, '').slice(0, 6);

            digits.split('').forEach((digit, i) => {
                if (otpInputs[i]) {
                    otpInputs[i].value = digit;
                    otpInputs[i].classList.add('filled');
                }
            });

            // Focus last filled or next empty
            const focusIndex = Math.min(digits.length, otpInputs.length - 1);
            otpInputs[focusIndex].focus();
        });

        // Auto-focus first input
        otpInputs[0].focus();
    }


    // ═══════════════════════════════════════════════════════════════
    //  FORM SUBMISSION — loading state
    // ═══════════════════════════════════════════════════════════════

    const authForms = document.querySelectorAll('#login-form, #register-form, #forgot-form, #otp-form, #new-password-form');

    authForms.forEach(form => {
        form.addEventListener('submit', () => {
            const btn = form.querySelector('.auth-submit-btn');
            if (btn) {
                btn.disabled = true;
                btn.style.opacity = '0.7';
                btn.innerHTML = `
                    <svg width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" class="spinner-svg">
                        <circle cx="12" cy="12" r="10" stroke-dasharray="31.4 31.4" stroke-dashoffset="0">
                            <animateTransform attributeName="transform" type="rotate" from="0 12 12" to="360 12 12" dur="1s" repeatCount="indefinite"/>
                        </circle>
                    </svg>
                    Processing...
                `;
            }
        });
    });

});
