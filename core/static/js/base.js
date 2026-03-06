/* ══════════════════════════════════════════════════════════════════════
   NULLIFY — Base JavaScript (Theme Manager + Utilities)
   ══════════════════════════════════════════════════════════════════════ */

const ThemeManager = {
    init() {
        const saved = localStorage.getItem('nullify-theme') || 'system';
        this.apply(saved);
        this.bindEvents();
    },

    apply(theme) {
        document.documentElement.setAttribute('data-theme', theme);
        localStorage.setItem('nullify-theme', theme);

        document.querySelectorAll('.theme-toggle-pill button').forEach(btn => {
            btn.classList.toggle('active', btn.dataset.theme === theme);
        });
    },

    bindEvents() {
        document.querySelectorAll('.theme-toggle-pill button').forEach(btn => {
            btn.addEventListener('click', (e) => {
                e.preventDefault();
                this.apply(btn.dataset.theme);
            });
        });
    }
};

document.addEventListener('DOMContentLoaded', () => {
    ThemeManager.init();

    // Auto-dismiss alerts
    document.querySelectorAll('.alert').forEach(alert => {
        setTimeout(() => {
            alert.style.opacity = '0';
            alert.style.transform = 'translateY(-10px)';
            setTimeout(() => alert.remove(), 300);
        }, 5000);
    });
});
