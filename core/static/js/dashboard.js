/* ══════════════════════════════════════════════════════════════════════
   DASHBOARD — JavaScript (Sidebar, Upload, Risk Meter, Scan)
   Charts are now server-side via matplotlib, no Chart.js needed.
   ══════════════════════════════════════════════════════════════════════ */

// ── Mobile Sidebar ───────────────────────────────────────────────────
const Sidebar = {
    init() {
        const toggle = document.querySelector('.mobile-toggle');
        const sidebar = document.querySelector('.sidebar');
        if (toggle && sidebar) {
            toggle.addEventListener('click', () => sidebar.classList.toggle('open'));
            document.querySelector('.page-content')?.addEventListener('click', () => {
                sidebar.classList.remove('open');
            });
        }
    }
};

// ── File Upload Drag & Drop ──────────────────────────────────────────
const FileUpload = {
    init() {
        const zone = document.querySelector('.upload-zone');
        const input = document.getElementById('file-upload-input');
        const preview = document.querySelector('.file-list-preview');

        if (!zone || !input) return;

        zone.addEventListener('click', () => input.click());

        ['dragenter', 'dragover'].forEach(evt => {
            zone.addEventListener(evt, (e) => { e.preventDefault(); zone.classList.add('dragover'); });
        });
        ['dragleave', 'drop'].forEach(evt => {
            zone.addEventListener(evt, (e) => { e.preventDefault(); zone.classList.remove('dragover'); });
        });

        zone.addEventListener('drop', (e) => {
            input.files = e.dataTransfer.files;
            this.updatePreview(input.files, preview);
        });

        input.addEventListener('change', () => this.updatePreview(input.files, preview));
    },

    updatePreview(files, container) {
        if (!container) return;
        container.innerHTML = '';
        if (!files || files.length === 0) return;

        Array.from(files).forEach(file => {
            const ext = file.name.split('.').pop().toUpperCase();
            const item = document.createElement('div');
            item.className = 'file-item animate-scale';
            item.innerHTML = `
                <svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
                    <path d="M14 2H6a2 2 0 0 0-2 2v16a2 2 0 0 0 2 2h12a2 2 0 0 0 2-2V8z"/>
                    <polyline points="14,2 14,8 20,8"/>
                </svg>
                <span class="file-name">${file.name}</span>
                <span class="badge badge-cyan" style="font-size:0.65rem;">${ext}</span>
                <span class="file-size">${this.formatSize(file.size)}</span>
            `;
            container.appendChild(item);
        });
    },

    formatSize(bytes) {
        if (bytes < 1024) return bytes + ' B';
        if (bytes < 1048576) return (bytes / 1024).toFixed(1) + ' KB';
        return (bytes / 1048576).toFixed(1) + ' MB';
    }
};

// ── Risk Meter Animation ─────────────────────────────────────────────
const RiskMeter = {
    init() {
        document.querySelectorAll('.risk-meter').forEach(meter => {
            const score = parseInt(meter.dataset.score) || 0;
            const circle = meter.querySelector('.risk-meter-fill');
            if (!circle) return;

            const radius = parseFloat(circle.getAttribute('r'));
            const circumference = 2 * Math.PI * radius;
            circle.style.strokeDasharray = circumference;
            circle.style.strokeDashoffset = circumference;

            setTimeout(() => {
                circle.style.strokeDashoffset = circumference - (score / 100) * circumference;
            }, 300);
        });
    }
};

// ── Instant Scan (AJAX) ──────────────────────────────────────────────
const InstantScan = {
    init() {
        const form = document.getElementById('instant-scan-form');
        if (!form) return;

        form.addEventListener('submit', async (e) => {
            e.preventDefault();
            const text = document.getElementById('instant-scan-text')?.value;
            if (!text?.trim()) return;

            const btn = form.querySelector('button[type="submit"]');
            const orig = btn.innerHTML;
            btn.innerHTML = '<svg class="spin" width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M21 12a9 9 0 11-6.219-8.56"/></svg> Scanning...';
            btn.disabled = true;

            try {
                const csrf = document.querySelector('[name=csrfmiddlewaretoken]')?.value;
                const resp = await fetch('/scan/', {
                    method: 'POST',
                    headers: { 'X-CSRFToken': csrf, 'X-Requested-With': 'XMLHttpRequest', 'Content-Type': 'application/x-www-form-urlencoded' },
                    body: `text=${encodeURIComponent(text)}`,
                });
                const data = await resp.json();
                this.displayResults(data);
            } catch (err) { console.error('Scan failed:', err); }
            finally { btn.innerHTML = orig; btn.disabled = false; }
        });
    },

    displayResults(data) {
        const container = document.getElementById('scan-results');
        const reference = document.getElementById('scan-reference');
        if (!container) return;
        container.style.display = 'block';
        container.classList.add('animate-fade');
        if (reference) reference.style.display = 'none';

        const meterEl = container.querySelector('.risk-meter');
        if (meterEl) {
            meterEl.dataset.score = data.risk_score;
            const valueEl = meterEl.querySelector('.risk-meter-value');
            if (valueEl) valueEl.textContent = data.risk_score + '%';
            meterEl.className = 'risk-meter';
            if (data.risk_score >= 70) meterEl.classList.add('risk-high');
            else if (data.risk_score >= 30) meterEl.classList.add('risk-medium');
            else meterEl.classList.add('risk-low');
            RiskMeter.init();
        }

        const previewEl = container.querySelector('.text-preview');
        if (previewEl) previewEl.innerHTML = data.highlighted || 'No PII detected.';

        const summaryEl = container.querySelector('.pii-summary-list');
        if (summaryEl) {
            summaryEl.innerHTML = '';
            if (data.pii_summary && Object.keys(data.pii_summary).length > 0) {
                for (const [type, count] of Object.entries(data.pii_summary)) {
                    summaryEl.innerHTML += `<div class="detection-item"><span class="badge badge-purple">${type}</span><span class="detection-value">${count} found</span></div>`;
                }
            } else {
                summaryEl.innerHTML = '<p class="text-muted text-center" style="padding:20px;">No PII detected</p>';
            }
        }

        const totalEl = container.querySelector('.scan-total');
        if (totalEl) totalEl.textContent = data.total || 0;
    }
};

// ── Animated Counter ─────────────────────────────────────────────────
const AnimatedCounter = {
    init() {
        document.querySelectorAll('.stat-value').forEach(el => {
            const text = el.textContent.trim();
            const num = parseInt(text);
            if (isNaN(num) || num === 0) return;

            const suffix = text.replace(num.toString(), '');
            el.textContent = '0' + suffix;
            const duration = 1200;
            const start = performance.now();

            const animate = (now) => {
                const elapsed = now - start;
                const progress = Math.min(elapsed / duration, 1);
                const eased = 1 - Math.pow(1 - progress, 3);
                const current = Math.round(num * eased);
                el.textContent = current + suffix;
                if (progress < 1) requestAnimationFrame(animate);
            };
            requestAnimationFrame(animate);
        });
    }
};

// ── Profile Dropdown ─────────────────────────────────────────────────
const ProfileDropdown = {
    init() {
        const trigger = document.getElementById('profile-trigger');
        const dropdown = document.getElementById('profile-dropdown');
        if (!trigger || !dropdown) return;

        trigger.addEventListener('click', (e) => {
            e.stopPropagation();
            dropdown.classList.toggle('open');
        });

        // Close on outside click
        document.addEventListener('click', (e) => {
            if (!e.target.closest('#profile-dropdown-wrapper')) {
                dropdown.classList.remove('open');
            }
        });

        // Close on Escape
        document.addEventListener('keydown', (e) => {
            if (e.key === 'Escape') dropdown.classList.remove('open');
        });
    }
};

// ── Init ──────────────────────────────────────────────────────
document.addEventListener('DOMContentLoaded', () => {
    Sidebar.init();
    FileUpload.init();
    RiskMeter.init();
    InstantScan.init();
    AnimatedCounter.init();
    ProfileDropdown.init();
});
