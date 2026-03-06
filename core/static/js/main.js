/* ══════════════════════════════════════════════════════════════════════
   NULLIFY — Main JavaScript
   Theme switching, file upload interactions, charts, instant scan
   ══════════════════════════════════════════════════════════════════════ */

// ── Theme Management ─────────────────────────────────────────────────
const ThemeManager = {
    init() {
        const saved = localStorage.getItem('nullify-theme') || 'system';
        this.apply(saved);
        this.bindEvents();
    },

    apply(theme) {
        document.documentElement.setAttribute('data-theme', theme);
        localStorage.setItem('nullify-theme', theme);
        // Update active indicator in dropdown
        document.querySelectorAll('.theme-option').forEach(opt => {
            opt.classList.toggle('active', opt.dataset.theme === theme);
        });
        // Update button icon
        this.updateIcon(theme);
    },

    updateIcon(theme) {
        const btn = document.querySelector('.theme-btn');
        if (!btn) return;
        const icons = {
            light: `<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><circle cx="12" cy="12" r="5"/><path d="M12 1v2m0 18v2M4.22 4.22l1.42 1.42m12.72 12.72l1.42 1.42M1 12h2m18 0h2M4.22 19.78l1.42-1.42M18.36 5.64l1.42-1.42"/></svg>`,
            dark: `<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M21 12.79A9 9 0 1111.21 3 7 7 0 0021 12.79z"/></svg>`,
            system: `<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><rect x="2" y="3" width="20" height="14" rx="2" ry="2"/><path d="M8 21h8m-4-4v4"/></svg>`,
        };
        const label = { light: 'Light', dark: 'Dark', system: 'System' };
        btn.innerHTML = (icons[theme] || icons.system) + `<span>${label[theme] || 'System'}</span>`;
    },

    bindEvents() {
        // Toggle dropdown
        const btn = document.querySelector('.theme-btn');
        const dropdown = document.querySelector('.theme-dropdown');
        if (btn && dropdown) {
            btn.addEventListener('click', (e) => {
                e.stopPropagation();
                dropdown.classList.toggle('show');
            });
            document.addEventListener('click', () => dropdown.classList.remove('show'));
        }

        // Theme options
        document.querySelectorAll('.theme-option').forEach(opt => {
            opt.addEventListener('click', () => {
                this.apply(opt.dataset.theme);
                document.querySelector('.theme-dropdown')?.classList.remove('show');
            });
        });
    }
};

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

        // Click to select
        zone.addEventListener('click', () => input.click());

        // Drag events
        ['dragenter', 'dragover'].forEach(evt => {
            zone.addEventListener(evt, (e) => {
                e.preventDefault();
                zone.classList.add('dragover');
            });
        });
        ['dragleave', 'drop'].forEach(evt => {
            zone.addEventListener(evt, (e) => {
                e.preventDefault();
                zone.classList.remove('dragover');
            });
        });

        zone.addEventListener('drop', (e) => {
            const dt = e.dataTransfer;
            input.files = dt.files;
            this.updatePreview(input.files, preview);
        });

        input.addEventListener('change', () => {
            this.updatePreview(input.files, preview);
        });
    },

    updatePreview(files, container) {
        if (!container) return;
        container.innerHTML = '';
        if (!files || files.length === 0) return;

        Array.from(files).forEach((file, idx) => {
            const item = document.createElement('div');
            item.className = 'file-item animate-scale';
            item.innerHTML = `
                <svg class="file-icon" width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
                    <path d="M14 2H6a2 2 0 0 0-2 2v16a2 2 0 0 0 2 2h12a2 2 0 0 0 2-2V8z"/>
                    <polyline points="14,2 14,8 20,8"/>
                </svg>
                <span class="file-name">${file.name}</span>
                <span class="file-size">${this.formatSize(file.size)}</span>
            `;
            container.appendChild(item);
        });
    },

    formatSize(bytes) {
        if (bytes < 1024) return bytes + ' B';
        if (bytes < 1024 * 1024) return (bytes / 1024).toFixed(1) + ' KB';
        return (bytes / (1024 * 1024)).toFixed(1) + ' MB';
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

            // Animate after a short delay
            setTimeout(() => {
                const offset = circumference - (score / 100) * circumference;
                circle.style.strokeDashoffset = offset;
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
            const originalText = btn.innerHTML;
            btn.innerHTML = '<svg class="spin" width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M21 12a9 9 0 11-6.219-8.56"/></svg> Scanning...';
            btn.disabled = true;

            try {
                const csrfToken = document.querySelector('[name=csrfmiddlewaretoken]')?.value;
                const resp = await fetch('/scan/', {
                    method: 'POST',
                    headers: {
                        'X-CSRFToken': csrfToken,
                        'X-Requested-With': 'XMLHttpRequest',
                        'Content-Type': 'application/x-www-form-urlencoded',
                    },
                    body: `text=${encodeURIComponent(text)}`,
                });

                const data = await resp.json();
                this.displayResults(data);
            } catch (err) {
                console.error('Scan failed:', err);
            } finally {
                btn.innerHTML = originalText;
                btn.disabled = false;
            }
        });
    },

    displayResults(data) {
        const container = document.getElementById('scan-results');
        if (!container) return;

        container.style.display = 'block';
        container.classList.add('animate-fade');

        // Update risk meter
        const meterEl = container.querySelector('.risk-meter');
        if (meterEl) {
            meterEl.dataset.score = data.risk_score;
            const valueEl = meterEl.querySelector('.risk-meter-value');
            if (valueEl) valueEl.textContent = data.risk_score + '%';

            // Update risk class
            meterEl.className = 'risk-meter';
            if (data.risk_score >= 70) meterEl.classList.add('risk-high');
            else if (data.risk_score >= 30) meterEl.classList.add('risk-medium');
            else meterEl.classList.add('risk-low');

            RiskMeter.init();
        }

        // Update highlighted text
        const previewEl = container.querySelector('.text-preview');
        if (previewEl) previewEl.innerHTML = data.highlighted || 'No PII detected.';

        // Update summary
        const summaryEl = container.querySelector('.pii-summary-list');
        if (summaryEl) {
            summaryEl.innerHTML = '';
            if (data.pii_summary && Object.keys(data.pii_summary).length > 0) {
                for (const [type, count] of Object.entries(data.pii_summary)) {
                    const item = document.createElement('div');
                    item.className = 'detection-item';
                    item.innerHTML = `
                        <span class="detection-type badge badge-purple">${type}</span>
                        <span class="detection-value">${count} found</span>
                    `;
                    summaryEl.appendChild(item);
                }
            } else {
                summaryEl.innerHTML = '<p class="text-muted text-center" style="padding:20px;">No PII detected</p>';
            }
        }

        // Update total count
        const totalEl = container.querySelector('.scan-total');
        if (totalEl) totalEl.textContent = data.total || 0;
    }
};

// ── Analytics Charts ─────────────────────────────────────────────────
const Analytics = {
    chartInstances: {},
    brandColors: {
        cyan: '#00E5FF',
        purple: '#7B61FF',
        teal: '#00C2A8',
        danger: '#EF4444',
        warning: '#F59E0B',
        success: '#10B981',
        info: '#3B82F6',
        pink: '#EC4899',
    },

    async init() {
        if (!document.getElementById('pii-distribution-chart')) return;

        try {
            const resp = await fetch('/api/analytics/');
            const data = await resp.json();
            this.renderPIIDistribution(data.pii_distribution);
            this.renderFileDistribution(data.file_distribution);
            this.renderFilesOverTime(data.files_over_time);
            this.renderRiskDistribution(data.risk_distribution);
            this.updateSummary(data.summary);
        } catch (err) {
            console.error('Failed to load analytics:', err);
        }
    },

    getChartColors(count) {
        const allColors = Object.values(this.brandColors);
        const colors = [];
        for (let i = 0; i < count; i++) {
            colors.push(allColors[i % allColors.length]);
        }
        return colors;
    },

    renderPIIDistribution(data) {
        const ctx = document.getElementById('pii-distribution-chart');
        if (!ctx || !data?.length) return;

        const colors = this.getChartColors(data.length);
        this.chartInstances.pii = new Chart(ctx, {
            type: 'doughnut',
            data: {
                labels: data.map(d => d.pii_type),
                datasets: [{
                    data: data.map(d => d.count),
                    backgroundColor: colors,
                    borderWidth: 0,
                    hoverOffset: 8,
                }]
            },
            options: {
                responsive: true,
                maintainAspectRatio: false,
                plugins: {
                    legend: {
                        position: 'bottom',
                        labels: {
                            padding: 16,
                            usePointStyle: true,
                            pointStyleWidth: 10,
                            color: getComputedStyle(document.documentElement).getPropertyValue('--text-secondary'),
                        }
                    }
                },
                cutout: '65%',
            }
        });
    },

    renderFileDistribution(data) {
        const ctx = document.getElementById('file-distribution-chart');
        if (!ctx || !data?.length) return;

        const colors = this.getChartColors(data.length);
        this.chartInstances.file = new Chart(ctx, {
            type: 'bar',
            data: {
                labels: data.map(d => d.file_type.toUpperCase()),
                datasets: [{
                    label: 'Files',
                    data: data.map(d => d.count),
                    backgroundColor: colors.map(c => c + '33'),
                    borderColor: colors,
                    borderWidth: 2,
                    borderRadius: 8,
                    borderSkipped: false,
                }]
            },
            options: {
                responsive: true,
                maintainAspectRatio: false,
                plugins: { legend: { display: false } },
                scales: {
                    y: {
                        beginAtZero: true,
                        ticks: { precision: 0, color: getComputedStyle(document.documentElement).getPropertyValue('--text-muted') },
                        grid: { color: getComputedStyle(document.documentElement).getPropertyValue('--border') },
                    },
                    x: {
                        ticks: { color: getComputedStyle(document.documentElement).getPropertyValue('--text-muted') },
                        grid: { display: false },
                    }
                }
            }
        });
    },

    renderFilesOverTime(data) {
        const ctx = document.getElementById('files-over-time-chart');
        if (!ctx) return;

        const chartData = data?.length ? data : [{ date: new Date().toISOString().split('T')[0], count: 0 }];
        this.chartInstances.timeline = new Chart(ctx, {
            type: 'line',
            data: {
                labels: chartData.map(d => d.date),
                datasets: [{
                    label: 'Files Processed',
                    data: chartData.map(d => d.count),
                    borderColor: this.brandColors.cyan,
                    backgroundColor: this.brandColors.cyan + '15',
                    borderWidth: 2,
                    fill: true,
                    tension: 0.4,
                    pointBackgroundColor: this.brandColors.cyan,
                    pointRadius: 4,
                    pointHoverRadius: 6,
                }]
            },
            options: {
                responsive: true,
                maintainAspectRatio: false,
                plugins: { legend: { display: false } },
                scales: {
                    y: {
                        beginAtZero: true,
                        ticks: { precision: 0, color: getComputedStyle(document.documentElement).getPropertyValue('--text-muted') },
                        grid: { color: getComputedStyle(document.documentElement).getPropertyValue('--border') },
                    },
                    x: {
                        ticks: { color: getComputedStyle(document.documentElement).getPropertyValue('--text-muted'), maxRotation: 45 },
                        grid: { display: false },
                    }
                }
            }
        });
    },

    renderRiskDistribution(data) {
        const ctx = document.getElementById('risk-distribution-chart');
        if (!ctx || !data) return;

        this.chartInstances.risk = new Chart(ctx, {
            type: 'doughnut',
            data: {
                labels: ['Low Risk', 'Medium Risk', 'High Risk'],
                datasets: [{
                    data: [data.low, data.medium, data.high],
                    backgroundColor: [this.brandColors.success, this.brandColors.warning, this.brandColors.danger],
                    borderWidth: 0,
                    hoverOffset: 8,
                }]
            },
            options: {
                responsive: true,
                maintainAspectRatio: false,
                plugins: {
                    legend: {
                        position: 'bottom',
                        labels: {
                            padding: 16,
                            usePointStyle: true,
                            color: getComputedStyle(document.documentElement).getPropertyValue('--text-secondary'),
                        }
                    }
                },
                cutout: '65%',
            }
        });
    },

    updateSummary(summary) {
        if (!summary) return;
        const map = {
            'analytics-total-files': summary.total_files,
            'analytics-total-pii': summary.total_pii,
            'analytics-total-sanitized': summary.total_sanitized,
            'analytics-avg-risk': (summary.avg_risk || 0) + '%',
        };
        for (const [id, val] of Object.entries(map)) {
            const el = document.getElementById(id);
            if (el) el.textContent = val;
        }
    }
};

// ── Dashboard Mini Chart ─────────────────────────────────────────────
const DashboardChart = {
    init() {
        const el = document.getElementById('dashboard-pii-chart');
        if (!el) return;

        const dataStr = el.dataset.breakdown;
        if (!dataStr) return;

        try {
            const data = JSON.parse(dataStr);
            if (!data.length) return;

            const colors = Analytics.getChartColors(data.length);
            new Chart(el, {
                type: 'doughnut',
                data: {
                    labels: data.map(d => d.pii_type),
                    datasets: [{
                        data: data.map(d => d.count),
                        backgroundColor: colors,
                        borderWidth: 0,
                    }]
                },
                options: {
                    responsive: true,
                    maintainAspectRatio: false,
                    plugins: {
                        legend: {
                            position: 'right',
                            labels: { padding: 12, usePointStyle: true, pointStyleWidth: 8, font: { size: 11 },
                                color: getComputedStyle(document.documentElement).getPropertyValue('--text-secondary'),
                            }
                        }
                    },
                    cutout: '60%',
                }
            });
        } catch (e) {
            console.error('Chart data parse error:', e);
        }
    }
};

// ── CSS Spin Animation ───────────────────────────────────────────────
const style = document.createElement('style');
style.textContent = `@keyframes spin { from { transform: rotate(0deg); } to { transform: rotate(360deg); } } .spin { animation: spin 1s linear infinite; }`;
document.head.appendChild(style);

// ── Init Everything on DOMContentLoaded ──────────────────────────────
document.addEventListener('DOMContentLoaded', () => {
    ThemeManager.init();
    Sidebar.init();
    FileUpload.init();
    RiskMeter.init();
    InstantScan.init();
    Analytics.init();
    DashboardChart.init();

    // Auto-dismiss alerts after 5 seconds
    document.querySelectorAll('.alert').forEach(alert => {
        setTimeout(() => {
            alert.style.opacity = '0';
            alert.style.transform = 'translateY(-10px)';
            setTimeout(() => alert.remove(), 300);
        }, 5000);
    });
});
