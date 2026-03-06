"""
Chart Generator — Server-side chart generation using matplotlib.
Generates charts as base64-encoded PNG images for embedding in templates.
"""

import io
import base64
import matplotlib
matplotlib.use('Agg')  # Non-interactive backend
import matplotlib.pyplot as plt
import matplotlib.ticker as ticker
from collections import Counter


# ── Brand Colors ──
BRAND_COLORS = [
    '#00E5FF', '#7B61FF', '#00C2A8', '#EF4444', '#F59E0B',
    '#10B981', '#3B82F6', '#EC4899', '#8B5CF6', '#06B6D4',
]

RISK_COLORS = {
    'Low': '#10B981',
    'Medium': '#F59E0B',
    'High': '#EF4444',
}


def _fig_to_base64(fig):
    """Convert a matplotlib figure to a base64-encoded PNG string."""
    buf = io.BytesIO()
    fig.savefig(buf, format='png', dpi=150, bbox_inches='tight',
                transparent=True, facecolor='none', edgecolor='none')
    buf.seek(0)
    img_b64 = base64.b64encode(buf.read()).decode('utf-8')
    plt.close(fig)
    return f"data:image/png;base64,{img_b64}"


def _setup_dark_style():
    """Configure matplotlib for dark-themed charts."""
    plt.rcParams.update({
        'text.color': '#94A3B8',
        'axes.labelcolor': '#94A3B8',
        'xtick.color': '#64748B',
        'ytick.color': '#64748B',
        'axes.edgecolor': '#334155',
        'axes.facecolor': 'none',
        'figure.facecolor': 'none',
        'font.family': 'sans-serif',
        'font.size': 10,
    })


def generate_pii_distribution_chart(pii_data):
    """
    Generate a doughnut chart of PII type distribution.
    pii_data: list of dicts [{'pii_type': str, 'count': int}, ...]
    Returns base64 image string.
    """
    _setup_dark_style()

    if not pii_data:
        return _generate_empty_chart("No PII Data Available")

    labels = [d['pii_type'] for d in pii_data]
    values = [d['count'] for d in pii_data]
    colors = BRAND_COLORS[:len(labels)]

    fig, ax = plt.subplots(figsize=(5, 4))

    wedges, texts, autotexts = ax.pie(
        values, labels=None, colors=colors, autopct='%1.0f%%',
        startangle=90, pctdistance=0.78,
        wedgeprops=dict(width=0.35, edgecolor='none', linewidth=0),
        textprops=dict(color='#E2E8F0', fontsize=9, fontweight='bold'),
    )

    for t in autotexts:
        t.set_fontsize(8)
        t.set_color('#E2E8F0')

    ax.legend(
        wedges, [f'{l} ({v})' for l, v in zip(labels, values)],
        loc='center left', bbox_to_anchor=(1, 0.5),
        fontsize=9, frameon=False, labelcolor='#94A3B8',
    )

    ax.set_title('PII Type Distribution', fontsize=13, fontweight='bold',
                 color='#E2E8F0', pad=15)

    return _fig_to_base64(fig)


def generate_risk_distribution_chart(low, medium, high):
    """
    Generate a doughnut chart of risk distribution.
    Returns base64 image string.
    """
    _setup_dark_style()

    labels = ['Low', 'Medium', 'High']
    values = [low, medium, high]
    colors = [RISK_COLORS[l] for l in labels]

    if sum(values) == 0:
        return _generate_empty_chart("No Risk Data Available")

    fig, ax = plt.subplots(figsize=(5, 4))

    wedges, texts, autotexts = ax.pie(
        values, labels=None, colors=colors, autopct='%1.0f%%',
        startangle=90, pctdistance=0.78,
        wedgeprops=dict(width=0.35, edgecolor='none', linewidth=0),
        textprops=dict(color='#E2E8F0', fontsize=10, fontweight='bold'),
    )

    for t in autotexts:
        t.set_fontsize(9)
        t.set_color('#E2E8F0')

    centre = plt.Circle((0, 0), 0.5, fc='none')
    ax.add_artist(centre)
    ax.text(0, 0.05, str(sum(values)), ha='center', va='center',
            fontsize=22, fontweight='bold', color='#E2E8F0')
    ax.text(0, -0.15, 'Total', ha='center', va='center',
            fontsize=9, color='#94A3B8')

    ax.legend(
        wedges, [f'{l}: {v}' for l, v in zip(labels, values)],
        loc='center left', bbox_to_anchor=(1, 0.5),
        fontsize=10, frameon=False, labelcolor='#94A3B8',
    )

    ax.set_title('Risk Distribution', fontsize=13, fontweight='bold',
                 color='#E2E8F0', pad=15)

    return _fig_to_base64(fig)


def generate_files_over_time_chart(time_data):
    """
    Generate a line chart of files uploaded over time.
    time_data: list of dicts [{'date': str, 'count': int}, ...]
    Returns base64 image string.
    """
    _setup_dark_style()

    if not time_data:
        return _generate_empty_chart("No Timeline Data Available")

    dates = [d['date'] for d in time_data]
    counts = [d['count'] for d in time_data]

    fig, ax = plt.subplots(figsize=(6, 3.5))

    ax.fill_between(range(len(dates)), counts, alpha=0.15, color='#00E5FF')
    ax.plot(range(len(dates)), counts, color='#00E5FF', linewidth=2.5,
            marker='o', markersize=6, markerfacecolor='#00E5FF',
            markeredgecolor='#0B132B', markeredgewidth=2)

    ax.set_xticks(range(len(dates)))
    ax.set_xticklabels(dates, rotation=45, ha='right', fontsize=8)
    ax.yaxis.set_major_locator(ticker.MaxNLocator(integer=True))

    ax.spines['top'].set_visible(False)
    ax.spines['right'].set_visible(False)
    ax.spines['left'].set_color('#334155')
    ax.spines['bottom'].set_color('#334155')
    ax.grid(axis='y', color='#1E293B', linestyle='--', alpha=0.5)

    ax.set_title('Files Uploaded Over Time', fontsize=13, fontweight='bold',
                 color='#E2E8F0', pad=15)
    ax.set_ylabel('Files', fontsize=10)

    plt.tight_layout()
    return _fig_to_base64(fig)


def generate_file_type_chart(file_data):
    """
    Generate a bar chart of file type distribution.
    file_data: list of dicts [{'file_type': str, 'count': int}, ...]
    Returns base64 image string.
    """
    _setup_dark_style()

    if not file_data:
        return _generate_empty_chart("No File Type Data Available")

    labels = [d['file_type'].upper() for d in file_data]
    values = [d['count'] for d in file_data]
    colors = BRAND_COLORS[:len(labels)]

    fig, ax = plt.subplots(figsize=(5, 3.5))

    bars = ax.bar(labels, values, color=colors, edgecolor='none',
                  width=0.6, alpha=0.85)

    # Add value labels on bars
    for bar, val in zip(bars, values):
        ax.text(bar.get_x() + bar.get_width() / 2, bar.get_height() + 0.15,
                str(val), ha='center', va='bottom', fontsize=10,
                fontweight='bold', color='#E2E8F0')

    ax.yaxis.set_major_locator(ticker.MaxNLocator(integer=True))
    ax.spines['top'].set_visible(False)
    ax.spines['right'].set_visible(False)
    ax.spines['left'].set_color('#334155')
    ax.spines['bottom'].set_color('#334155')
    ax.grid(axis='y', color='#1E293B', linestyle='--', alpha=0.5)

    ax.set_title('File Type Distribution', fontsize=13, fontweight='bold',
                 color='#E2E8F0', pad=15)
    ax.set_ylabel('Count', fontsize=10)

    plt.tight_layout()
    return _fig_to_base64(fig)


def generate_method_distribution_chart(method_data):
    """
    Generate a horizontal bar chart of sanitization method usage.
    method_data: list of dicts [{'method': str, 'count': int}, ...]
    Returns base64 image string.
    """
    _setup_dark_style()

    if not method_data:
        return _generate_empty_chart("No Method Data Available")

    labels = [d['method'].title() for d in method_data]
    values = [d['count'] for d in method_data]
    colors = ['#7B61FF', '#00C2A8', '#F59E0B'][:len(labels)]

    fig, ax = plt.subplots(figsize=(5, 3))

    bars = ax.barh(labels, values, color=colors, edgecolor='none', height=0.5)

    for bar, val in zip(bars, values):
        ax.text(bar.get_width() + 0.2, bar.get_y() + bar.get_height() / 2,
                str(val), ha='left', va='center', fontsize=10,
                fontweight='bold', color='#E2E8F0')

    ax.xaxis.set_major_locator(ticker.MaxNLocator(integer=True))
    ax.spines['top'].set_visible(False)
    ax.spines['right'].set_visible(False)
    ax.spines['left'].set_color('#334155')
    ax.spines['bottom'].set_color('#334155')
    ax.grid(axis='x', color='#1E293B', linestyle='--', alpha=0.5)

    ax.set_title('Sanitization Methods Used', fontsize=13, fontweight='bold',
                 color='#E2E8F0', pad=15)

    plt.tight_layout()
    return _fig_to_base64(fig)


def generate_dashboard_mini_chart(pii_breakdown):
    """
    Generate a small PII breakdown doughnut for the dashboard.
    pii_breakdown: list of dicts [{'pii_type': str, 'count': int}, ...]
    Returns base64 image string.
    """
    _setup_dark_style()

    if not pii_breakdown:
        return _generate_empty_chart("No PII Data", figsize=(4, 3))

    labels = [d['pii_type'] for d in pii_breakdown]
    values = [d['count'] for d in pii_breakdown]
    colors = BRAND_COLORS[:len(labels)]

    fig, ax = plt.subplots(figsize=(4.5, 3.5))

    wedges, texts, autotexts = ax.pie(
        values, labels=None, colors=colors, autopct='%1.0f%%',
        startangle=90, pctdistance=0.78,
        wedgeprops=dict(width=0.4, edgecolor='none'),
        textprops=dict(color='#E2E8F0', fontsize=8),
    )

    for t in autotexts:
        t.set_fontsize(7)
        t.set_color('#E2E8F0')

    ax.legend(
        wedges, labels,
        loc='center left', bbox_to_anchor=(1, 0.5),
        fontsize=8, frameon=False, labelcolor='#94A3B8',
    )

    plt.tight_layout()
    return _fig_to_base64(fig)


def generate_pii_summary_chart(pii_summary):
    """
    Generate a horizontal bar chart for PII summary on results page.
    pii_summary: dict {'Email': 5, 'Phone': 3, ...}
    Returns base64 image string.
    """
    _setup_dark_style()

    if not pii_summary:
        return _generate_empty_chart("No PII Detected", figsize=(4, 3))

    labels = list(pii_summary.keys())
    values = list(pii_summary.values())
    colors = BRAND_COLORS[:len(labels)]

    fig, ax = plt.subplots(figsize=(4.5, max(2.5, len(labels) * 0.6)))

    bars = ax.barh(labels, values, color=colors, edgecolor='none', height=0.5)

    for bar, val in zip(bars, values):
        ax.text(bar.get_width() + 0.15, bar.get_y() + bar.get_height() / 2,
                str(val), ha='left', va='center', fontsize=9,
                fontweight='bold', color='#E2E8F0')

    ax.xaxis.set_major_locator(ticker.MaxNLocator(integer=True))
    ax.spines['top'].set_visible(False)
    ax.spines['right'].set_visible(False)
    ax.spines['left'].set_color('#334155')
    ax.spines['bottom'].set_color('#334155')
    ax.grid(axis='x', color='#1E293B', linestyle='--', alpha=0.5)
    ax.invert_yaxis()

    ax.set_title('PII Breakdown', fontsize=12, fontweight='bold',
                 color='#E2E8F0', pad=10)

    plt.tight_layout()
    return _fig_to_base64(fig)


def _generate_empty_chart(message, figsize=(5, 3)):
    """Generate a placeholder chart with a message."""
    _setup_dark_style()
    fig, ax = plt.subplots(figsize=figsize)
    ax.text(0.5, 0.5, message, ha='center', va='center',
            fontsize=14, color='#64748B', style='italic',
            transform=ax.transAxes)
    ax.set_xlim(0, 1)
    ax.set_ylim(0, 1)
    ax.axis('off')
    return _fig_to_base64(fig)
