"""
File Generator — Generate sanitized output files and PDF reports.
"""

from io import BytesIO
from django.core.files.base import ContentFile


def generate_sanitized_file(uploaded_file, sanitized_text):
    """
    Create a sanitized text file.
    Returns (filename, ContentFile) tuple for saving to SanitizedFile.sanitized_file.
    """
    base_name = uploaded_file.original_filename.rsplit('.', 1)[0]
    filename = f"sanitized_{uploaded_file.id}_{base_name}.txt"
    content = ContentFile(sanitized_text.encode('utf-8'))
    return filename, content


def generate_report_pdf(uploaded_file, detections, sanitized_file=None):
    """
    Generate a PDF sanitization report.
    Returns a BytesIO buffer containing the PDF.
    """
    try:
        from reportlab.lib import colors
        from reportlab.lib.pagesizes import A4
        from reportlab.lib.units import inch, cm
        from reportlab.platypus import SimpleDocTemplate, Table, TableStyle, Paragraph, Spacer, HRFlowable
        from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
        from reportlab.lib.enums import TA_CENTER, TA_LEFT
    except ImportError:
        # Fallback: generate a simple text report
        return _generate_text_report(uploaded_file, detections, sanitized_file)

    buffer = BytesIO()
    doc = SimpleDocTemplate(buffer, pagesize=A4,
                            topMargin=1.5 * cm, bottomMargin=1.5 * cm,
                            leftMargin=2 * cm, rightMargin=2 * cm)

    styles = getSampleStyleSheet()

    # Custom styles
    title_style = ParagraphStyle(
        'CustomTitle', parent=styles['Title'],
        fontSize=22, textColor=colors.HexColor('#0B132B'),
        spaceAfter=6
    )
    subtitle_style = ParagraphStyle(
        'CustomSubtitle', parent=styles['Normal'],
        fontSize=11, textColor=colors.HexColor('#64748B'),
        spaceAfter=20
    )
    heading_style = ParagraphStyle(
        'CustomHeading', parent=styles['Heading2'],
        fontSize=14, textColor=colors.HexColor('#7B61FF'),
        spaceBefore=20, spaceAfter=10
    )
    info_style = ParagraphStyle(
        'InfoStyle', parent=styles['Normal'],
        fontSize=10, leading=16
    )

    story = []

    # ── Header ──
    story.append(Paragraph("Nullify — Sanitization Report", title_style))
    story.append(Paragraph("PII Detection & Data Sanitization Platform", subtitle_style))
    story.append(HRFlowable(width="100%", thickness=1, color=colors.HexColor('#E2E8F0')))
    story.append(Spacer(1, 15))

    # ── File Information ──
    story.append(Paragraph("File Information", heading_style))

    file_info = [
        ['Property', 'Details'],
        ['File Name', uploaded_file.original_filename],
        ['File Type', uploaded_file.file_type.upper()],
        ['File Size', _format_size(uploaded_file.file_size)],
        ['Upload Date', uploaded_file.uploaded_at.strftime('%d %B %Y, %I:%M %p')],
        ['Uploaded By', uploaded_file.uploaded_by.username],
        ['Risk Score', f"{uploaded_file.risk_score}% ({uploaded_file.risk_level().title()})"],
        ['Sanitization Method', sanitized_file.get_method_display() if sanitized_file else 'N/A'],
        ['Total PII Found', str(len(detections))],
    ]

    t = Table(file_info, colWidths=[150, 300])
    t.setStyle(TableStyle([
        ('BACKGROUND', (0, 0), (-1, 0), colors.HexColor('#7B61FF')),
        ('TEXTCOLOR', (0, 0), (-1, 0), colors.white),
        ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
        ('FONTSIZE', (0, 0), (-1, -1), 10),
        ('BOTTOMPADDING', (0, 0), (-1, 0), 10),
        ('TOPPADDING', (0, 0), (-1, 0), 10),
        ('GRID', (0, 0), (-1, -1), 0.5, colors.HexColor('#E2E8F0')),
        ('ROWBACKGROUNDS', (0, 1), (-1, -1), [colors.white, colors.HexColor('#F8FAFC')]),
        ('VALIGN', (0, 0), (-1, -1), 'MIDDLE'),
        ('LEFTPADDING', (0, 0), (-1, -1), 10),
    ]))
    story.append(t)
    story.append(Spacer(1, 20))

    # ── PII Detection Summary ──
    story.append(Paragraph("PII Detection Summary", heading_style))

    pii_summary = {}
    for d in detections:
        pii_type = d.pii_type if hasattr(d, 'pii_type') else d.get('type', 'Unknown')
        pii_summary[pii_type] = pii_summary.get(pii_type, 0) + 1

    if pii_summary:
        summary_data = [['PII Type', 'Count', 'Risk Weight']]
        from .pii_engine import PII_WEIGHTS
        for pii_type, count in sorted(pii_summary.items()):
            weight = PII_WEIGHTS.get(pii_type, 1)
            summary_data.append([pii_type, str(count), str(weight)])

        t2 = Table(summary_data, colWidths=[180, 100, 120])
        t2.setStyle(TableStyle([
            ('BACKGROUND', (0, 0), (-1, 0), colors.HexColor('#00C2A8')),
            ('TEXTCOLOR', (0, 0), (-1, 0), colors.white),
            ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
            ('FONTSIZE', (0, 0), (-1, -1), 10),
            ('BOTTOMPADDING', (0, 0), (-1, 0), 10),
            ('TOPPADDING', (0, 0), (-1, 0), 10),
            ('GRID', (0, 0), (-1, -1), 0.5, colors.HexColor('#E2E8F0')),
            ('ROWBACKGROUNDS', (0, 1), (-1, -1), [colors.white, colors.HexColor('#F8FAFC')]),
            ('ALIGN', (1, 0), (-1, -1), 'CENTER'),
            ('LEFTPADDING', (0, 0), (-1, -1), 10),
        ]))
        story.append(t2)
    else:
        story.append(Paragraph("No PII detected in this file.", info_style))

    story.append(Spacer(1, 30))

    # ── Footer ──
    story.append(HRFlowable(width="100%", thickness=1, color=colors.HexColor('#E2E8F0')))
    story.append(Spacer(1, 8))
    footer_style = ParagraphStyle(
        'Footer', parent=styles['Normal'],
        fontSize=8, textColor=colors.HexColor('#94A3B8'),
        alignment=TA_CENTER
    )
    story.append(Paragraph(
        "Generated by Nullify — PII Detection & Data Sanitization Platform",
        footer_style
    ))

    doc.build(story)
    buffer.seek(0)
    return buffer


def _generate_text_report(uploaded_file, detections, sanitized_file):
    """Fallback text-based report if reportlab is not available."""
    buffer = BytesIO()
    lines = [
        "=" * 60,
        "NULLIFY — SANITIZATION REPORT",
        "=" * 60,
        "",
        f"File Name:      {uploaded_file.original_filename}",
        f"File Type:      {uploaded_file.file_type.upper()}",
        f"Upload Date:    {uploaded_file.uploaded_at}",
        f"Risk Score:     {uploaded_file.risk_score}%",
        f"Method:         {sanitized_file.get_method_display() if sanitized_file else 'N/A'}",
        f"Total PII:      {len(detections)}",
        "",
        "-" * 60,
        "PII DETECTION SUMMARY",
        "-" * 60,
    ]

    pii_summary = {}
    for d in detections:
        pii_type = d.pii_type if hasattr(d, 'pii_type') else d.get('type', 'Unknown')
        pii_summary[pii_type] = pii_summary.get(pii_type, 0) + 1

    for pii_type, count in sorted(pii_summary.items()):
        lines.append(f"  {pii_type:20s} : {count}")

    lines.extend(["", "=" * 60])
    buffer.write('\n'.join(lines).encode('utf-8'))
    buffer.seek(0)
    return buffer


def _format_size(size_bytes):
    """Format file size in human-readable format."""
    if size_bytes < 1024:
        return f"{size_bytes} B"
    elif size_bytes < 1024 * 1024:
        return f"{size_bytes / 1024:.1f} KB"
    else:
        return f"{size_bytes / (1024 * 1024):.1f} MB"
