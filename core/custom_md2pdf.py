import re
from reportlab.lib.pagesizes import A4
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer, HRFlowable, Table, TableStyle
from reportlab.lib import colors

styles = getSampleStyleSheet()

h1_style = ParagraphStyle('H1', parent=styles['Heading1'], fontSize=18, spaceAfter=14, textColor=colors.HexColor('#2E3A59'))
h2_style = ParagraphStyle('H2', parent=styles['Heading2'], fontSize=15, spaceBefore=12, spaceAfter=10, textColor=colors.HexColor('#2E3A59'))
h3_style = ParagraphStyle('H3', parent=styles['Heading3'], fontSize=13, spaceBefore=10, spaceAfter=8)
normal_style = ParagraphStyle('Normal', parent=styles['Normal'], fontSize=10, leading=14, spaceAfter=6)
bullet_style = ParagraphStyle('Bullet', parent=normal_style, leftIndent=15, firstLineIndent=0, spaceAfter=4)
code_style = ParagraphStyle('Code', parent=normal_style, fontName='Courier', leftIndent=10, backColor=colors.HexColor('#F4F4F4'), borderPadding=5, spaceAfter=10)

def parse_md_to_flowables(md_text):
    flowables = []
    lines = md_text.split('\n')
    i = 0
    in_code_block = False
    code_content = []
    
    while i < len(lines):
        line = lines[i]
        
        # Code logic
        if line.startswith('```'):
            if in_code_block:
                flowables.append(Paragraph('<br/>'.join(code_content), code_style))
                code_content = []
                in_code_block = False
            else:
                in_code_block = True
            i += 1
            continue
            
        if in_code_block:
            safe_line = line.replace('&', '&amp;').replace('<', '&lt;').replace('>', '&gt;')
            code_content.append(safe_line)
            i += 1
            continue
            
        line = line.strip()
        if not line:
            i += 1
            continue
            
        # bold logic
        line = re.sub(r'\*\*(.*?)\*\*', r'<b>\1</b>', line)
        line = re.sub(r'\*(.*?)\*', r'<i>\1</i>', line)
        line = re.sub(r'`(.*?)`', r'<font name="Courier">\1</font>', line)
        
        if line.startswith('---'):
            flowables.append(HRFlowable(width="100%", thickness=1, color=colors.HexColor('#E2E8F0'), spaceBefore=10, spaceAfter=10))
        elif line.startswith('# '):
            flowables.append(Paragraph(line[2:], h1_style))
        elif line.startswith('## '):
            flowables.append(Paragraph(line[3:], h2_style))
        elif line.startswith('### '):
            flowables.append(Paragraph(line[4:], h3_style))
        elif line.startswith('- '):
            flowables.append(Paragraph('&#8226; ' + line[2:], bullet_style))
        elif re.match(r'^\d+\.\s', line):
            flowables.append(Paragraph(line, bullet_style))
        elif line.startswith('|'):
            # simple table logic
            table_rows = []
            while i < len(lines) and lines[i].strip().startswith('|'):
                row_line = lines[i].strip()
                row_line = re.sub(r'\*\*(.*?)\*\*', r'<b>\1</b>', row_line)
                row_line = re.sub(r'`(.*?)`', r'<font name="Courier">\1</font>', row_line)
                cells = [c.strip() for c in row_line.split('|')[1:-1]]
                if not all(c.replace('-','').strip() == '' for c in cells):
                    table_rows.append([Paragraph(c, normal_style) for c in cells])
                i += 1
            if table_rows:
                t = Table(table_rows)
                t.setStyle(TableStyle([
                    ('BACKGROUND', (0,0), (-1,0), colors.HexColor('#E2E8F0')),
                    ('GRID', (0,0), (-1,-1), 1, colors.HexColor('#CBD5E1')),
                    ('VALIGN', (0,0), (-1,-1), 'MIDDLE'),
                    ('PADDING', (0,0), (-1,-1), 6),
                ]))
                flowables.append(t)
            continue
        else:
            flowables.append(Paragraph(line, normal_style))
            
        i += 1
    return flowables

try:
    with open(r'c:\Users\Dev\Desktop\Nullify_Setup_Documentation.md', 'r', encoding='utf-8') as f:
        md_text = f.read()

    doc = SimpleDocTemplate(r'c:\Users\Dev\Desktop\Nullify_Setup_Documentation.pdf', pagesize=A4, rightMargin=30, leftMargin=30, topMargin=30, bottomMargin=30)
    story = parse_md_to_flowables(md_text)
    doc.build(story)
    print("SUCCESS")
except Exception as e:
    with open('reportlab_err.txt', 'w') as err:
        err.write(str(e))
