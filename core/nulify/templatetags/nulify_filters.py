"""
Custom template filters for the Nulify app.
Renders pipe-delimited table rows as HTML tables.
"""

from django import template
from django.utils.safestring import mark_safe, SafeData
from django.utils.html import escape

register = template.Library()


@register.filter(name='render_tables')
def render_tables(text):
    """
    Convert pipe-delimited lines into HTML tables.
    Non-table lines are rendered with <br> for line breaks.
    Consecutive lines containing '|' are grouped into a single <table>.

    If the text is already marked safe (e.g. from |safe filter),
    HTML tags are preserved as-is.  Otherwise text is escaped.
    """
    if not text:
        return ''

    text_str = str(text)
    already_safe = isinstance(text, SafeData)

    lines = text_str.split('\n')
    output_parts = []
    i = 0

    while i < len(lines):
        line = lines[i]

        # Only treat as table row if:
        # 1. Contains | as separator
        # 2. Is not empty
        # 3. Does NOT contain HTML tags (to avoid mangling highlighted text)
        is_table_row = (
            '|' in line
            and line.strip()
            and '<mark' not in line
            and '</mark>' not in line
        )

        if is_table_row:
            # Collect consecutive table rows
            table_rows = []
            while i < len(lines) and '|' in lines[i] and lines[i].strip() and '<mark' not in lines[i]:
                raw_cells = lines[i].split('|')
                cells = [c.strip() for c in raw_cells]
                # Remove empty edge cells from leading/trailing pipes
                cells = [c for c in cells if c or len(raw_cells) <= 3]
                if cells:
                    if not already_safe:
                        cells = [escape(c) for c in cells]
                    table_rows.append(cells)
                i += 1

            if table_rows:
                # Build HTML table
                html = '<table class="sanitized-table">'
                for row_idx, row in enumerate(table_rows):
                    html += '<tr>'
                    tag = 'th' if row_idx == 0 else 'td'
                    for cell in row:
                        html += f'<{tag}>{cell}</{tag}>'
                    html += '</tr>'
                html += '</table>'
                output_parts.append(html)
        else:
            # Regular line
            if already_safe:
                output_parts.append(line + '<br>')
            else:
                output_parts.append(escape(line) + '<br>')
            i += 1

    return mark_safe(''.join(output_parts))
