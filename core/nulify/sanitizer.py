"""
Sanitization Engine — Replace PII with masked/redacted/tokenized values.
Three methods: Masking, Redaction, Tokenization.
"""

import uuid
import re


def sanitize_text(text, detections, method='redaction'):
    """
    Apply sanitization to text using the specified method.
    detections: list of dicts with 'type', 'value', 'start', 'end'
    method: 'masking' | 'redaction' | 'tokenization'
    Returns sanitized text string.
    """
    if not detections:
        return text

    # Sort by start position descending to avoid offset issues
    sorted_detections = sorted(detections, key=lambda d: d['start'], reverse=True)

    sanitized = text
    for d in sorted_detections:
        start = d['start']
        end = d['end']
        original = d['value']
        pii_type = d['type']

        replacement = _get_replacement(original, pii_type, method)
        sanitized = sanitized[:start] + replacement + sanitized[end:]

    return sanitized


def _get_replacement(original, pii_type, method):
    """Generate replacement string based on sanitization method."""
    if method == 'redaction':
        return f'[REDACTED]'

    elif method == 'masking':
        return _mask_value(original, pii_type)

    elif method == 'tokenization':
        token = uuid.uuid4().hex[:8].upper()
        return f'TOK_{pii_type.upper().replace(" ", "_")}_{token}'

    return '[REDACTED]'


def _mask_value(original, pii_type):
    """Apply masking — show partial characters, hide the rest."""
    if pii_type == 'Email':
        parts = original.split('@')
        if len(parts) == 2:
            name = parts[0]
            if len(name) <= 2:
                masked_name = '*' * len(name)
            else:
                masked_name = name[0] + '*' * (len(name) - 2) + name[-1]
            return f"{masked_name}@{parts[1]}"

    elif pii_type == 'Phone':
        digits_only = re.sub(r'[^\d]', '', original)
        if len(digits_only) >= 4:
            return '*' * (len(digits_only) - 4) + digits_only[-4:]
        return '*' * len(original)

    elif pii_type == 'PAN':
        if len(original) >= 4:
            return original[:2] + '*' * (len(original) - 4) + original[-2:]
        return '*' * len(original)

    elif pii_type == 'Aadhaar':
        clean = re.sub(r'[\s\-]', '', original)
        if len(clean) == 12:
            return 'XXXX-XXXX-' + clean[-4:]
        return '*' * len(original)

    elif pii_type == 'Credit Card':
        clean = re.sub(r'[\s\-]', '', original)
        if len(clean) >= 4:
            return '*' * (len(clean) - 4) + clean[-4:]
        return '*' * len(original)

    elif pii_type == 'IP Address':
        parts = original.split('.')
        if len(parts) == 4:
            return f"{parts[0]}.***.***{parts[3]}"
        return '***.***.***.***'

    elif pii_type == 'Date of Birth':
        return '**/**/****'

    elif pii_type == 'Passport':
        if len(original) >= 3:
            return original[0] + '*' * (len(original) - 2) + original[-1]
        return '*' * len(original)

    elif pii_type == 'UPI ID':
        parts = original.split('@')
        if len(parts) == 2:
            return '****@' + parts[1]
        return '****'

    # Default: mask all but first and last char
    if len(original) > 2:
        return original[0] + '*' * (len(original) - 2) + original[-1]
    return '*' * len(original)
