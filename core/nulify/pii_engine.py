"""
PII Detection Engine — Rule-based regex detection for personally identifiable information.
No AI/ML models — pure regex pattern matching.
"""

import re

# ── PII Regex Patterns ──────────────────────────────────────────────
PII_PATTERNS = {
    'Email': re.compile(
        r'[a-zA-Z0-9._%+\-]+@[a-zA-Z0-9.\-]+\.[a-zA-Z]{2,}',
        re.IGNORECASE
    ),
    'Phone': re.compile(
        r'(?:\+91[\s\-]?)?(?:\(?0?\d{2,4}\)?[\s\-]?)?\d{5}[\s\-]?\d{5}'
        r'|(?:\+91[\s\-]?)?[6-9]\d{9}'
        r'|\b\d{3}[\s\-]\d{3}[\s\-]\d{4}\b',
    ),
    'PAN': re.compile(
        r'\b[A-Z]{5}\d{4}[A-Z]\b'
    ),
    'Aadhaar': re.compile(
        r'\b\d{4}[\s\-]?\d{4}[\s\-]?\d{4}\b'
    ),
    'IP Address': re.compile(
        r'\b(?:(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\.){3}(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\b'
    ),
    'Credit Card': re.compile(
        r'\b(?:\d{4}[\s\-]?){3}\d{4}\b'
    ),
    'Date of Birth': re.compile(
        r'\b(?:0[1-9]|[12]\d|3[01])[/\-](?:0[1-9]|1[0-2])[/\-](?:19|20)\d{2}\b'
        r'|\b(?:19|20)\d{2}[/\-](?:0[1-9]|1[0-2])[/\-](?:0[1-9]|[12]\d|3[01])\b'
    ),
    'Passport': re.compile(
        r'\b[A-Z]\d{7}\b'
    ),
    'UPI ID': re.compile(
        r'[a-zA-Z0-9.\-_]+@[a-zA-Z]{2,}',
        re.IGNORECASE
    ),
}

# Priority order for overlapping patterns (higher-weight types checked first)
PII_PRIORITY = [
    'Email', 'Credit Card', 'Aadhaar', 'PAN', 'Phone',
    'IP Address', 'Date of Birth', 'Passport', 'UPI ID',
]

# Risk weights for score calculation
PII_WEIGHTS = {
    'Email': 3,
    'Phone': 3,
    'PAN': 8,
    'Aadhaar': 10,
    'IP Address': 2,
    'Credit Card': 9,
    'Date of Birth': 2,
    'Passport': 7,
    'UPI ID': 4,
}


def detect_pii(text):
    """
    Scan text for PII using regex patterns.
    Returns list of dicts: [{'type', 'value', 'start', 'end', 'line'}]
    """
    if not text:
        return []

    detections = []
    occupied = set()  # track character positions already matched

    # Build line index for line number lookup
    line_starts = [0]
    for i, ch in enumerate(text):
        if ch == '\n':
            line_starts.append(i + 1)

    def get_line_number(pos):
        lo, hi = 0, len(line_starts) - 1
        while lo <= hi:
            mid = (lo + hi) // 2
            if line_starts[mid] <= pos:
                lo = mid + 1
            else:
                hi = mid - 1
        return lo  # 1-indexed

    for pii_type in PII_PRIORITY:
        pattern = PII_PATTERNS[pii_type]
        for match in pattern.finditer(text):
            start, end = match.start(), match.end()
            # Skip if this region overlaps with a higher-priority match
            if any(pos in occupied for pos in range(start, end)):
                continue
            # Additional validation for specific types
            value = match.group()
            if pii_type == 'Aadhaar':
                digits = re.sub(r'[\s\-]', '', value)
                if len(digits) != 12:
                    continue
                # Skip if it looks like a credit card (16 digits)
                if len(digits) > 12:
                    continue
            if pii_type == 'Credit Card':
                digits = re.sub(r'[\s\-]', '', value)
                if len(digits) != 16:
                    continue
                # Luhn check (basic)
                if not _luhn_check(digits):
                    continue
            if pii_type == 'IP Address':
                octets = value.split('.')
                if any(int(o) > 255 for o in octets):
                    continue
            if pii_type == 'UPI ID':
                # Skip if already detected as email
                if '@' in value and '.' in value.split('@')[1]:
                    continue

            # Mark positions as occupied
            for pos in range(start, end):
                occupied.add(pos)

            detections.append({
                'type': pii_type,
                'value': value,
                'start': start,
                'end': end,
                'line': get_line_number(start),
            })

    # Sort by position
    detections.sort(key=lambda d: d['start'])
    return detections


def _luhn_check(card_number):
    """Luhn algorithm to validate credit card numbers."""
    try:
        digits = [int(d) for d in card_number]
        odd_digits = digits[-1::-2]
        even_digits = digits[-2::-2]
        total = sum(odd_digits)
        for d in even_digits:
            total += sum(divmod(d * 2, 10))
        return total % 10 == 0
    except (ValueError, IndexError):
        return False


def calculate_risk_score(detections):
    """
    Calculate a 0-100 risk score based on detected PII types and counts.
    Example: 5 emails + 3 phones + 1 PAN + 1 Aadhaar → ~82%
    """
    if not detections:
        return 0

    total_weight = 0
    for d in detections:
        weight = PII_WEIGHTS.get(d['type'] if isinstance(d, dict) else d.pii_type, 1)
        total_weight += weight

    score = min(100, int((total_weight / 50) * 100))
    return max(1, score)  # Minimum 1% if any PII found


def get_pii_summary(detections):
    """Group detections by type with counts."""
    summary = {}
    for d in detections:
        pii_type = d['type'] if isinstance(d, dict) else d.pii_type
        summary[pii_type] = summary.get(pii_type, 0) + 1
    return summary
