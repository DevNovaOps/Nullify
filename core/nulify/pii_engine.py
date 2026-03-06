"""
PII Detection Engine — Combined multi-method PII detection.
Supports three detection techniques:
  1. Regex-based detection (rule-based, always available)
  2. NLP-based Named Entity Recognition via Ollama
  3. ML-based confidence scoring and validation via Ollama
"""

import re
import logging
from .nlp_engine import detect_pii_nlp, get_ollama_status
from .ml_engine import classify_pii_ml

logger = logging.getLogger(__name__)

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
    'Name': 2,
    'Address': 5,
    'SSN': 10,
    'Bank Account': 9,
    'Medical ID': 6,
    'License': 6,
}


# ══════════════════════════════════════════════════════════════════════
#  COMBINED DETECTION
# ══════════════════════════════════════════════════════════════════════

def detect_pii(text, methods=None):
    """
    Scan text for PII using multiple detection methods.

    Args:
        text: The text to scan
        methods: List of methods to use. Options: ['regex', 'nlp', 'ml']
                 Default: all available methods

    Returns:
        List of dicts: [{'type', 'value', 'start', 'end', 'line', 'method',
                         'confidence', 'sensitivity'}]
    """
    if not text:
        return []

    if methods is None:
        methods = ['regex', 'nlp', 'ml']

    all_detections = []

    # ── Step 1: Regex Detection (always fast and reliable) ────────
    if 'regex' in methods:
        regex_detections = _detect_regex(text)
        all_detections.extend(regex_detections)
        logger.info(f"Regex detected {len(regex_detections)} PII items")

    # ── Step 2: NLP Detection via Ollama ──────────────────────────
    if 'nlp' in methods:
        try:
            nlp_detections = detect_pii_nlp(text)
            # Merge NLP results (avoid duplicates with regex)
            new_nlp = _deduplicate(nlp_detections, all_detections)
            all_detections.extend(new_nlp)
            logger.info(f"NLP detected {len(nlp_detections)} items ({len(new_nlp)} new)")
        except Exception as e:
            logger.warning(f"NLP detection skipped: {e}")

    # ── Step 3: ML Classification (enhance with confidence) ───────
    if 'ml' in methods:
        try:
            all_detections = classify_pii_ml(text, all_detections)
            logger.info(f"ML classification applied to {len(all_detections)} items")
        except Exception as e:
            logger.warning(f"ML classification skipped: {e}")

    # Filter out false positives (is_valid == False)
    all_detections = [
        d for d in all_detections
        if d.get('is_valid', True) is True
    ]

    # Sort by position
    all_detections.sort(key=lambda d: d.get('start', 0))
    return all_detections


def detect_pii_regex_only(text):
    """Regex-only detection (for backward compatibility and instant scan)."""
    if not text:
        return []
    return _detect_regex(text)


# ══════════════════════════════════════════════════════════════════════
#  REGEX DETECTION
# ══════════════════════════════════════════════════════════════════════

def _detect_regex(text):
    """Scan text for PII using regex patterns only."""
    detections = []
    occupied = set()

    # Build line index
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
        return lo

    for pii_type in PII_PRIORITY:
        pattern = PII_PATTERNS[pii_type]
        for match in pattern.finditer(text):
            start, end = match.start(), match.end()
            if any(pos in occupied for pos in range(start, end)):
                continue

            value = match.group()

            # Additional validation
            if pii_type == 'Aadhaar':
                digits = re.sub(r'[\s\-]', '', value)
                if len(digits) != 12:
                    continue
                if len(digits) > 12:
                    continue
            if pii_type == 'Credit Card':
                digits = re.sub(r'[\s\-]', '', value)
                if len(digits) != 16:
                    continue
                if not _luhn_check(digits):
                    continue
            if pii_type == 'IP Address':
                octets = value.split('.')
                if any(int(o) > 255 for o in octets):
                    continue
            if pii_type == 'UPI ID':
                if '@' in value and '.' in value.split('@')[1]:
                    continue

            for pos in range(start, end):
                occupied.add(pos)

            detections.append({
                'type': pii_type,
                'value': value,
                'start': start,
                'end': end,
                'line': get_line_number(start),
                'method': 'regex',
            })

    detections.sort(key=lambda d: d['start'])
    return detections


# ══════════════════════════════════════════════════════════════════════
#  DEDUPLICATION
# ══════════════════════════════════════════════════════════════════════

def _deduplicate(new_detections, existing_detections):
    """Remove detections that overlap with already found ones."""
    if not existing_detections:
        return new_detections

    # Build set of occupied positions from existing detections
    occupied = set()
    for d in existing_detections:
        for pos in range(d.get('start', 0), d.get('end', 0)):
            occupied.add(pos)

    unique = []
    for d in new_detections:
        start = d.get('start', 0)
        end = d.get('end', 0)
        # Check if more than 50% of the detection overlaps
        overlap = sum(1 for pos in range(start, end) if pos in occupied)
        total = max(1, end - start)
        if overlap / total < 0.5:
            unique.append(d)

    return unique


# ══════════════════════════════════════════════════════════════════════
#  UTILITIES
# ══════════════════════════════════════════════════════════════════════

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
    Calculate 0-100 risk score based on detected PII.
    If ML confidence is available, weight by confidence.
    """
    if not detections:
        return 0

    total_weight = 0
    for d in detections:
        pii_type = d['type'] if isinstance(d, dict) else d.pii_type
        weight = PII_WEIGHTS.get(pii_type, 1)
        confidence = d.get('confidence', 1.0) if isinstance(d, dict) else 1.0
        total_weight += weight * confidence

    score = min(100, int((total_weight / 50) * 100))
    return max(1, score)


def get_pii_summary(detections):
    """Group detections by type with counts."""
    summary = {}
    for d in detections:
        pii_type = d['type'] if isinstance(d, dict) else d.pii_type
        summary[pii_type] = summary.get(pii_type, 0) + 1
    return summary


def get_method_summary(detections):
    """Group detections by detection method."""
    summary = {'regex': 0, 'nlp': 0, 'ml': 0}
    for d in detections:
        method = d.get('method', 'regex') if isinstance(d, dict) else 'regex'
        if method in summary:
            summary[method] += 1
        else:
            summary[method] = 1
    return summary


def get_detection_methods_available():
    """Check which detection methods are currently available."""
    status = get_ollama_status()
    return {
        'regex': True,  # Always available
        'nlp': status.get('nlp_ready', False),
        'ml': status.get('available', False),
        'ollama_status': status,
    }
