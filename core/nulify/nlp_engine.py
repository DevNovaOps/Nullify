"""
NLP Engine — NLP-based Named Entity Recognition (NER) for PII detection.
Uses spaCy's local NER pipeline for fast, offline entity detection.
"""

import logging

logger = logging.getLogger(__name__)

# ── spaCy Configuration ──────────────────────────────────────────────
_nlp = None  # Lazy-loaded spaCy model


def _get_nlp():
    """Lazy-load the spaCy model (loads once, reuses on subsequent calls)."""
    global _nlp
    if _nlp is None:
        try:
            import spacy
            _nlp = spacy.load('en_core_web_sm')
            logger.info("spaCy model 'en_core_web_sm' loaded successfully.")
        except Exception as e:
            logger.error(f"Failed to load spaCy model: {e}")
            return None
    return _nlp


# ── Entity label → PII type mapping ─────────────────────────────────
SPACY_LABEL_MAP = {
    'PERSON': 'Name',
    'GPE': 'Address',          # Geo-Political Entity (city, country)
    'LOC': 'Address',          # Locations
    'FAC': 'Address',          # Facilities (buildings, airports)
    'ORG': 'Organization',     # Organizations
    'DATE': 'Date of Birth',   # Dates (contextual — may not always be DOB)
    'CARDINAL': None,          # Skip plain numbers
    'ORDINAL': None,
    'MONEY': None,
    'PERCENT': None,
    'TIME': None,
    'QUANTITY': None,
    'WORK_OF_ART': None,
    'LAW': None,
    'LANGUAGE': None,
    'EVENT': None,
    'PRODUCT': None,
    'NORP': None,              # Nationalities, religious groups
}


def detect_pii_nlp(text):
    """
    Detect PII using spaCy's Named Entity Recognition.
    Returns list of dicts: [{'type', 'value', 'start', 'end', 'line', 'method'}]
    
    This runs locally and is extremely fast (milliseconds).
    """
    if not text or not text.strip():
        return []

    nlp = _get_nlp()
    if nlp is None:
        logger.warning("spaCy is not available. Skipping NLP detection.")
        return []

    try:
        # Process text (limit to 100k chars for very large files)
        max_chars = 100000
        process_text = text[:max_chars] if len(text) > max_chars else text

        # Increase max_length if needed
        nlp.max_length = max(nlp.max_length, len(process_text) + 1000)

        doc = nlp(process_text)

        # Build line index for line number lookup
        line_starts = _build_line_index(process_text)

        detections = []
        seen_values = set()  # Avoid duplicates from spaCy

        for ent in doc.ents:
            pii_type = SPACY_LABEL_MAP.get(ent.label_)
            if pii_type is None:
                continue

            value = ent.text.strip()
            if not value or len(value) < 2:
                continue

            # Skip very short names (likely false positives)
            if pii_type == 'Name' and len(value) < 4:
                continue

            # Skip generic organization names
            if pii_type == 'Organization' and len(value) < 3:
                continue

            # Dedupe within spaCy results
            dedup_key = (pii_type, value, ent.start_char)
            if dedup_key in seen_values:
                continue
            seen_values.add(dedup_key)

            detections.append({
                'type': pii_type,
                'value': value,
                'start': ent.start_char,
                'end': ent.end_char,
                'line': _get_line_number(ent.start_char, line_starts),
                'method': 'nlp',
            })

        logger.info(f"spaCy NER detected {len(detections)} entities.")
        return detections

    except Exception as e:
        logger.error(f"spaCy NLP detection error: {e}")
        return []


def _build_line_index(text):
    """Build a line starts index for line number lookup."""
    line_starts = [0]
    for i, ch in enumerate(text):
        if ch == '\n':
            line_starts.append(i + 1)
    return line_starts


def _get_line_number(pos, line_starts):
    """Get 1-indexed line number for a character position."""
    lo, hi = 0, len(line_starts) - 1
    while lo <= hi:
        mid = (lo + hi) // 2
        if line_starts[mid] <= pos:
            lo = mid + 1
        else:
            hi = mid - 1
    return lo


def get_ollama_status():
    """
    Get NLP engine status - now reports spaCy status instead of Ollama.
    Kept for backward compatibility with existing views.
    """
    nlp = _get_nlp()
    if nlp is not None:
        return {
            'available': True,
            'engine': 'spaCy',
            'model': 'en_core_web_sm',
            'nlp_ready': True,
            'models': ['en_core_web_sm'],
        }
    return {
        'available': False,
        'engine': 'spaCy',
        'error': 'spaCy model not loaded',
        'nlp_ready': False,
    }
