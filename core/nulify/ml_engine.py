"""
ML Engine — Machine Learning-based PII classification and confidence scoring.
Uses Ollama's local LLM API for ML-powered PII validation and context analysis.
"""

import json
import logging
import requests
from django.conf import settings

logger = logging.getLogger(__name__)

# ── Ollama Configuration ──────────────────────────────────────────────
OLLAMA_BASE_URL = getattr(settings, 'OLLAMA_BASE_URL', 'http://localhost:11434')
OLLAMA_ML_MODEL = getattr(settings, 'OLLAMA_ML_MODEL', 'qwen2.5:0.5b')
OLLAMA_TIMEOUT = getattr(settings, 'OLLAMA_TIMEOUT', 120)

# ── ML Classification Prompt ─────────────────────────────────────────
ML_SYSTEM_PROMPT = """You are a PII (Personally Identifiable Information) validation expert.
Your task is to analyze detected PII candidates and classify each one with a confidence score.

For each PII candidate, you must determine:
1. Whether it is TRULY PII (true positive) or a false positive
2. A confidence score from 0.0 to 1.0
3. The sensitivity level: "low", "medium", "high", or "critical"

Classification guidelines:
- Email: Must be a valid email format → high confidence if valid
- Phone: Must be a plausible phone number → check digit count and format
- PAN: Must match Indian PAN format (5 letters, 4 digits, 1 letter) → high confidence
- Aadhaar: Must be exactly 12 digits → check if it's plausible (not all zeros/ones)
- IP Address: Must be valid IPv4 → not localhost or internal unless in context
- Credit Card: Must pass Luhn check → critical sensitivity
- Date of Birth: Must be a plausible birth date → context matters
- Passport: Must match passport format → verify context
- Name: Could be a real person's name → check context for surrounding keywords
- Address: Physical location → check for street/city/zipcode patterns

Sensitivity levels:
- critical: Financial data (Credit Card, Bank Account)
- high: Government IDs (PAN, Aadhaar, Passport, SSN)
- medium: Contact info (Email, Phone, Address)
- low: General info (Date of Birth, Name, IP Address)

Respond ONLY with a valid JSON array. Each object must have:
{"value": "the_pii_text", "is_pii": true/false, "confidence": 0.0-1.0, "sensitivity": "low/medium/high/critical", "reason": "brief explanation"}"""

ML_USER_PROMPT = """Analyze the following PII candidates detected from a document.
For each candidate, classify whether it is truly PII and assign a confidence score.

CONTEXT (surrounding text):
{context}

PII CANDIDATES:
{candidates}

JSON OUTPUT:"""


def classify_pii_ml(text, detections):
    """
    Use ML (Ollama LLM) to validate and score PII detections.
    Adds 'confidence', 'sensitivity', and 'is_valid' fields to each detection.

    Args:
        text: Original text for context
        detections: List of dicts with 'type', 'value', 'start', 'end'

    Returns:
        Enhanced detections with ML confidence scores, or original detections
        with default scores if Ollama is unavailable.
    """
    if not detections:
        return detections

    try:
        if not _is_ollama_available():
            logger.warning("Ollama unavailable. Using default ML scores.")
            return _apply_default_scores(detections)

        # Build candidates string
        candidates_str = "\n".join([
            f"- Type: {d['type']}, Value: \"{d['value']}\""
            for d in detections
        ])

        # Get surrounding context (truncate if too long)
        context = text[:2000] if len(text) > 2000 else text

        response = requests.post(
            f"{OLLAMA_BASE_URL}/api/generate",
            json={
                'model': OLLAMA_ML_MODEL,
                'prompt': ML_USER_PROMPT.format(context=context, candidates=candidates_str),
                'system': ML_SYSTEM_PROMPT,
                'stream': False,
                'options': {
                    'temperature': 0.1,
                    'num_predict': 2048,
                },
            },
            timeout=OLLAMA_TIMEOUT,
        )
        response.raise_for_status()
        result = response.json()
        raw_output = result.get('response', '').strip()

        # Parse ML classifications
        classifications = _parse_ml_response(raw_output)

        # Merge ML results into detections
        return _merge_classifications(detections, classifications)

    except Exception as e:
        logger.error(f"ML classification error: {e}")
        return _apply_default_scores(detections)


def _parse_ml_response(raw_output):
    """Parse ML classification response from LLM."""
    try:
        json_str = _extract_json(raw_output)
        if not json_str:
            return []

        parsed = json.loads(json_str)
        if not isinstance(parsed, list):
            return []

        classifications = []
        for item in parsed:
            if not isinstance(item, dict):
                continue
            classifications.append({
                'value': item.get('value', ''),
                'is_pii': item.get('is_pii', True),
                'confidence': min(1.0, max(0.0, float(item.get('confidence', 0.5)))),
                'sensitivity': item.get('sensitivity', 'medium'),
                'reason': item.get('reason', ''),
            })
        return classifications

    except (json.JSONDecodeError, TypeError, ValueError) as e:
        logger.warning(f"Failed to parse ML response: {e}")
        return []


def _merge_classifications(detections, classifications):
    """Merge ML classifications into detection results."""
    # Build lookup by value
    cl_map = {}
    for cl in classifications:
        cl_map[cl['value']] = cl

    enhanced = []
    for d in detections:
        d_copy = dict(d)
        cl = cl_map.get(d['value'])

        if cl:
            d_copy['confidence'] = cl['confidence']
            d_copy['sensitivity'] = cl['sensitivity']
            d_copy['is_valid'] = cl['is_pii']
            d_copy['ml_reason'] = cl.get('reason', '')
        else:
            # No ML result for this detection — use defaults
            defaults = _get_default_score(d['type'])
            d_copy.update(defaults)

        # Ensure method is set
        if 'method' not in d_copy:
            d_copy['method'] = d.get('method', 'regex')

        enhanced.append(d_copy)

    return enhanced


def _apply_default_scores(detections):
    """Apply default confidence scores when ML is unavailable."""
    enhanced = []
    for d in detections:
        d_copy = dict(d)
        defaults = _get_default_score(d['type'])
        d_copy.update(defaults)
        if 'method' not in d_copy:
            d_copy['method'] = d.get('method', 'regex')
        enhanced.append(d_copy)
    return enhanced


def _get_default_score(pii_type):
    """Get default confidence/sensitivity for a PII type (when ML is unavailable)."""
    defaults = {
        'Email': {'confidence': 0.95, 'sensitivity': 'medium', 'is_valid': True, 'ml_reason': 'Regex match'},
        'Phone': {'confidence': 0.80, 'sensitivity': 'medium', 'is_valid': True, 'ml_reason': 'Regex match'},
        'PAN': {'confidence': 0.90, 'sensitivity': 'high', 'is_valid': True, 'ml_reason': 'Regex match'},
        'Aadhaar': {'confidence': 0.85, 'sensitivity': 'high', 'is_valid': True, 'ml_reason': 'Regex match'},
        'IP Address': {'confidence': 0.75, 'sensitivity': 'low', 'is_valid': True, 'ml_reason': 'Regex match'},
        'Credit Card': {'confidence': 0.90, 'sensitivity': 'critical', 'is_valid': True, 'ml_reason': 'Regex + Luhn'},
        'Date of Birth': {'confidence': 0.60, 'sensitivity': 'low', 'is_valid': True, 'ml_reason': 'Regex match'},
        'Passport': {'confidence': 0.70, 'sensitivity': 'high', 'is_valid': True, 'ml_reason': 'Regex match'},
        'UPI ID': {'confidence': 0.75, 'sensitivity': 'medium', 'is_valid': True, 'ml_reason': 'Regex match'},
        'Name': {'confidence': 0.65, 'sensitivity': 'low', 'is_valid': True, 'ml_reason': 'NLP entity'},
        'Address': {'confidence': 0.70, 'sensitivity': 'medium', 'is_valid': True, 'ml_reason': 'NLP entity'},
        'SSN': {'confidence': 0.85, 'sensitivity': 'critical', 'is_valid': True, 'ml_reason': 'Pattern match'},
        'Bank Account': {'confidence': 0.80, 'sensitivity': 'critical', 'is_valid': True, 'ml_reason': 'Pattern match'},
    }
    return defaults.get(pii_type, {
        'confidence': 0.50,
        'sensitivity': 'medium',
        'is_valid': True,
        'ml_reason': 'Unknown type',
    })


def _extract_json(text):
    """Extract JSON array from LLM response text."""
    text = text.strip()

    if text.startswith('[') and text.endswith(']'):
        return text

    bracket_start = text.find('[')
    bracket_end = text.rfind(']')
    if bracket_start != -1 and bracket_end != -1 and bracket_end > bracket_start:
        return text[bracket_start:bracket_end + 1]

    if '```json' in text:
        start = text.find('```json') + 7
        end = text.find('```', start)
        if end > start:
            return text[start:end].strip()

    if '```' in text:
        start = text.find('```') + 3
        end = text.find('```', start)
        if end > start:
            candidate = text[start:end].strip()
            if candidate.startswith('['):
                return candidate

    return None


def _is_ollama_available():
    """Check if Ollama server is running."""
    try:
        resp = requests.get(f"{OLLAMA_BASE_URL}/api/tags", timeout=5)
        return resp.status_code == 200
    except Exception:
        return False
