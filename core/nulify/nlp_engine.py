"""
NLP Engine — NLP-based Named Entity Recognition (NER) for PII detection.
Uses Ollama's local LLM API to identify PII entities in text.
"""

import json
import logging
import requests
from django.conf import settings

logger = logging.getLogger(__name__)

# ── Ollama Configuration ──────────────────────────────────────────────
OLLAMA_BASE_URL = getattr(settings, 'OLLAMA_BASE_URL', 'http://localhost:11434')
OLLAMA_NLP_MODEL = getattr(settings, 'OLLAMA_NLP_MODEL', 'llama3.2')
OLLAMA_TIMEOUT = getattr(settings, 'OLLAMA_TIMEOUT', 60)

# ── NER Prompt Template ──────────────────────────────────────────────
NER_SYSTEM_PROMPT = """You are a PII (Personally Identifiable Information) detection expert.
Your task is to identify ALL PII entities in the given text using Named Entity Recognition.

You MUST detect these PII types:
- Email: Email addresses
- Phone: Phone numbers (any format, including Indian +91)
- PAN: Indian PAN numbers (format: ABCDE1234F)
- Aadhaar: Indian Aadhaar numbers (12 digits, may have spaces/dashes)
- IP Address: IPv4 addresses
- Credit Card: Credit card numbers (16 digits, may have spaces/dashes)
- Date of Birth: Dates that appear to be birth dates (DD/MM/YYYY or YYYY-MM-DD)
- Passport: Passport numbers (letter followed by 7 digits)
- Name: Person names
- Address: Physical/postal addresses
- SSN: Social Security Numbers
- Bank Account: Bank account numbers
- Medical ID: Medical record identifiers
- License: Driver's license numbers

IMPORTANT: Respond ONLY with a valid JSON array. No explanation, no markdown.
Each object must have: {"type": "PII_TYPE", "value": "exact_matched_text", "start": char_offset, "end": char_offset}

If no PII is found, respond with: []"""

NER_USER_PROMPT = """Analyze the following text and identify ALL PII entities.
Return ONLY a JSON array with detected entities.

TEXT:
{text}

JSON OUTPUT:"""


def detect_pii_nlp(text):
    """
    Detect PII using NLP-based Named Entity Recognition via Ollama.
    Returns list of dicts: [{'type', 'value', 'start', 'end', 'line', 'method'}]
    """
    if not text or not text.strip():
        return []

    try:
        # Check if Ollama is available
        if not _is_ollama_available():
            logger.warning("Ollama is not available. Skipping NLP detection.")
            return []

        # For very long texts, process in chunks
        max_chunk = 3000  # characters per chunk
        if len(text) > max_chunk:
            return _detect_chunked(text, max_chunk)

        return _detect_single(text)

    except Exception as e:
        logger.error(f"NLP detection error: {e}")
        return []


def _detect_single(text):
    """Run NLP detection on a single text segment."""
    try:
        response = requests.post(
            f"{OLLAMA_BASE_URL}/api/generate",
            json={
                'model': OLLAMA_NLP_MODEL,
                'prompt': NER_USER_PROMPT.format(text=text),
                'system': NER_SYSTEM_PROMPT,
                'stream': False,
                'options': {
                    'temperature': 0.1,  # Low temperature for precise detection
                    'num_predict': 2048,
                },
            },
            timeout=OLLAMA_TIMEOUT,
        )
        response.raise_for_status()
        result = response.json()
        raw_output = result.get('response', '').strip()

        # Parse the JSON response
        detections = _parse_llm_response(raw_output, text)

        # Add method tag and line numbers
        line_starts = _build_line_index(text)
        for d in detections:
            d['method'] = 'nlp'
            d['line'] = _get_line_number(d['start'], line_starts)

        return detections

    except requests.exceptions.Timeout:
        logger.warning("Ollama NLP request timed out.")
        return []
    except requests.exceptions.ConnectionError:
        logger.warning("Cannot connect to Ollama. Is it running?")
        return []
    except Exception as e:
        logger.error(f"NLP single detection error: {e}")
        return []


def _detect_chunked(text, max_chunk):
    """Process long text in chunks for NLP detection."""
    detections = []
    offset = 0

    # Split by paragraphs first, then by size
    paragraphs = text.split('\n')
    current_chunk = ""
    chunk_start = 0

    for para in paragraphs:
        if len(current_chunk) + len(para) + 1 > max_chunk and current_chunk:
            # Process current chunk
            chunk_detections = _detect_single(current_chunk)
            for d in chunk_detections:
                d['start'] += chunk_start
                d['end'] += chunk_start
            detections.extend(chunk_detections)

            chunk_start += len(current_chunk)
            current_chunk = para + '\n'
        else:
            current_chunk += para + '\n'

    # Process remaining chunk
    if current_chunk.strip():
        chunk_detections = _detect_single(current_chunk)
        for d in chunk_detections:
            d['start'] += chunk_start
            d['end'] += chunk_start
        detections.extend(chunk_detections)

    return detections


def _parse_llm_response(raw_output, original_text):
    """Parse the LLM's JSON response into structured detections."""
    detections = []

    # Try to extract JSON from the response
    json_str = _extract_json(raw_output)
    if not json_str:
        return []

    try:
        parsed = json.loads(json_str)
        if not isinstance(parsed, list):
            return []

        for item in parsed:
            if not isinstance(item, dict):
                continue

            pii_type = item.get('type', '').strip()
            value = item.get('value', '').strip()

            if not pii_type or not value:
                continue

            # Normalize PII type names
            pii_type = _normalize_pii_type(pii_type)

            # Try to find the exact position in original text
            start = item.get('start')
            end = item.get('end')

            # Validate/fix positions by searching for the value in text
            if start is not None and end is not None:
                # Verify the position matches
                actual = original_text[start:end] if 0 <= start < len(original_text) and end <= len(original_text) else None
                if actual != value:
                    # LLM gave wrong position, search for it
                    start, end = _find_value_in_text(value, original_text)
            else:
                start, end = _find_value_in_text(value, original_text)

            if start is not None and end is not None:
                detections.append({
                    'type': pii_type,
                    'value': value,
                    'start': start,
                    'end': end,
                })

    except (json.JSONDecodeError, TypeError, KeyError) as e:
        logger.warning(f"Failed to parse NLP response: {e}")

    return detections


def _extract_json(text):
    """Extract JSON array from LLM response text."""
    text = text.strip()

    # If it starts with [ and ends with ], try direct parse
    if text.startswith('[') and text.endswith(']'):
        return text

    # Try to find JSON array in the text
    bracket_start = text.find('[')
    bracket_end = text.rfind(']')

    if bracket_start != -1 and bracket_end != -1 and bracket_end > bracket_start:
        return text[bracket_start:bracket_end + 1]

    # Try to find in markdown code blocks
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


def _normalize_pii_type(pii_type):
    """Normalize PII type names from LLM to match our standard types."""
    mapping = {
        'email': 'Email',
        'email address': 'Email',
        'e-mail': 'Email',
        'phone': 'Phone',
        'phone number': 'Phone',
        'mobile': 'Phone',
        'mobile number': 'Phone',
        'telephone': 'Phone',
        'pan': 'PAN',
        'pan number': 'PAN',
        'pan card': 'PAN',
        'aadhaar': 'Aadhaar',
        'aadhar': 'Aadhaar',
        'aadhaar number': 'Aadhaar',
        'aadhar number': 'Aadhaar',
        'ip': 'IP Address',
        'ip address': 'IP Address',
        'ipv4': 'IP Address',
        'credit card': 'Credit Card',
        'credit card number': 'Credit Card',
        'card number': 'Credit Card',
        'cc': 'Credit Card',
        'dob': 'Date of Birth',
        'date of birth': 'Date of Birth',
        'birth date': 'Date of Birth',
        'birthday': 'Date of Birth',
        'passport': 'Passport',
        'passport number': 'Passport',
        'name': 'Name',
        'person name': 'Name',
        'full name': 'Name',
        'first name': 'Name',
        'last name': 'Name',
        'address': 'Address',
        'physical address': 'Address',
        'postal address': 'Address',
        'mailing address': 'Address',
        'ssn': 'SSN',
        'social security': 'SSN',
        'social security number': 'SSN',
        'bank account': 'Bank Account',
        'bank account number': 'Bank Account',
        'account number': 'Bank Account',
        'upi': 'UPI ID',
        'upi id': 'UPI ID',
        'medical id': 'Medical ID',
        'medical record': 'Medical ID',
        'license': 'License',
        'driver license': 'License',
        'driving license': 'License',
    }
    return mapping.get(pii_type.lower().strip(), pii_type.title())


def _find_value_in_text(value, text):
    """Find the start and end position of a value in text."""
    idx = text.find(value)
    if idx != -1:
        return idx, idx + len(value)
    # Case-insensitive search
    idx = text.lower().find(value.lower())
    if idx != -1:
        return idx, idx + len(value)
    return None, None


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


def _is_ollama_available():
    """Check if Ollama server is running and the model is available."""
    try:
        resp = requests.get(f"{OLLAMA_BASE_URL}/api/tags", timeout=5)
        if resp.status_code == 200:
            models = resp.json().get('models', [])
            model_names = [m.get('name', '').split(':')[0] for m in models]
            if OLLAMA_NLP_MODEL.split(':')[0] in model_names:
                return True
            logger.warning(f"Ollama model '{OLLAMA_NLP_MODEL}' not found. Available: {model_names}")
            return False
        return False
    except Exception:
        return False


def get_ollama_status():
    """Get the current status of Ollama connection and available models."""
    try:
        resp = requests.get(f"{OLLAMA_BASE_URL}/api/tags", timeout=5)
        if resp.status_code == 200:
            models = resp.json().get('models', [])
            model_names = [m.get('name', '') for m in models]
            return {
                'available': True,
                'url': OLLAMA_BASE_URL,
                'models': model_names,
                'nlp_model': OLLAMA_NLP_MODEL,
                'nlp_ready': OLLAMA_NLP_MODEL.split(':')[0] in [n.split(':')[0] for n in model_names],
            }
        return {'available': False, 'url': OLLAMA_BASE_URL, 'error': f'Status {resp.status_code}'}
    except requests.exceptions.ConnectionError:
        return {'available': False, 'url': OLLAMA_BASE_URL, 'error': 'Cannot connect to Ollama'}
    except Exception as e:
        return {'available': False, 'url': OLLAMA_BASE_URL, 'error': str(e)}
