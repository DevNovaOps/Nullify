"""
Image Sanitizer — Redact PII regions on images using bounding boxes from OCR.
Supports three methods: redaction (black rectangles), masking (pixelation),
and tokenization (colored overlay with label).
"""

import logging
from io import BytesIO

logger = logging.getLogger(__name__)


def _get_font(size):
    from PIL import ImageFont
    try:
        return ImageFont.truetype("arial.ttf", size)
    except (OSError, IOError):
        try:
            return ImageFont.truetype("/usr/share/fonts/truetype/dejavu/DejaVuSans-Bold.ttf", size)
        except (OSError, IOError):
            return ImageFont.load_default()

def sanitize_image(image_path, detections, boxes, full_text, method='redaction'):
    """
    Create a sanitized copy of the image with PII regions processed.
    Draws replacement text over the original bounding box.
    """
    from PIL import Image, ImageDraw, ImageFont
    from nulify.sanitizer import _get_replacement

    img = Image.open(image_path).copy()
    if img.mode != 'RGB':
        img = img.convert('RGB')
        
    draw = ImageDraw.Draw(img)
    padding = 2

    if not detections or not boxes:
        buf = BytesIO()
        img.save(buf, format='PNG')
        buf.seek(0)
        return buf

    # Build character to box map
    char_to_box = {}
    pos = 0
    for b_idx, box in enumerate(boxes):
        word = box['text']
        word_start = full_text.find(word, pos)
        if word_start == -1:
            word_start = full_text.find(word, max(0, pos - 10))
        if word_start == -1:
            continue
        for ci in range(word_start, word_start + len(word)):
            char_to_box[ci] = b_idx
        pos = word_start + len(word)

    for det in detections:
        start = det.get('start', 0)
        end = det.get('end', 0)
        
        # Find all boxes for this detection
        b_indices = set()
        for ci in range(start, end):
            b_idx = char_to_box.get(ci)
            if b_idx is not None:
                b_indices.add(b_idx)
                
        if not b_indices:
            continue
            
        det_boxes = [boxes[i] for i in b_indices]
        
        # Calculate merged bounding box
        x1 = min(b['x'] for b in det_boxes) - padding
        y1 = min(b['y'] for b in det_boxes) - padding
        x2 = max(b['x'] + b['w'] for b in det_boxes) + padding
        y2 = max(b['y'] + b['h'] for b in det_boxes) + padding

        original = det.get('value', '')
        pii_type = det.get('type', 'PII')
        replacement = _get_replacement(original, pii_type, method)

        if method == 'masking' and pii_type in ('Address', 'Device ID', 'Fingerprint', 'Face Template'):
            if all(c in '*█.' for c in replacement):
                draw.rectangle([x1, y1, x2, y2], fill='black')
                continue

        if method == 'redaction':
            bg_color = 'black'
            text_color = 'white'
        elif method == 'tokenization':
            bg_color = (103, 58, 183) # Purple
            text_color = 'white'
        else: # masking
            bg_color = 'white'
            text_color = 'black'

        draw.rectangle([x1, y1, x2, y2], fill=bg_color)

        box_h = max(2, y2 - y1)
        box_w = max(2, x2 - x1)
        font_size = max(10, min(box_h - 2, 24))
        font = _get_font(font_size)
        
        text_bbox = draw.textbbox((0, 0), replacement, font=font)
        tw = text_bbox[2] - text_bbox[0]
        while tw > box_w and font_size > 8:
            font_size -= 1
            font = _get_font(font_size)
            text_bbox = draw.textbbox((0, 0), replacement, font=font)
            tw = text_bbox[2] - text_bbox[0]

        th = text_bbox[3] - text_bbox[1]
        tx = x1 + max(0, (box_w - tw) // 2)
        ty = y1 + max(0, (box_h - th) // 2)
        draw.text((tx, ty), replacement, fill=text_color, font=font)

    buf = BytesIO()
    img.save(buf, format='PNG')
    buf.seek(0)
    return buf


def _find_pii_boxes(detections, boxes, full_text):
    """
    Map text-based PII detections to their corresponding OCR bounding boxes.

    Strategy:
      1. Build a character-to-box mapping by replaying how the text was assembled.
      2. For each PII detection (start, end), find all boxes that contributed
         characters in that range.
    """
    if not detections or not boxes:
        return []

    # Rebuild the character position → box index mapping
    char_to_box = {}
    pos = 0

    for b_idx, box in enumerate(boxes):
        word = box['text']
        word_start = full_text.find(word, pos)
        if word_start == -1:
            word_start = full_text.find(word, max(0, pos - 10))
        if word_start == -1:
            continue

        for ci in range(word_start, word_start + len(word)):
            char_to_box[ci] = b_idx

        pos = word_start + len(word)

    # For each detection, collect all boxes that overlap with its character range
    pii_boxes = []
    seen_box_indices = set()

    for det in detections:
        start = det['start']
        end = det['end']

        for char_pos in range(start, end):
            b_idx = char_to_box.get(char_pos)
            if b_idx is not None and b_idx not in seen_box_indices:
                seen_box_indices.add(b_idx)
                pii_boxes.append(boxes[b_idx])

    logger.info(f"Mapped {len(detections)} PII detections to {len(pii_boxes)} image regions")
    return pii_boxes


def _map_boxes_to_types(detections, boxes, full_text):
    """
    Build a mapping from box object id → PII type label for tokenization overlays.
    """
    if not detections or not boxes:
        return {}

    char_to_box = {}
    pos = 0
    for b_idx, box in enumerate(boxes):
        word = box['text']
        word_start = full_text.find(word, pos)
        if word_start == -1:
            word_start = full_text.find(word, max(0, pos - 10))
        if word_start == -1:
            continue
        for ci in range(word_start, word_start + len(word)):
            char_to_box[ci] = b_idx
        pos = word_start + len(word)

    box_types = {}
    seen_box_indices = set()

    for det in detections:
        start = det['start']
        end = det['end']
        pii_type = det.get('type', 'PII')

        for char_pos in range(start, end):
            b_idx = char_to_box.get(char_pos)
            if b_idx is not None and b_idx not in seen_box_indices:
                seen_box_indices.add(b_idx)
                box_types[id(boxes[b_idx])] = pii_type

    return box_types


def generate_image_preview(image_path, detections, boxes, full_text):
    """
    Generate a preview image with PII regions highlighted (red outline).
    Used for admin preview on the results page.

    Returns:
        BytesIO buffer containing the highlighted PNG image
    """
    from PIL import Image, ImageDraw

    img = Image.open(image_path).copy()
    draw = ImageDraw.Draw(img)

    pii_boxes = _find_pii_boxes(detections, boxes, full_text)

    # Draw red outlines around PII regions
    padding = 2
    for box in pii_boxes:
        x1 = max(0, box['x'] - padding)
        y1 = max(0, box['y'] - padding)
        x2 = min(img.width, box['x'] + box['w'] + padding)
        y2 = min(img.height, box['y'] + box['h'] + padding)
        draw.rectangle([x1, y1, x2, y2], outline='red', width=2)

    buf = BytesIO()
    img.save(buf, format='PNG')
    buf.seek(0)
    return buf
