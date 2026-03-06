"""
Text Extraction Engine — Extract text content from multiple file formats.
Supports: PDF, DOCX, TXT, CSV, SQL, JSON
"""

import os
import csv
import json


def extract_text(file_path, file_type):
    """
    Main dispatcher: extract text from a file based on its type.
    Returns the full text content as a string.
    """
    file_type = file_type.lower().strip('.')

    extractors = {
        'pdf': extract_from_pdf,
        'docx': extract_from_docx,
        'txt': extract_from_txt,
        'csv': extract_from_csv,
        'sql': extract_from_sql,
        'json': extract_from_json,
    }

    extractor = extractors.get(file_type)
    if not extractor:
        raise ValueError(f"Unsupported file type: {file_type}")

    return extractor(file_path)


def extract_from_pdf(file_path):
    """Extract text from PDF using PyPDF2."""
    try:
        from PyPDF2 import PdfReader
    except ImportError:
        raise ImportError("PyPDF2 is required for PDF processing. Install with: pip install PyPDF2")

    reader = PdfReader(file_path)
    text_parts = []
    for page in reader.pages:
        page_text = page.extract_text()
        if page_text:
            text_parts.append(page_text)
    return '\n'.join(text_parts)


def extract_from_docx(file_path):
    """Extract text from DOCX using python-docx."""
    try:
        from docx import Document
    except ImportError:
        raise ImportError("python-docx is required for DOCX processing. Install with: pip install python-docx")

    doc = Document(file_path)
    text_parts = []

    # Extract from paragraphs
    for para in doc.paragraphs:
        if para.text.strip():
            text_parts.append(para.text)

    # Extract from tables
    for table in doc.tables:
        for row in table.rows:
            row_text = [cell.text.strip() for cell in row.cells if cell.text.strip()]
            if row_text:
                text_parts.append(' | '.join(row_text))

    return '\n'.join(text_parts)


def extract_from_txt(file_path):
    """Extract text from plain text files."""
    encodings = ['utf-8', 'latin-1', 'cp1252', 'ascii']
    for encoding in encodings:
        try:
            with open(file_path, 'r', encoding=encoding) as f:
                return f.read()
        except (UnicodeDecodeError, UnicodeError):
            continue
    raise ValueError("Unable to decode the text file with supported encodings")


def extract_from_csv(file_path):
    """Extract text from CSV files."""
    text_parts = []
    encodings = ['utf-8', 'latin-1', 'cp1252']

    for encoding in encodings:
        try:
            with open(file_path, 'r', encoding=encoding, newline='') as f:
                reader = csv.reader(f)
                for row in reader:
                    text_parts.append(' | '.join(str(cell) for cell in row))
            return '\n'.join(text_parts)
        except (UnicodeDecodeError, UnicodeError):
            continue

    raise ValueError("Unable to decode the CSV file with supported encodings")


def extract_from_sql(file_path):
    """Extract text from SQL dump files."""
    return extract_from_txt(file_path)


def extract_from_json(file_path):
    """Extract text from JSON files by flattening all values."""
    with open(file_path, 'r', encoding='utf-8') as f:
        data = json.load(f)

    text_parts = []
    _flatten_json(data, text_parts)
    return '\n'.join(text_parts)


def _flatten_json(obj, parts, prefix=''):
    """Recursively flatten JSON and collect all string values."""
    if isinstance(obj, dict):
        for key, value in obj.items():
            _flatten_json(value, parts, f"{prefix}{key}: ")
    elif isinstance(obj, list):
        for item in obj:
            _flatten_json(item, parts, prefix)
    else:
        parts.append(f"{prefix}{obj}")
