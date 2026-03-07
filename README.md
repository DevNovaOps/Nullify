# Nullify

Nullify is a comprehensive PII Detection & Data Sanitization Platform. It supports scanning and sanitizing various file formats, including documents, spreadsheets, images, and raw text, by redacting, masking, or tokenizing sensitive information using Regex, NLP (spaCy), and ML (Ollama/Qwen) techniques.

## Features
- **Multi-Format Support**: Sanitizes TXT, PDF, DOCX, XLSX, CSV, SQL, JSON, and Images (PNG/JPG).
- **Intelligent PII Detection**: Uses Regex for patterns, spaCy for Named Entity Recognition (NER), and local LLMs (Ollama) for deep context scanning.
- **Image Redaction**: Draws true black boxes or masking text over PII directly onto images using Tesseract OCR.
- **Reporting & Auditing**: Detailed PDF sanitization reports, visual dashboards, and audit logs.
- **Role-Based Access**: User workspace for self-serve sanitization, and Admin tools to review flagged requests.

## Architecture & Workflow

Nullify operates as a seamless pipeline converting raw, potentially sensitive data into clean, compliant equivalents:

1. **Ingestion Layer**
   - Files are securely uploaded through the web interface.
   - The platform supports dynamic routing based on MIME type (Text, PDF, Word, Excel, CSV, JSON, SQL, PNG, JPG).
2. **Extraction Engine**
   - **Text & Docs:** Direct text conversion using specialized libraries (`python-docx`, `PyPDF2`, `openpyxl`). 
   - **Images:** Uses Tesseract OCR to map bounding boxes and extract visible text from images.
3. **Detection Core**
   - Passes the extracted data through a multi-tiered pipeline:
     - **Level 1 (Regex):** Standard exact-match pattern finding for SSNs, Emails, Phones, Credit Cards.
     - **Level 2 (NLP):** Utilizes `spaCy` NER to understand contextual entities (Names, Organizations, Locations).
     - **Level 3 (Machine Learning):** Uses `Qwen` (via Ollama) to execute Deep Scans on contextual anomalies and output an algorithmic Risk Score.
4. **Sanitization Processor**
   - Cross-references detection positions and performs the chosen method:
     - **Masking:** Replaces characters with `X` or solid black boxes `█` (specifically for images).
     - **Redaction:** Complete obliteration inserting `[REDACTED]`.
     - **Tokenization:** Replaces PII with secure, reversible format-preserving generic tokens (e.g. `[EMAIL_1]`).
5. **Reconstruction & Output**
   - The sanitized data is perfectly reconstructed into its native original format.
   - Comprehensive Audit Logs and PDF Sanitization Reports are generated for compliance tracking.

## Prerequisites

Before starting, ensure you have the following installed on your machine:
- **Python 3.10+**
- **MySQL Server**
- **Tesseract OCR** (Required for image scanning)
- **Ollama** (Required for "Deep Scan with AI" features)

### Installing System Dependencies (Windows)
1. **Tesseract OCR**: Download and install from [UB-Mannheim/tesseract](https://github.com/UB-Mannheim/tesseract/wiki). Ensure the installation path (typically `C:\Program Files\Tesseract-OCR\tesseract.exe`) is added to your system's `PATH`.
2. **Ollama**: Download and install from [Ollama's official website](https://ollama.com). 
   - After installation, open a terminal and run `ollama run qwen2.5:0.5b` to download the required machine learning model.

## Installation Steps

1. **Clone the repository** (if you haven't already and navigate to the root directory)
   ```bash
   cd c:\Nirma\core
   ```

2. **Create and activate a virtual environment**
   ```bash
   python -m venv venv
   # On Windows:
   venv\Scripts\activate
   # On macOS/Linux:
   source venv/bin/activate
   ```

3. **Install Python dependencies**
   ```bash
   pip install -r requirements.txt
   ```

4. **Install the spaCy NLP model**
   ```bash
   python -m spacy download en_core_web_sm
   ```

## Database Setup
Ensure MySQL is running. Open your MySQL client and run:
   ```sql
   CREATE DATABASE nullify;
   ```
*(Adjust the database credentials in `core/settings.py` if your local MySQL root password differs from what is configured).*

Apply the Django database migrations:
   ```bash
   python manage.py makemigrations nulify
   python manage.py migrate
   ```

### Database Schema Overview

| Table Name | Description | Key Fields |
|---|---|---|
| **`nulify_user`** | Custom user handling, extending Django's auth model. | `username`, `email`, `role (admin/user)` |
| **`nulify_uploaded_file`** | Tracks the lifecycle of every file uploaded to the platform. | `file`, `file_type`, `status`, `risk_score`, `uploaded_by` |
| **`nulify_pii_detection`** | Records individual instances of sensitive data found during a scan. | `pii_type`, `original_value`, `start/end_position`, `confidence` |
| **`nulify_sanitized_file`** | Stores the final, cleaned version of a file ready for compliance. | `original_file_id`, `sanitized_file`, `method`, `detection_source` |
| **`nulify_sanitization_request`** | Handles user-submitted requests asking an admin to sanitize their text/files. | `user_id`, `data_text/data_file`, `method`, `status`, `admin_response` |
| **`nulify_audit_log`** | Immutable trail of every critical event on the platform. | `user_id`, `action`, `file_id`, `timestamp`, `ip_address` |

## Execution Instructions

1. **Start the Django Development Server**
   Make sure your virtual environment is activated, then run:
   ```bash
   python manage.py runserver
   ```
2. **Access the Platform**
   Open your browser and navigate to `http://127.0.0.1:8000`.

3. **Admin Access**
   You can create a superuser to access the Django admin panel, or use the in-app Admin tools:
   ```bash
   python manage.py createsuperuser
   ```

## Settings & Environment Variables
The application relies on `core/settings.py` for variables like:
- `OLLAMA_BASE_URL`: Default is `http://localhost:11434`
- `EMAIL_HOST_USER`: For SMTP email features (OTP verifications). Must be configured with an App Password if using Gmail.

## Troubleshooting
- **Missing SQLite/MySQL Errors**: Ensure your MySQL daemon is running and the credentials in `settings.py` match your local root user.
- **TesseractNotFoundError**: Ensure the Tesseract-OCR directory is added to your system `PATH` completely or set `pytesseract.pytesseract.tesseract_cmd = r'C:\Program Files\Tesseract-OCR\tesseract.exe'` within `image_sanitizer.py`.
- **Deep Scan Timing out**: Ensure Ollama is actively running in the background.
