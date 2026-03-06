from django.db import models
from django.contrib.auth.models import AbstractUser


class User(AbstractUser):
    """Custom user with role-based access control."""
    ROLE_CHOICES = [
        ('admin', 'Admin'),
        ('user', 'Standard User'),
    ]
    role = models.CharField(max_length=10, choices=ROLE_CHOICES, default='user')

    class Meta:
        db_table = 'nulify_user'

    def is_admin(self):
        return self.role == 'admin'

    def __str__(self):
        return f"{self.username} ({self.get_role_display()})"


class UploadedFile(models.Model):
    """Tracks each uploaded file through the processing pipeline."""
    STATUS_CHOICES = [
        ('pending', 'Pending'),
        ('processing', 'Processing'),
        ('completed', 'Completed'),
        ('failed', 'Failed'),
    ]
    file = models.FileField(upload_to='uploads/%Y/%m/')
    original_filename = models.CharField(max_length=255)
    file_type = models.CharField(max_length=10)
    file_size = models.BigIntegerField(default=0)
    uploaded_by = models.ForeignKey(User, on_delete=models.CASCADE, related_name='uploaded_files')
    uploaded_at = models.DateTimeField(auto_now_add=True)
    status = models.CharField(max_length=20, choices=STATUS_CHOICES, default='pending')
    risk_score = models.IntegerField(default=0)
    extracted_text = models.TextField(blank=True, default='')
    pii_count = models.IntegerField(default=0)

    class Meta:
        db_table = 'nulify_uploaded_file'
        ordering = ['-uploaded_at']

    def __str__(self):
        return f"{self.original_filename} ({self.get_status_display()})"

    def risk_level(self):
        if self.risk_score >= 70:
            return 'high'
        elif self.risk_score >= 30:
            return 'medium'
        return 'low'


class PIIDetection(models.Model):
    """Individual PII match found in an uploaded file."""
    METHOD_CHOICES = [
        ('regex', 'Regex'),
        ('nlp', 'NLP (NER)'),
        ('ml', 'ML Model'),
    ]
    SENSITIVITY_CHOICES = [
        ('low', 'Low'),
        ('medium', 'Medium'),
        ('high', 'High'),
        ('critical', 'Critical'),
    ]
    file = models.ForeignKey(UploadedFile, on_delete=models.CASCADE, related_name='detections')
    pii_type = models.CharField(max_length=50)
    original_value = models.CharField(max_length=500)
    start_position = models.IntegerField()
    end_position = models.IntegerField()
    line_number = models.IntegerField(default=0)
    detection_method = models.CharField(max_length=10, choices=METHOD_CHOICES, default='regex')
    confidence = models.FloatField(default=1.0)  # 0.0 to 1.0
    sensitivity = models.CharField(max_length=10, choices=SENSITIVITY_CHOICES, default='medium')

    class Meta:
        db_table = 'nulify_pii_detection'

    def __str__(self):
        return f"[{self.get_detection_method_display()}] {self.pii_type}: {self.original_value[:30]}..."


class SanitizedFile(models.Model):
    """Sanitized output version of an uploaded file."""
    METHOD_CHOICES = [
        ('masking', 'Masking'),
        ('redaction', 'Redaction'),
        ('tokenization', 'Tokenization'),
    ]
    original_file = models.ForeignKey(UploadedFile, on_delete=models.CASCADE, related_name='sanitized_versions')
    sanitized_file = models.FileField(upload_to='sanitized/%Y/%m/')
    method = models.CharField(max_length=20, choices=METHOD_CHOICES)
    sanitized_text = models.TextField(blank=True, default='')
    created_at = models.DateTimeField(auto_now_add=True)
    created_by = models.ForeignKey(User, on_delete=models.CASCADE)

    class Meta:
        db_table = 'nulify_sanitized_file'
        ordering = ['-created_at']

    def __str__(self):
        return f"Sanitized: {self.original_file.original_filename} ({self.get_method_display()})"


class AuditLog(models.Model):
    """Comprehensive audit trail for every user action."""
    ACTION_CHOICES = [
        ('upload', 'File Upload'),
        ('process', 'File Processing'),
        ('sanitize', 'Sanitization'),
        ('download', 'File Download'),
        ('download_original', 'Original File Download'),
        ('download_report', 'Report Download'),
        ('login', 'User Login'),
        ('logout', 'User Logout'),
        ('register', 'User Registration'),
        ('scan', 'Instant Scan'),
    ]
    user = models.ForeignKey(User, on_delete=models.SET_NULL, null=True, related_name='audit_logs')
    action = models.CharField(max_length=30, choices=ACTION_CHOICES)
    file = models.ForeignKey(UploadedFile, on_delete=models.SET_NULL, null=True, blank=True)
    timestamp = models.DateTimeField(auto_now_add=True)
    details = models.TextField(blank=True, default='')
    ip_address = models.GenericIPAddressField(null=True, blank=True)

    class Meta:
        db_table = 'nulify_audit_log'
        ordering = ['-timestamp']

    def __str__(self):
        return f"[{self.timestamp}] {self.user} → {self.get_action_display()}"
