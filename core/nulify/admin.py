from django.contrib import admin
from .models import User, UploadedFile, PIIDetection, SanitizedFile, AuditLog


@admin.register(User)
class UserAdmin(admin.ModelAdmin):
    list_display = ['username', 'email', 'role', 'is_active', 'date_joined']
    list_filter = ['role', 'is_active']
    search_fields = ['username', 'email']


@admin.register(UploadedFile)
class UploadedFileAdmin(admin.ModelAdmin):
    list_display = ['original_filename', 'file_type', 'uploaded_by', 'status', 'risk_score', 'pii_count', 'uploaded_at']
    list_filter = ['status', 'file_type']
    search_fields = ['original_filename']
    readonly_fields = ['uploaded_at']


@admin.register(PIIDetection)
class PIIDetectionAdmin(admin.ModelAdmin):
    list_display = ['file', 'pii_type', 'original_value', 'line_number']
    list_filter = ['pii_type']
    search_fields = ['original_value']


@admin.register(SanitizedFile)
class SanitizedFileAdmin(admin.ModelAdmin):
    list_display = ['original_file', 'method', 'created_by', 'created_at']
    list_filter = ['method']


@admin.register(AuditLog)
class AuditLogAdmin(admin.ModelAdmin):
    list_display = ['user', 'action', 'file', 'timestamp', 'ip_address']
    list_filter = ['action']
    search_fields = ['details']
    readonly_fields = ['timestamp']
