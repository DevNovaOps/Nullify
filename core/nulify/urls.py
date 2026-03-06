from django.urls import path
from . import views

urlpatterns = [
    # Public pages
    path('', views.home, name='home'),
    path('about/', views.about, name='about'),
    path('contact/', views.contact, name='contact'),
    path('privacy/', views.privacy, name='privacy'),

    # Auth
    path('login/', views.login_view, name='login'),
    path('register/', views.register_view, name='register'),
    path('logout/', views.logout_view, name='logout'),

    # Dashboard
    path('dashboard/', views.dashboard, name='dashboard'),

    # File operations
    path('upload/', views.upload_file, name='upload'),
    path('files/', views.file_list, name='file_list'),
    path('files/<int:file_id>/', views.file_detail, name='file_detail'),

    # Downloads
    path('download/sanitized/<int:sanitized_id>/', views.download_sanitized, name='download_sanitized'),
    path('download/original/<int:file_id>/', views.download_original, name='download_original'),
    path('download/report/<int:file_id>/', views.download_report, name='download_report'),

    # Analytics
    path('analytics/', views.analytics, name='analytics'),
    path('api/analytics/', views.api_analytics, name='api_analytics'),

    # Audit
    path('audit/', views.audit_logs, name='audit_logs'),

    # Instant Scan
    path('scan/', views.instant_scan, name='instant_scan'),
]
