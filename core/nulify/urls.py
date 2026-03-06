from django.urls import path
from . import views

urlpatterns = [
    # Public pages
    path('', views.home, name='home'),
    path('about/', views.about, name='about'),
    path('contact/', views.contact, name='contact'),
    path('privacy/', views.privacy, name='privacy'),
    path('terms/', views.terms, name='terms'),
    path('cookie-policy/', views.cookie_policy, name='cookie_policy'),
    path('download-my-data/', views.download_my_data, name='download_my_data'),

    # Auth
    path('login/', views.login_view, name='login'),
    path('register/', views.register_view, name='register'),
    path('logout/', views.logout_view, name='logout'),

    # Forgot Password Flow
    path('forgot-password/', views.forgot_password_view, name='forgot_password'),
    path('verify-otp/', views.verify_otp_view, name='verify_otp'),
    path('resend-otp/', views.resend_otp_view, name='resend_otp'),
    path('otp-verified/', views.otp_verified_view, name='otp_verified'),
    path('set-new-password/', views.set_new_password_view, name='set_new_password'),
    path('continue-without-changing/', views.continue_without_changing_view, name='continue_without_changing'),

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

    # Settings
    path('settings/', views.settings_view, name='settings'),
    path('settings/profile/', views.settings_update_profile, name='settings_update_profile'),
    path('settings/password/', views.settings_change_password, name='settings_change_password'),
    path('settings/delete/', views.settings_delete_account, name='settings_delete_account'),
]
