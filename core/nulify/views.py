"""
Views — All request handlers for the Nulify platform.
Session-based authentication. Role-based access control.
"""

import os
import json
import random
from django.shortcuts import render, redirect, get_object_or_404
from django.contrib.auth import login, logout, authenticate
from django.contrib.auth.decorators import login_required
from django.http import JsonResponse, HttpResponse, FileResponse
from django.contrib import messages
from django.db.models import Count, Q, Avg
from django.db.models.functions import TruncDate
from django.utils import timezone
from django.core.mail import send_mail
from django.conf import settings as django_settings
from datetime import timedelta
from .models import User, UploadedFile, PIIDetection, SanitizedFile, AuditLog
from .forms import (
    LoginForm, RegisterForm, FileUploadForm, InstantScanForm,
    ForgotPasswordForm, SetNewPasswordForm,
)
from .decorators import admin_required
from .pii_engine import detect_pii, detect_pii_regex_only, calculate_risk_score, get_pii_summary, get_method_summary, get_detection_methods_available
from .extractors import extract_text
from .sanitizer import sanitize_text
from .file_generator import generate_sanitized_file, generate_report_pdf
from .chart_generator import (
    generate_pii_distribution_chart,
    generate_risk_distribution_chart,
    generate_files_over_time_chart,
    generate_file_type_chart,
    generate_method_distribution_chart,
    generate_dashboard_mini_chart,
    generate_pii_summary_chart,
)


# Admin email constant
ADMIN_EMAIL = 'nullifyorg@gmail.com'


# ══════════════════════════════════════════════════════════════════════
#  HELPERS
# ══════════════════════════════════════════════════════════════════════

def _ip(request):
    """Get client IP address."""
    xff = request.META.get('HTTP_X_FORWARDED_FOR')
    return xff.split(',')[0].strip() if xff else request.META.get('REMOTE_ADDR')


def _highlight_pii(text, detections):
    """Insert <mark> tags around detected PII in the text."""
    highlighted = text
    sorted_d = sorted(detections, key=lambda d: d['start'], reverse=True)
    for d in sorted_d:
        s, e = d['start'], d['end']
        pii_css = d['type'].lower().replace(' ', '-')
        tag = f'<mark class="pii-highlight pii-{pii_css}" data-pii-type="{d["type"]}">'
        highlighted = highlighted[:s] + tag + highlighted[s:e] + '</mark>' + highlighted[e:]
    return highlighted


def _generate_otp():
    """Generate a 6-digit OTP."""
    return str(random.randint(100000, 999999))


def _send_otp_email(email, otp):
    """Send OTP to the user's email."""
    subject = 'Nullify — Password Reset OTP'
    message = f"""Hello,

Your verification code for password reset is:

    {otp}

This code is valid for 10 minutes. Do not share it with anyone.

If you did not request this, please ignore this email.

— Nullify SecureAuth™
"""
    try:
        send_mail(
            subject,
            message,
            django_settings.DEFAULT_FROM_EMAIL,
            [email],
            fail_silently=False,
        )
        return True
    except Exception:
        return False


# ══════════════════════════════════════════════════════════════════════
#  PUBLIC PAGES
# ══════════════════════════════════════════════════════════════════════

def home(request):
    return render(request, 'nulify/home.html')

def about(request):
    return render(request, 'nulify/about.html')

def contact(request):
    return render(request, 'nulify/contact.html')

def privacy(request):
    return render(request, 'nulify/privacy.html')

def terms(request):
    return render(request, 'nulify/terms.html')

def cookie_policy(request):
    return render(request, 'nulify/cookie_policy.html')

@login_required
def download_my_data(request):
    """Export the logged-in user's profile data as a JSON file."""
    import json as _json
    user = request.user
    data = {
        'username': user.username,
        'email': user.email,
        'first_name': user.first_name,
        'last_name': user.last_name,
        'role': user.role,
        'date_joined': user.date_joined.isoformat(),
        'last_login': user.last_login.isoformat() if user.last_login else None,
        'audit_log_count': user.audit_logs.count(),
    }
    payload = _json.dumps(data, indent=2)
    response = HttpResponse(payload, content_type='application/json')
    response['Content-Disposition'] = f'attachment; filename="nullify_data_{user.username}.json"'
    AuditLog.objects.create(
        user=user, action='settings',
        details='User downloaded their personal data export.',
        ip_address=_ip(request),
    )
    return response


# ══════════════════════════════════════════════════════════════════════
#  AUTH VIEWS
# ══════════════════════════════════════════════════════════════════════

def login_view(request):
    if request.user.is_authenticated:
        return redirect('dashboard')
    if request.method == 'POST':
        form = LoginForm(request.POST)
        if form.is_valid():
            email = form.cleaned_data['email']
            password = form.cleaned_data['password']
            # Look up user by email
            try:
                user_obj = User.objects.get(email=email)
                user = authenticate(
                    request,
                    username=user_obj.username,
                    password=password,
                )
            except User.DoesNotExist:
                user = None

            if user is not None:
                login(request, user)
                AuditLog.objects.create(
                    user=user, action='login',
                    details=f'User logged in via email',
                    ip_address=_ip(request),
                )
                messages.success(request, f'Welcome back, {user.first_name or user.username}!')
                return redirect('dashboard')
            else:
                messages.error(request, 'Invalid email or password.')
    else:
        form = LoginForm()
    return render(request, 'nulify/login.html', {'form': form})


def register_view(request):
    if request.user.is_authenticated:
        return redirect('dashboard')
    if request.method == 'POST':
        form = RegisterForm(request.POST)
        if form.is_valid():
            user = form.save(commit=False)
            user.set_password(form.cleaned_data['password'])
            # Assign admin role if email matches admin email
            if user.email.lower() == ADMIN_EMAIL.lower():
                user.role = 'admin'
            else:
                user.role = 'user'
            user.save()
            AuditLog.objects.create(
                user=user, action='register',
                details=f'New user registered: {user.username} ({user.role})',
                ip_address=_ip(request),
            )
            login(request, user)
            messages.success(request, 'Account created successfully!')
            return redirect('dashboard')
    else:
        form = RegisterForm()
    return render(request, 'nulify/register.html', {'form': form})


def logout_view(request):
    if request.user.is_authenticated:
        AuditLog.objects.create(
            user=request.user, action='logout',
            details='User logged out',
            ip_address=_ip(request),
        )
    logout(request)
    messages.info(request, 'You have been logged out.')
    return redirect('login')


# ══════════════════════════════════════════════════════════════════════
#  FORGOT PASSWORD FLOW
# ══════════════════════════════════════════════════════════════════════

def forgot_password_view(request):
    """Step 1: User enters email to receive OTP."""
    if request.user.is_authenticated:
        return redirect('dashboard')

    if request.method == 'POST':
        form = ForgotPasswordForm(request.POST)
        if form.is_valid():
            email = form.cleaned_data['email']
            try:
                user = User.objects.get(email=email)
                otp = _generate_otp()
                # Store OTP in session
                request.session['reset_otp'] = otp
                request.session['reset_email'] = email
                request.session['otp_created_at'] = timezone.now().isoformat()

                if _send_otp_email(email, otp):
                    messages.success(request, 'Verification code sent to your email.')
                    return redirect('verify_otp')
                else:
                    messages.error(request, 'Failed to send email. Please try again.')
            except User.DoesNotExist:
                # Don't reveal whether user exists
                messages.success(request, 'If an account with that email exists, a verification code has been sent.')
                return redirect('verify_otp')
    else:
        form = ForgotPasswordForm()

    return render(request, 'nulify/forgot_password.html', {'form': form})


def verify_otp_view(request):
    """Step 2: User enters the 6-digit OTP."""
    if request.user.is_authenticated:
        return redirect('dashboard')

    # Must have come from forgot password
    reset_email = request.session.get('reset_email')
    if not reset_email:
        messages.error(request, 'Please start the password reset process first.')
        return redirect('forgot_password')

    if request.method == 'POST':
        # Collect OTP from 6 separate fields
        otp_digits = []
        for i in range(1, 7):
            digit = request.POST.get(f'otp_{i}', '')
            otp_digits.append(digit)
        entered_otp = ''.join(otp_digits)

        stored_otp = request.session.get('reset_otp')
        otp_created = request.session.get('otp_created_at')

        # Check OTP validity (10 minute expiry)
        if otp_created:
            from datetime import datetime
            created_time = datetime.fromisoformat(otp_created)
            if (timezone.now() - timezone.make_aware(created_time) if timezone.is_naive(created_time) else timezone.now() - created_time) > timedelta(minutes=10):
                messages.error(request, 'OTP has expired. Please request a new one.')
                return redirect('forgot_password')

        if entered_otp == stored_otp:
            request.session['otp_verified'] = True
            return redirect('otp_verified')
        else:
            messages.error(request, 'Invalid OTP. Please try again.')

    return render(request, 'nulify/verify_otp.html', {'email': reset_email})


def resend_otp_view(request):
    """Resend the OTP to the user's email."""
    reset_email = request.session.get('reset_email')
    if not reset_email:
        return redirect('forgot_password')

    otp = _generate_otp()
    request.session['reset_otp'] = otp
    request.session['otp_created_at'] = timezone.now().isoformat()

    if _send_otp_email(reset_email, otp):
        messages.success(request, 'A new verification code has been sent.')
    else:
        messages.error(request, 'Failed to send email. Please try again.')

    return redirect('verify_otp')


def otp_verified_view(request):
    """Step 3: OTP verified — choose to set new password or continue."""
    if request.user.is_authenticated:
        return redirect('dashboard')

    if not request.session.get('otp_verified'):
        messages.error(request, 'Please verify your OTP first.')
        return redirect('forgot_password')

    return render(request, 'nulify/otp_verified.html')


def set_new_password_view(request):
    """Step 4: Set a new password after OTP verification."""
    if request.user.is_authenticated:
        return redirect('dashboard')

    if not request.session.get('otp_verified'):
        messages.error(request, 'Please verify your OTP first.')
        return redirect('forgot_password')

    reset_email = request.session.get('reset_email')

    if request.method == 'POST':
        form = SetNewPasswordForm(request.POST)
        if form.is_valid():
            try:
                user = User.objects.get(email=reset_email)
                user.set_password(form.cleaned_data['new_password'])
                user.save()

                # Clear session data
                for key in ['reset_otp', 'reset_email', 'otp_created_at', 'otp_verified']:
                    request.session.pop(key, None)

                messages.success(request, 'Password updated successfully! Please sign in.')
                return redirect('login')
            except User.DoesNotExist:
                messages.error(request, 'An error occurred. Please try again.')
                return redirect('forgot_password')
    else:
        form = SetNewPasswordForm()

    return render(request, 'nulify/set_new_password.html', {'form': form})


def continue_without_changing_view(request):
    """User chose not to change password — log them in directly."""
    reset_email = request.session.get('reset_email')

    # Clear session data
    for key in ['reset_otp', 'reset_email', 'otp_created_at', 'otp_verified']:
        request.session.pop(key, None)

    # Directly log the user in using their verified email
    if reset_email:
        try:
            user = User.objects.get(email=reset_email)
            login(request, user)
            AuditLog.objects.create(
                user=user, action='login',
                details='User logged in via OTP verification (continue without changing password)',
                ip_address=_ip(request),
            )
            messages.success(request, f'Welcome back, {user.first_name or user.username}!')
            return redirect('dashboard')
        except User.DoesNotExist:
            pass

    messages.info(request, 'No changes made. Please sign in.')
    return redirect('login')


# ══════════════════════════════════════════════════════════════════════
#  DASHBOARD
# ══════════════════════════════════════════════════════════════════════

@login_required
def dashboard(request):
    if request.user.is_admin():
        total_files = UploadedFile.objects.count()
        total_pii = PIIDetection.objects.count()
        total_sanitized = SanitizedFile.objects.count()
        high_risk = UploadedFile.objects.filter(risk_score__gte=70).count()
        recent_files = UploadedFile.objects.select_related('uploaded_by')[:5]

        # PII type breakdown for mini-chart (matplotlib)
        pii_breakdown = list(
            PIIDetection.objects.values('pii_type')
            .annotate(count=Count('id'))
            .order_by('-count')[:6]
        )
        pii_chart = generate_dashboard_mini_chart(pii_breakdown)

        context = {
            'total_files': total_files,
            'total_pii': total_pii,
            'total_sanitized': total_sanitized,
            'high_risk': high_risk,
            'recent_files': recent_files,
            'pii_chart': pii_chart,
        }
    else:
        # Standard user: only sanitized files
        sanitized_files = (
            SanitizedFile.objects
            .select_related('original_file', 'original_file__uploaded_by')
            .order_by('-created_at')[:10]
        )
        context = {
            'sanitized_files': sanitized_files,
            'total_available': SanitizedFile.objects.count(),
        }

    return render(request, 'nulify/dashboard.html', context)


# ══════════════════════════════════════════════════════════════════════
#  FILE UPLOAD & PROCESSING
# ══════════════════════════════════════════════════════════════════════

@login_required
@admin_required
def upload_file(request):
    if request.method == 'POST':
        files = request.FILES.getlist('files')
        method = request.POST.get('sanitization_method', 'redaction')

        if not files:
            messages.error(request, 'Please select at least one file.')
            return render(request, 'nulify/upload.html', {'form': FileUploadForm()})

        results = []
        for f in files:
            ext = os.path.splitext(f.name)[1].lower().lstrip('.')
            if ext not in ['pdf', 'docx', 'txt', 'csv', 'sql', 'json']:
                results.append({
                    'name': f.name, 'success': False,
                    'error': f'Unsupported file type: .{ext}',
                })
                continue

            # Save the uploaded file
            uploaded = UploadedFile.objects.create(
                file=f,
                original_filename=f.name,
                file_type=ext,
                file_size=f.size,
                uploaded_by=request.user,
                status='processing',
            )

            AuditLog.objects.create(
                user=request.user, action='upload', file=uploaded,
                details=f'Uploaded: {f.name} ({ext.upper()}, {f.size} bytes)',
                ip_address=_ip(request),
            )

            try:
                # 1. Extract text
                text = extract_text(uploaded.file.path, ext)
                uploaded.extracted_text = text

                # 2. Detect PII
                detections = detect_pii(text)

                # 3. Save detections
                pii_objects = []
                for d in detections:
                    pii_objects.append(PIIDetection(
                        file=uploaded,
                        pii_type=d['type'],
                        original_value=d['value'],
                        start_position=d['start'],
                        end_position=d['end'],
                        line_number=d.get('line', 0),
                        detection_method=d.get('method', 'regex'),
                        confidence=d.get('confidence', 1.0),
                        sensitivity=d.get('sensitivity', 'medium'),
                    ))
                PIIDetection.objects.bulk_create(pii_objects)

                # 4. Calculate risk score
                uploaded.risk_score = calculate_risk_score(detections)
                uploaded.pii_count = len(detections)

                # 5. Sanitize
                sanitized_text = sanitize_text(text, detections, method)

                # 6. Generate output file
                filename, content = generate_sanitized_file(uploaded, sanitized_text)
                sanitized = SanitizedFile(
                    original_file=uploaded,
                    method=method,
                    sanitized_text=sanitized_text,
                    created_by=request.user,
                )
                sanitized.sanitized_file.save(filename, content)
                sanitized.save()

                uploaded.status = 'completed'
                uploaded.save()

                AuditLog.objects.create(
                    user=request.user, action='process', file=uploaded,
                    details=f'Processed {f.name}: {len(detections)} PII found, method={method}',
                    ip_address=_ip(request),
                )

                results.append({
                    'name': f.name, 'success': True,
                    'id': uploaded.id, 'pii_count': len(detections),
                    'risk_score': uploaded.risk_score,
                })

            except Exception as e:
                uploaded.status = 'failed'
                uploaded.save()
                results.append({
                    'name': f.name, 'success': False,
                    'error': str(e),
                })

        # Single file → go to detail page
        if len(files) == 1 and results and results[0].get('success'):
            return redirect('file_detail', file_id=results[0]['id'])

        # Batch → show results summary
        return render(request, 'nulify/upload.html', {
            'form': FileUploadForm(),
            'results': results,
            'batch': True,
        })

    return render(request, 'nulify/upload.html', {'form': FileUploadForm()})


# ══════════════════════════════════════════════════════════════════════
#  FILE LIST & DETAIL
# ══════════════════════════════════════════════════════════════════════

@login_required
def file_list(request):
    if request.user.is_admin():
        files = UploadedFile.objects.select_related('uploaded_by').all()
    else:
        files = UploadedFile.objects.filter(status='completed')

    # Search filter
    q = request.GET.get('q', '')
    if q:
        files = files.filter(
            Q(original_filename__icontains=q) |
            Q(file_type__icontains=q)
        )

    return render(request, 'nulify/file_list.html', {'files': files, 'query': q})


@login_required
def file_detail(request, file_id):
    uploaded = get_object_or_404(UploadedFile, id=file_id)

    # Standard users can only see completed files
    if not request.user.is_admin() and uploaded.status != 'completed':
        messages.error(request, 'Access denied.')
        return redirect('file_list')

    detections = list(uploaded.detections.all())
    sanitized = uploaded.sanitized_versions.first()

    # Build highlighted text
    det_list = [
        {'type': d.pii_type, 'value': d.original_value,
         'start': d.start_position, 'end': d.end_position}
        for d in detections
    ]
    highlighted = _highlight_pii(uploaded.extracted_text, det_list)

    # PII summary
    pii_summary = {}
    for d in detections:
        pii_summary[d.pii_type] = pii_summary.get(d.pii_type, 0) + 1

    # Generate PII summary chart using matplotlib
    pii_summary_chart = generate_pii_summary_chart(pii_summary)

    # Get all sanitized versions for this file
    sanitized_versions = uploaded.sanitized_versions.all()

    # Method summary for badges
    method_summary = {}
    for d in detections:
        m = d.detection_method
        method_summary[m] = method_summary.get(m, 0) + 1

    context = {
        'file': uploaded,
        'detections': detections,
        'sanitized': sanitized,
        'sanitized_versions': sanitized_versions,
        'highlighted_text': highlighted,
        'pii_summary': pii_summary,
        'pii_summary_chart': pii_summary_chart,
        'method_summary': method_summary,
    }
    return render(request, 'nulify/results.html', context)


# ══════════════════════════════════════════════════════════════════════
#  DOWNLOADS
# ══════════════════════════════════════════════════════════════════════

@login_required
def download_sanitized(request, sanitized_id):
    sanitized = get_object_or_404(SanitizedFile, id=sanitized_id)

    AuditLog.objects.create(
        user=request.user, action='download', file=sanitized.original_file,
        details=f'Downloaded sanitized: {sanitized.original_file.original_filename}',
        ip_address=_ip(request),
    )

    response = HttpResponse(
        sanitized.sanitized_file.read(),
        content_type='text/plain; charset=utf-8',
    )
    safe_name = sanitized.original_file.original_filename.rsplit('.', 1)[0]
    response['Content-Disposition'] = f'attachment; filename="sanitized_{safe_name}.txt"'
    return response


@login_required
@admin_required
def download_original(request, file_id):
    uploaded = get_object_or_404(UploadedFile, id=file_id)

    AuditLog.objects.create(
        user=request.user, action='download_original', file=uploaded,
        details=f'Downloaded original: {uploaded.original_filename}',
        ip_address=_ip(request),
    )

    response = FileResponse(uploaded.file.open('rb'), as_attachment=True)
    response['Content-Disposition'] = f'attachment; filename="{uploaded.original_filename}"'
    return response


@login_required
@admin_required
def download_report(request, file_id):
    uploaded = get_object_or_404(UploadedFile, id=file_id)
    detections = uploaded.detections.all()
    sanitized = uploaded.sanitized_versions.first()

    AuditLog.objects.create(
        user=request.user, action='download_report', file=uploaded,
        details=f'Downloaded report: {uploaded.original_filename}',
        ip_address=_ip(request),
    )

    pdf_buffer = generate_report_pdf(uploaded, detections, sanitized)
    response = HttpResponse(pdf_buffer.read(), content_type='application/pdf')
    safe_name = uploaded.original_filename.rsplit('.', 1)[0]
    response['Content-Disposition'] = f'attachment; filename="report_{safe_name}.pdf"'
    return response


# ══════════════════════════════════════════════════════════════════════
#  ANALYTICS (Matplotlib Charts)
# ══════════════════════════════════════════════════════════════════════

@login_required
@admin_required
def analytics(request):
    """Render analytics page with server-side matplotlib charts."""

    # PII type distribution
    pii_dist = list(
        PIIDetection.objects.values('pii_type')
        .annotate(count=Count('id'))
        .order_by('-count')
    )

    # File type distribution
    file_dist = list(
        UploadedFile.objects.values('file_type')
        .annotate(count=Count('id'))
        .order_by('-count')
    )

    # Files over time (last 30 days)
    thirty_ago = timezone.now() - timedelta(days=30)
    files_time = list(
        UploadedFile.objects
        .filter(uploaded_at__gte=thirty_ago)
        .annotate(date=TruncDate('uploaded_at'))
        .values('date')
        .annotate(count=Count('id'))
        .order_by('date')
    )
    files_time_formatted = [
        {'date': f['date'].strftime('%b %d'), 'count': f['count']}
        for f in files_time
    ]

    # Risk distribution
    low = UploadedFile.objects.filter(risk_score__lt=30).count()
    medium = UploadedFile.objects.filter(risk_score__gte=30, risk_score__lt=70).count()
    high = UploadedFile.objects.filter(risk_score__gte=70).count()

    # Method distribution
    method_dist = list(
        SanitizedFile.objects.values('method')
        .annotate(count=Count('id'))
        .order_by('-count')
    )

    # Summary stats
    total_files = UploadedFile.objects.count()
    total_pii = PIIDetection.objects.count()
    total_sanitized = SanitizedFile.objects.count()
    avg_risk_val = UploadedFile.objects.aggregate(avg=Avg('risk_score'))['avg']
    avg_risk = round(avg_risk_val) if avg_risk_val else 0

    # Generate all charts using matplotlib
    pii_chart = generate_pii_distribution_chart(pii_dist)
    risk_chart = generate_risk_distribution_chart(low, medium, high)
    timeline_chart = generate_files_over_time_chart(files_time_formatted)
    file_type_chart = generate_file_type_chart(file_dist)
    method_chart = generate_method_distribution_chart(method_dist)

    context = {
        'total_files': total_files,
        'total_pii': total_pii,
        'total_sanitized': total_sanitized,
        'avg_risk': avg_risk,
        'pii_chart': pii_chart,
        'risk_chart': risk_chart,
        'timeline_chart': timeline_chart,
        'file_type_chart': file_type_chart,
        'method_chart': method_chart,
    }
    return render(request, 'nulify/analytics.html', context)


@login_required
@admin_required
def api_analytics(request):
    """JSON endpoint for analytics data (kept for API use)."""
    # PII type distribution
    pii_dist = list(
        PIIDetection.objects.values('pii_type')
        .annotate(count=Count('id'))
        .order_by('-count')
    )

    # File type distribution
    file_dist = list(
        UploadedFile.objects.values('file_type')
        .annotate(count=Count('id'))
        .order_by('-count')
    )

    # Files over time (last 30 days)
    thirty_ago = timezone.now() - timedelta(days=30)
    files_time = list(
        UploadedFile.objects
        .filter(uploaded_at__gte=thirty_ago)
        .annotate(date=TruncDate('uploaded_at'))
        .values('date')
        .annotate(count=Count('id'))
        .order_by('date')
    )

    # Risk distribution
    low = UploadedFile.objects.filter(risk_score__lt=30).count()
    medium = UploadedFile.objects.filter(risk_score__gte=30, risk_score__lt=70).count()
    high = UploadedFile.objects.filter(risk_score__gte=70).count()

    # Method distribution
    method_dist = list(
        SanitizedFile.objects.values('method')
        .annotate(count=Count('id'))
        .order_by('-count')
    )

    avg_risk_val = UploadedFile.objects.aggregate(avg=Avg('risk_score'))['avg']

    data = {
        'pii_distribution': pii_dist,
        'file_distribution': file_dist,
        'files_over_time': [
            {'date': f['date'].strftime('%Y-%m-%d'), 'count': f['count']}
            for f in files_time
        ],
        'risk_distribution': {'low': low, 'medium': medium, 'high': high},
        'method_distribution': method_dist,
        'summary': {
            'total_files': UploadedFile.objects.count(),
            'total_pii': PIIDetection.objects.count(),
            'total_sanitized': SanitizedFile.objects.count(),
            'avg_risk': round(avg_risk_val) if avg_risk_val else 0,
        },
    }
    return JsonResponse(data)


# ══════════════════════════════════════════════════════════════════════
#  AUDIT LOGS
# ══════════════════════════════════════════════════════════════════════

@login_required
@admin_required
def audit_logs(request):
    logs = AuditLog.objects.select_related('user', 'file').all()

    # Filters
    action = request.GET.get('action', '')
    user_q = request.GET.get('user', '')
    if action:
        logs = logs.filter(action=action)
    if user_q:
        logs = logs.filter(user__username__icontains=user_q)

    context = {
        'logs': logs[:200],
        'action_filter': action,
        'user_filter': user_q,
        'action_choices': AuditLog.ACTION_CHOICES,
    }
    return render(request, 'nulify/audit.html', context)


# ══════════════════════════════════════════════════════════════════════
#  INSTANT PII SCAN
# ══════════════════════════════════════════════════════════════════════

@login_required
def instant_scan(request):
    methods_status = get_detection_methods_available()
    context = {'form': InstantScanForm(), 'methods_status': methods_status}

    if request.method == 'POST':
        text = request.POST.get('text', '').strip()
        if not text:
            messages.error(request, 'Please enter some text to scan.')
            return render(request, 'nulify/instant_scan.html', context)

        # Use all available methods for instant scan
        detections = detect_pii(text)
        risk_score = calculate_risk_score(detections)
        highlighted = _highlight_pii(text, detections)
        pii_summary = get_pii_summary(detections)
        method_summary = get_method_summary(detections)

        AuditLog.objects.create(
            user=request.user, action='scan',
            details=f'Instant scan: {len(detections)} PII detected (methods: {method_summary})',
            ip_address=_ip(request),
        )

        # AJAX request
        if request.headers.get('X-Requested-With') == 'XMLHttpRequest':
            return JsonResponse({
                'detections': detections,
                'highlighted': highlighted,
                'risk_score': risk_score,
                'pii_summary': pii_summary,
                'method_summary': method_summary,
                'total': len(detections),
            })

        context.update({
            'text': text,
            'detections': detections,
            'highlighted': highlighted,
            'risk_score': risk_score,
            'pii_summary': pii_summary,
            'method_summary': method_summary,
            'scanned': True,
        })

    return render(request, 'nulify/instant_scan.html', context)


# ══════════════════════════════════════════════════════════════════════
#  OLLAMA STATUS API
# ══════════════════════════════════════════════════════════════════════

@login_required
def ollama_status(request):
    """API endpoint returning Ollama connection status and available models."""
    status = get_detection_methods_available()
    return JsonResponse(status)
#  SETTINGS
# ══════════════════════════════════════════════════════════════════════

@login_required
@admin_required
def settings_view(request):
    """Render the settings page with all tabs."""
    return render(request, 'nulify/settings.html')


@login_required
def settings_update_profile(request):
    """Handle profile update form submission."""
    if request.method != 'POST':
        return redirect('settings')

    user = request.user
    first_name = request.POST.get('first_name', '').strip()
    last_name  = request.POST.get('last_name', '').strip()
    email      = request.POST.get('email', '').strip()
    username   = request.POST.get('username', '').strip()

    if not username:
        messages.error(request, 'Username cannot be empty.')
        return redirect('settings')

    # Check username uniqueness (exclude self)
    if User.objects.filter(username=username).exclude(pk=user.pk).exists():
        messages.error(request, 'That username is already taken.')
        return redirect('settings')

    # Check email uniqueness (exclude self)
    if email and User.objects.filter(email=email).exclude(pk=user.pk).exists():
        messages.error(request, 'That email address is already in use.')
        return redirect('settings')

    user.first_name = first_name
    user.last_name  = last_name
    user.username   = username
    if email:
        user.email  = email
    user.save()

    AuditLog.objects.create(
        user=user, action='settings',
        details='User updated their profile information.',
        ip_address=_ip(request),
    )
    messages.success(request, 'Profile updated successfully!')
    from django.urls import reverse
    from django.http import HttpResponseRedirect
    return HttpResponseRedirect(reverse('settings') + '#profile')


@login_required
def settings_change_password(request):
    """Handle password change form submission."""
    if request.method != 'POST':
        return redirect('settings')

    user            = request.user
    current_pw      = request.POST.get('current_password', '')
    new_pw          = request.POST.get('new_password', '')
    confirm_pw      = request.POST.get('confirm_password', '')

    if not user.check_password(current_pw):
        messages.error(request, 'Current password is incorrect.')
        return redirect('settings')

    if len(new_pw) < 8:
        messages.error(request, 'New password must be at least 8 characters.')
        return redirect('settings')

    if new_pw != confirm_pw:
        messages.error(request, 'New passwords do not match.')
        return redirect('settings')

    user.set_password(new_pw)
    user.save()

    # Re-authenticate so the session stays valid
    from django.contrib.auth import update_session_auth_hash
    update_session_auth_hash(request, user)

    AuditLog.objects.create(
        user=user, action='settings',
        details='User changed their password.',
        ip_address=_ip(request),
    )
    messages.success(request, 'Password changed successfully!')
    from django.urls import reverse
    from django.http import HttpResponseRedirect
    return HttpResponseRedirect(reverse('settings') + '#security')


@login_required
def settings_delete_account(request):
    """Handle account deletion form submission."""
    if request.method != 'POST':
        return redirect('settings')

    user = request.user
    AuditLog.objects.create(
        user=user, action='settings',
        details=f'Account deleted: {user.username} ({user.email})',
        ip_address=_ip(request),
    )
    logout(request)
    user.delete()
    messages.info(request, 'Your account has been permanently deleted.')
    return redirect('home')

