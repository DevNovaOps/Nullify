"""
Forms — Login, Registration, File Upload, Instant Scan, Password Reset.
"""

from django import forms
from .models import User


class LoginForm(forms.Form):
    email = forms.EmailField(
        max_length=254,
        widget=forms.EmailInput(attrs={
            'placeholder': 'name@organization.org',
            'autocomplete': 'email',
            'id': 'login-email',
        })
    )
    password = forms.CharField(
        widget=forms.PasswordInput(attrs={
            'placeholder': '••••••',
            'autocomplete': 'current-password',
            'id': 'login-password',
        })
    )


class RegisterForm(forms.ModelForm):
    password = forms.CharField(
        widget=forms.PasswordInput(attrs={
            'placeholder': '••••••',
            'autocomplete': 'new-password',
            'id': 'register-password',
        })
    )
    confirm_password = forms.CharField(
        widget=forms.PasswordInput(attrs={
            'placeholder': '••••••',
            'autocomplete': 'new-password',
            'id': 'register-confirm-password',
        })
    )

    class Meta:
        model = User
        fields = ['username', 'email', 'first_name', 'last_name']
        widgets = {
            'username': forms.TextInput(attrs={
                'placeholder': 'Choose a username',
                'autocomplete': 'username',
                'id': 'register-username',
            }),
            'email': forms.EmailInput(attrs={
                'placeholder': 'name@organization.org',
                'autocomplete': 'email',
                'id': 'register-email',
            }),
            'first_name': forms.TextInput(attrs={
                'placeholder': 'First name',
                'id': 'register-first-name',
            }),
            'last_name': forms.TextInput(attrs={
                'placeholder': 'Last name',
                'id': 'register-last-name',
            }),
        }

    def clean_email(self):
        email = self.cleaned_data.get('email')
        if User.objects.filter(email=email).exists():
            raise forms.ValidationError("An account with this email already exists.")
        return email

    def clean(self):
        cleaned_data = super().clean()
        password = cleaned_data.get('password')
        confirm = cleaned_data.get('confirm_password')
        if password and confirm and password != confirm:
            raise forms.ValidationError("Passwords do not match.")
        return cleaned_data


class ForgotPasswordForm(forms.Form):
    email = forms.EmailField(
        max_length=254,
        widget=forms.EmailInput(attrs={
            'placeholder': 'name@organization.org',
            'autocomplete': 'email',
            'id': 'forgot-email',
        })
    )


class SetNewPasswordForm(forms.Form):
    new_password = forms.CharField(
        widget=forms.PasswordInput(attrs={
            'placeholder': '••••••',
            'autocomplete': 'new-password',
            'id': 'new-password',
        })
    )
    confirm_password = forms.CharField(
        widget=forms.PasswordInput(attrs={
            'placeholder': '••••••',
            'autocomplete': 'new-password',
            'id': 'confirm-new-password',
        })
    )

    def clean(self):
        cleaned_data = super().clean()
        password = cleaned_data.get('new_password')
        confirm = cleaned_data.get('confirm_password')
        if password and confirm and password != confirm:
            raise forms.ValidationError("Passwords do not match.")
        return cleaned_data


class FileUploadForm(forms.Form):
    SANITIZATION_METHODS = [
        ('redaction', 'Redaction — Replace with [REDACTED]'),
        ('masking', 'Masking — Partial character reveal'),
        ('tokenization', 'Tokenization — Replace with unique tokens'),
    ]
    sanitization_method = forms.ChoiceField(
        choices=SANITIZATION_METHODS,
        initial='redaction',
        widget=forms.Select(attrs={'id': 'sanitization-method'})
    )


class InstantScanForm(forms.Form):
    text = forms.CharField(
        widget=forms.Textarea(attrs={
            'placeholder': 'Paste your text here to scan for PII...',
            'rows': 10,
            'id': 'instant-scan-text',
        })
    )


class ProfileUpdateForm(forms.ModelForm):
    class Meta:
        model = User
        fields = ['username', 'email', 'first_name', 'last_name']

    def clean_email(self):
        email = self.cleaned_data.get('email')
        if User.objects.filter(email=email).exclude(pk=self.instance.pk).exists():
            raise forms.ValidationError("An account with this email already exists.")
        return email

    def clean_username(self):
        username = self.cleaned_data.get('username')
        if User.objects.filter(username=username).exclude(pk=self.instance.pk).exists():
            raise forms.ValidationError("This username is already taken.")
        return username


class ChangePasswordForm(forms.Form):
    current_password = forms.CharField(
        widget=forms.PasswordInput(attrs={
            'placeholder': 'Enter current password',
            'id': 'current-password',
        })
    )
    new_password = forms.CharField(
        widget=forms.PasswordInput(attrs={
            'placeholder': 'Min 8 characters',
            'id': 'sec-new-password',
        })
    )
    confirm_password = forms.CharField(
        widget=forms.PasswordInput(attrs={
            'placeholder': 'Re-enter new password',
            'id': 'sec-confirm-password',
        })
    )

    def clean(self):
        cleaned_data = super().clean()
        new_pw = cleaned_data.get('new_password')
        confirm = cleaned_data.get('confirm_password')
        if new_pw and confirm and new_pw != confirm:
            raise forms.ValidationError("Passwords do not match.")
        if new_pw and len(new_pw) < 8:
            raise forms.ValidationError("Password must be at least 8 characters.")
        return cleaned_data
