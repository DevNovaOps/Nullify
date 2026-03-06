"""
Forms — Login, Registration, File Upload, Instant Scan.
"""

from django import forms
from .models import User


class LoginForm(forms.Form):
    username = forms.CharField(
        max_length=150,
        widget=forms.TextInput(attrs={
            'placeholder': 'Username',
            'autocomplete': 'username',
            'id': 'login-username',
        })
    )
    password = forms.CharField(
        widget=forms.PasswordInput(attrs={
            'placeholder': 'Password',
            'autocomplete': 'current-password',
            'id': 'login-password',
        })
    )


class RegisterForm(forms.ModelForm):
    password = forms.CharField(
        widget=forms.PasswordInput(attrs={
            'placeholder': 'Password',
            'autocomplete': 'new-password',
            'id': 'register-password',
        })
    )
    confirm_password = forms.CharField(
        widget=forms.PasswordInput(attrs={
            'placeholder': 'Confirm Password',
            'autocomplete': 'new-password',
            'id': 'register-confirm-password',
        })
    )
    role = forms.ChoiceField(
        choices=User.ROLE_CHOICES,
        widget=forms.Select(attrs={'id': 'register-role'})
    )

    class Meta:
        model = User
        fields = ['username', 'email', 'first_name', 'last_name', 'role']
        widgets = {
            'username': forms.TextInput(attrs={
                'placeholder': 'Username',
                'autocomplete': 'username',
                'id': 'register-username',
            }),
            'email': forms.EmailInput(attrs={
                'placeholder': 'Email',
                'autocomplete': 'email',
                'id': 'register-email',
            }),
            'first_name': forms.TextInput(attrs={
                'placeholder': 'First Name',
                'id': 'register-first-name',
            }),
            'last_name': forms.TextInput(attrs={
                'placeholder': 'Last Name',
                'id': 'register-last-name',
            }),
        }

    def clean(self):
        cleaned_data = super().clean()
        password = cleaned_data.get('password')
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
