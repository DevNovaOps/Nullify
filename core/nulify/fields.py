from django.db import models
from django.conf import settings
from cryptography.fernet import Fernet
import base64

def get_fernet():
    # Use SECRET_KEY padded/truncated to 32 bytes for the Fernet key
    key = settings.SECRET_KEY.encode('utf-8')[:32].ljust(32, b'0')
    return Fernet(base64.urlsafe_b64encode(key))

class EncryptedTextField(models.TextField):
    """
    Transparently encrypts data before saving to the database and decrypts
    when retrieving it.
    """
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)

    def get_prep_value(self, value):
        value = super().get_prep_value(value)
        if value is None or value == '':
            return value
        try:
            return get_fernet().encrypt(value.encode('utf-8')).decode('utf-8')
        except Exception:
            return value

    def from_db_value(self, value, expression, connection):
        if value is None or value == '':
            return value
        try:
            return get_fernet().decrypt(value.encode('utf-8')).decode('utf-8')
        except Exception:
            # If decryption fails (e.g. data is unencrypted or key changed),
            # return the raw value.
            return value

    def to_python(self, value):
        if value is None or value == '':
            return value
        # to_python might be called on already decrypted values
        # We try to decrypt, if it fails, we assume it's already decrypted
        try:
            return get_fernet().decrypt(value.encode('utf-8')).decode('utf-8')
        except Exception:
            return value
