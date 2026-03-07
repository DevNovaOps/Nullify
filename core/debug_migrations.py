import os
import django
from django.core.management import call_command
import sys

os.environ.setdefault('DJANGO_SETTINGS_MODULE', 'core.settings')
django.setup()

try:
    print("Calling makemigrations...")
    call_command('makemigrations', 'nulify')
    print("Done makemigrations")
except Exception as e:
    import traceback
    traceback.print_exc()
