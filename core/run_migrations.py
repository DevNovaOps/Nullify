import os
import django
from django.core.management import call_command
import sys

os.environ.setdefault('DJANGO_SETTINGS_MODULE', 'core.settings')
try:
    django.setup()
    with open('migration_output.txt', 'w') as f:
        sys.stdout = f
        call_command('makemigrations', 'nulify')
    print("FINISHED")
except Exception as e:
    with open('migration_output.txt', 'w') as f:
        f.write(str(e))
    print("FAILED")
