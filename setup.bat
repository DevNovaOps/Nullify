@echo off
call c:\Nirma\venv\Scripts\activate.bat
pip install PyPDF2 python-docx reportlab mysqlclient
echo INSTALL_DONE
python c:\Nirma\core\manage.py makemigrations nulify
echo MAKEMIGRATIONS_DONE
python c:\Nirma\core\manage.py migrate
echo MIGRATE_DONE
