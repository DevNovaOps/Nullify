@echo off
call c:\Nirma\venv\Scripts\activate.bat
python c:\Nirma\core\custom_md2pdf.py > c:\Nirma\core\bat_log.txt 2>&1
echo BAT FINISHED >> c:\Nirma\core\bat_log.txt
