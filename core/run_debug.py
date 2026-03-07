import subprocess

with open('pdf_debug.txt', 'w') as f:
    try:
        result = subprocess.run([r'C:\Nirma\venv\Scripts\python.exe', 'generate_pdf.py'], capture_output=True, text=True)
        f.write("STDOUT:\n" + result.stdout + "\n")
        f.write("STDERR:\n" + result.stderr + "\n")
    except Exception as e:
        f.write("EXCEPTION: " + str(e) + "\n")
