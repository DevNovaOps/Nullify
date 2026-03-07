import pdfplumber

pdf_path = r'c:\Nirma\core\media\uploads\2026\03\customer_support_report.pdf'
with pdfplumber.open(pdf_path) as pdf:
    p = pdf.pages[0]
    print("Default Tables:", p.find_tables())
    print("Text extraction:", p.extract_tables())
    
    custom_tables = p.find_tables(table_settings={"vertical_strategy": "text", "horizontal_strategy": "text"})
    print("Custom Tables:", len(custom_tables))
    if custom_tables:
        print("First table cells:", p.extract_tables(table_settings={"vertical_strategy": "text", "horizontal_strategy": "text"})[0][:2])
