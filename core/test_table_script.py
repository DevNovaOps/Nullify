import sys
import pdfplumber

def main():
    try:
        pdf_path = r'c:\Nirma\core\media\uploads\2026\03\customer_support_report.pdf'
        with pdfplumber.open(pdf_path) as pdf:
            page = pdf.pages[0]
            
            with open('test_table.txt', 'w', encoding='utf-8') as f:
                f.write("FIND_TABLES:\n")
                f.write(str(page.find_tables()) + "\n")
                
                f.write("\nCUSTOM_TEXT_TABLES:\n")
                custom = page.find_tables({"vertical_strategy": "text", "horizontal_strategy": "text"})
                f.write(str(custom) + "\n")
                if custom:
                    f.write(str(page.extract_tables({"vertical_strategy": "text", "horizontal_strategy": "text"})))
                    
                f.write("\n-----------------\n")
                f.write(page.extract_text(layout=True))
                
    except Exception as e:
        with open('test_table.txt', 'w', encoding='utf-8') as f:
            f.write(f"ERROR: {e}")

if __name__ == "__main__":
    main()
