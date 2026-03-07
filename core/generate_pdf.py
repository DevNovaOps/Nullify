from markdown_pdf import MarkdownPdf, Section

try:
    with open(r'c:\Users\Dev\Desktop\Nullify_Setup_Documentation.md', 'r', encoding='utf-8') as f:
        md_text = f.read()
    
    pdf = MarkdownPdf(toc_level=2)
    pdf.add_section(Section(md_text))
    
    out_path = r'c:\Users\Dev\Desktop\Nullify_Setup_Documentation.pdf'
    pdf.save(out_path)
    
    print("SUCCESS: PDF generated at", out_path)
except Exception as e:
    print("ERROR:", str(e))
