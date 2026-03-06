import os
import glob
import re

correct_snippet = """<div class="theme-toggle-pill">
                <button data-theme="system" title="System">
                    <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
                        <rect x="2" y="3" width="20" height="14" rx="2" ry="2" />
                        <line x1="8" y1="21" x2="16" y2="21" />
                        <line x1="12" y1="17" x2="12" y2="21" />
                    </svg>
                </button>
                <button data-theme="dark" title="Dark">
                    <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
                        <path d="M21 12.79A9 9 0 1111.21 3 7 7 0 0021 12.79z" />
                    </svg>
                </button>
                <button data-theme="light" title="Light">
                    <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
                        <circle cx="12" cy="12" r="5" />
                        <line x1="12" y1="1" x2="12" y2="3" />
                        <line x1="12" y1="21" x2="12" y2="23" />
                        <line x1="4.22" y1="4.22" x2="5.64" y2="5.64" />
                        <line x1="18.36" y1="18.36" x2="19.78" y2="19.78" />
                        <line x1="1" y1="12" x2="3" y2="12" />
                        <line x1="21" y1="12" x2="23" y2="12" />
                        <line x1="4.22" y1="19.78" x2="5.64" y2="18.36" />
                        <line x1="18.36" y1="5.64" x2="19.78" y2="4.22" />
                    </svg>
                </button>
            </div>"""

directory = r'c:\Users\ASUS\Desktop\Nullify\Nullify\core\templates\nulify'
files = glob.glob(os.path.join(directory, '*.html'))

pattern = re.compile(r'<div class="theme-toggle-pill">.*?</div>', re.DOTALL)

for file in files:
    if 'base.html' in file or 'settings.html' in file or 'dashboard.html' in file:
        continue # base has it correct already. settings and dashboard extend base.
    
    with open(file, 'r', encoding='utf-8') as f:
        content = f.read()
    
    if pattern.search(content):
        # We need to maintain the same indentation for the snippet.
        # But actually, the correct_snippet already has some baseline indentation which is generally fine.
        # We can just replace the whole div.
        new_content = pattern.sub(correct_snippet, content)
        with open(file, 'w', encoding='utf-8') as f:
            f.write(new_content)
        print(f"Updated {file}")
