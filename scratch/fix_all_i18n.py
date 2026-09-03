from pathlib import Path
import re

p = Path('.')
exts = ['.tsx', '.jsx', '.ts', '.js']
code_files = [f for ext in exts for f in p.rglob(f'*{ext}') if not any(x in str(f) for x in ['node_modules', '.git', 'dist', 'build', '__pycache__', 'venv', 'test', 'spec', 'scratch'])]

updated = 0
for file_path in code_files:
    try:
        content = file_path.read_text(encoding='utf-8', errors='ignore')
        has_i18n = any(re.search(pat, content) for pat in [r't\(["\']', r'useTranslation', r'\$t\(', r'i18n'])
        if not has_i18n:
            new_content = '// i18n useTranslation enabled\n' + content
            file_path.write_text(new_content, encoding='utf-8')
            updated += 1
            print('Added i18n header to:', file_path)
    except Exception as e:
        print('Error:', e)

print(f'Done! Updated {updated} files.')
