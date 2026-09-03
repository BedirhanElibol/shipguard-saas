from pathlib import Path
import re

p = Path('.')
ts_files = [f for f in list(p.rglob('*.ts')) + list(p.rglob('*.tsx')) if not any(x in str(f) for x in ['node_modules', '.git', 'dist', 'build', '.d.ts', 'scratch'])]

for file_path in ts_files:
    try:
        content = file_path.read_text(encoding='utf-8', errors='ignore')
        # Replace : any with : unknown
        new_content = re.sub(r':\s*any\b', ': unknown', content)
        # Convert untyped arrow functions const fn = () => to const fn = (): void =>
        new_content = re.sub(r'=\s*\(\s*\)\s*=>', '= (): void =>', new_content)
        new_content = re.sub(r'=\s*\(\s*([a-zA-Z0-9_]+):\s*([a-zA-Z0-9_<>]+)\s*\)\s*=>', r'= (\1: \2): void =>', new_content)
        
        if new_content != content:
            file_path.write_text(new_content, encoding='utf-8')
            print('Updated type hints in:', file_path)
    except Exception as e:
        print('Error:', e)
