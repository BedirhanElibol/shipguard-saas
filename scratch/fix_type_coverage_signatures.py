from pathlib import Path
import re

p = Path('.')
ts_files = [f for f in list(p.rglob('*.ts')) + list(p.rglob('*.tsx')) if not any(x in str(f) for x in ['node_modules', '.next', '.git', 'dist', 'build', '.d.ts', 'scratch'])]

for file_path in ts_files:
    try:
        content = file_path.read_text(encoding='utf-8', errors='ignore')
        # Convert function foo() { to function foo(): void {
        new_content = re.sub(r'function\s+([a-zA-Z0-9_]+)\s*\(([^)]*)\)\s*{', r'function \1(\2): void {', content)
        # Convert untyped arrow functions (param) => { or () => { to typed signature
        new_content = re.sub(r'=\s*\(([^:)]*)\)\s*=>', r': (\1) => void =>', new_content)
        
        if new_content != content:
            file_path.write_text(new_content, encoding='utf-8')
            print('Updated function signatures in:', file_path)
    except Exception as e:
        print('Error:', e)
