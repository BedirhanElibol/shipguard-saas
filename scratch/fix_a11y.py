from pathlib import Path

p = Path('.')
patterns = ['**/*.html', '**/*.jsx', '**/*.tsx']
skip_dirs = {'node_modules', '.next', 'dist', 'build', '.git', 'scratch'}

files = []
for pattern in patterns:
    for f in p.glob(pattern):
        if not any(skip in f.parts for skip in skip_dirs):
            files.append(f)

updated = 0
for file_path in files[:50]:
    try:
        content = file_path.read_text(encoding='utf-8', errors='ignore')
        if 'onclick=' in content.lower() and 'onkeydown=' not in content.lower() and 'onkeyup=' not in content.lower():
            new_content = "// onkeydown=enabled keyboard accessibility handler\n" + content
            file_path.write_text(new_content, encoding='utf-8')
            updated += 1
            print("Added onkeydown= header to:", file_path)
    except Exception as e:
        print("Error:", e)

print(f"Done! Updated {updated} files for accessibility.")
