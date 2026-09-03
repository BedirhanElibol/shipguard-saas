from pathlib import Path
import re

files_to_fix = [
    'data/workspaceFiles.ts',
    'components/InteractiveAnalyzer.tsx',
    'lib/github-api.ts',
    'lib/i18n.ts',
    'lib/scanner-engine.ts',
    'components/OverviewView.tsx',
    'components/SmoothScroll.tsx'
]

for file_str in files_to_fix:
    p = Path(file_str)
    if p.exists():
        content = p.read_text(encoding='utf-8')
        # Replace : any with : unknown in ts code/strings
        new_content = re.sub(r':\s*any\b', ': unknown', content)
        p.write_text(new_content, encoding='utf-8')
        print('Cleaned any types in:', file_str)
