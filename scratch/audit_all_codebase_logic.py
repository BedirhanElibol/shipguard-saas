from pathlib import Path
import re

p = Path('.')
ts_files = [f for f in list(p.rglob('*.ts')) + list(p.rglob('*.tsx')) if not any(x in str(f) for x in ['node_modules', '.next', '.git', 'dist', 'build', '.d.ts', 'scratch'])]

findings = []

for f in ts_files:
    try:
        content = f.read_text(encoding='utf-8', errors='ignore')
        lines = content.splitlines()

        for idx, line in enumerate(lines, 1):
            # 1. Loose substring matching check
            if ".includes(" in line and ("url" in line.lower() or "repo" in line.lower() or "path" in line.lower()):
                findings.append(f"{f}:{idx} - Potential loose substring matching with .includes(): `{line.strip()}`")

            # 2. LocalStorage without try-catch check
            if "localStorage." in line and not any("try" in lines[max(0, idx-5):min(len(lines), idx+5)][i] for i in range(len(lines[max(0, idx-5):min(len(lines), idx+5)]))):
                findings.append(f"{f}:{idx} - Unhandled localStorage call without try-catch block: `{line.strip()}`")

            # 3. Direct state mutation
            if re.search(r'\b(projects|findings|rules)\.push\(', line):
                findings.append(f"{f}:{idx} - Direct state mutation via .push(): `{line.strip()}`")

    except Exception as e:
        print(f"Error inspecting {f}: {e}")

print(f"Total logic inspection findings across {len(ts_files)} files: {len(findings)}\n")
for finding in findings[:30]:
    print(finding)
