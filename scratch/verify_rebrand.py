import os, re

dirs_to_check = ['app', 'components', 'public']
findings = []

for d in dirs_to_check:
    for root, _, files in os.walk(d):
        for f in files:
            if not f.endswith(('.tsx', '.ts', '.html', '.json')):
                continue
            path = os.path.join(root, f)
            with open(path, 'r', encoding='utf-8') as file:
                for num, line in enumerate(file, 1):
                    if 'shipguard' in line.lower():
                        clean = re.sub(r"['\"](shipguard_[a-zA-Z0-9_]+|shipguardignore|\.shipguardignore)['\"]", '', line)
                        clean = re.sub(r'proj-shipguard-self', '', clean)
                        clean = re.sub(r'purgeShipguardStorage', '', clean)
                        clean = re.sub(r'SHIPGUARD_PRICING_PLANS', '', clean)
                        clean = re.sub(r'shipguardSolution', '', clean)
                        clean = re.sub(r'shipguard-saas\.vercel\.app', '', clean)
                        clean = re.sub(r'shipguard\.dev', '', clean)
                        clean = re.sub(r'shipguard-core', '', clean)
                        if 'shipguard' in clean.lower() and not clean.strip().startswith('//') and not clean.strip().startswith('*'):
                            findings.append((path, num, line.strip()))

print(f'Visible/Unhandled ShipGuard matches: {len(findings)}')
for path, num, line in findings:
    print(f'{path}:{num}: {line}')
