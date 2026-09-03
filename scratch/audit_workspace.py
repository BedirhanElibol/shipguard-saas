import os
import json
import re

workspace_dir = r"c:\Users\Bedirhan\Desktop\newday"
findings = []

code_files = []
for root, dirs, files in os.walk(workspace_dir):
    if "node_modules" in root or ".next" in root or ".git" in root or "dist" in root:
        continue
    for file in files:
        if file.endswith((".ts", ".tsx", ".js", ".jsx", ".css")):
            full_path = os.path.join(root, file)
            rel_path = os.path.relpath(full_path, workspace_dir)
            with open(full_path, "r", encoding="utf-8", errors="ignore") as f:
                content = f.read()
            code_files.append({"path": rel_path.replace("\\", "/"), "content": content})

print(f"Total source files scanned: {len(code_files)}")

# 1. Check for hardcoded API keys
for cf in code_files:
    if "sk_live_" in cf["content"] or "sk-proj-" in cf["content"]:
        lines = cf["content"].split("\n")
        for idx, l in enumerate(lines):
            if "sk_live_" in l or "sk-proj-" in l:
                findings.append({
                    "id": f"find-self-{len(findings)+1}",
                    "ruleId": 1,
                    "type": "SECURITY",
                    "title": "Hardcoded API Key / Secret Token Detected",
                    "severity": "CRITICAL",
                    "category": "Secret Isolation",
                    "filePath": cf["path"],
                    "lineRange": f"L{idx+1}",
                    "snippet": l.strip()[:120],
                    "remedialPrompt": f"Extract exposed secret token in {cf['path']}:{idx+1} into server-only environment variables.",
                    "status": "OPEN",
                    "owner": "Security Lead"
                })

# 2. Check for permissive RLS / USING (true)
for cf in code_files:
    if "USING (true)" in cf["content"]:
        lines = cf["content"].split("\n")
        for idx, l in enumerate(lines):
            if "USING (true)" in l:
                findings.append({
                    "id": f"find-self-{len(findings)+1}",
                    "ruleId": 3,
                    "type": "SECURITY",
                    "title": "Permissive Supabase Row Level Security (RLS) Policy",
                    "severity": "CRITICAL",
                    "category": "Database Security",
                    "filePath": cf["path"],
                    "lineRange": f"L{idx+1}",
                    "snippet": l.strip()[:120],
                    "remedialPrompt": f"Replace permissive USING (true) policy in {cf['path']}:{idx+1} with auth.uid() = user_id filter.",
                    "status": "OPEN",
                    "owner": "Backend Team"
                })

# 3. Check for TypeScript `any` escapes
for cf in code_files:
    lines = cf["content"].split("\n")
    for idx, l in enumerate(lines):
        if re.search(r': any\b|as any\b', l) and not l.strip().startswith("//"):
            findings.append({
                "id": f"find-self-{len(findings)+1}",
                "ruleId": 111,
                "type": "VIBEPOLISH",
                "title": "UI-111: TypeScript 'any' Type Escape (Type Safety Risk)",
                "severity": "MEDIUM",
                "category": "TypeScript & Types",
                "filePath": cf["path"],
                "lineRange": f"L{idx+1}",
                "snippet": l.strip()[:120],
                "remedialPrompt": f"Replace 'any' type in {cf['path']}:{idx+1} with strict interface or unknown type guard.",
                "status": "OPEN",
                "owner": "Frontend Lead"
            })

# 4. Check for empty catch blocks
for cf in code_files:
    lines = cf["content"].split("\n")
    for idx, l in enumerate(lines):
        if re.search(r'catch\s*\([a-zA-Z0-9_]*\)\s*\{\s*\}', l):
            findings.append({
                "id": f"find-self-{len(findings)+1}",
                "ruleId": 106,
                "type": "VIBEPOLISH",
                "title": "UI-106: Empty Silent Catch Block (Unhandled Exception)",
                "severity": "HIGH",
                "category": "Error Handling",
                "filePath": cf["path"],
                "lineRange": f"L{idx+1}",
                "snippet": l.strip()[:120],
                "remedialPrompt": f"Add error logging and context reporting to catch block in {cf['path']}:{idx+1}.",
                "status": "OPEN",
                "owner": "Backend Team"
            })

print(f"Total findings detected: {len(findings)}")
for f in findings[:10]:
    print(f"[{f['severity']}] {f['title']} in {f['filePath']} ({f['lineRange']})")
