import os
import json

workspace_dir = r"c:\Users\Bedirhan\Desktop\newday"
real_files = []

target_dirs = ["app", "components", "data", "lib"]

for td in target_dirs:
    dir_path = os.path.join(workspace_dir, td)
    if not os.path.exists(dir_path):
        continue
    for root, dirs, files in os.walk(dir_path):
        for file in files:
            if file.endswith((".ts", ".tsx", ".js", ".css")):
                full_path = os.path.join(root, file)
                rel_path = os.path.relpath(full_path, workspace_dir).replace("\\", "/")
                with open(full_path, "r", encoding="utf-8", errors="ignore") as f:
                    content = f.read()
                real_files.append({"path": rel_path, "content": content})

ts_content = "import { CodeFile } from '@/lib/scanner-engine';\n\n"
ts_content += "export const WORKSPACE_SOURCE_FILES: CodeFile[] = " + json.dumps(real_files, indent=2) + ";\n"

out_path = os.path.join(workspace_dir, "data", "workspaceFiles.ts")
with open(out_path, "w", encoding="utf-8") as f:
    f.write(ts_content)

print(f"Successfully written {len(real_files)} REAL source files into data/workspaceFiles.ts!")
