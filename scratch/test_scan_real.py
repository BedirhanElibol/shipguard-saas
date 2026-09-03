import os
import json
import re

workspace_dir = r"c:\Users\Bedirhan\Desktop\newday"
with open(os.path.join(workspace_dir, "data", "workspaceFiles.ts"), "r", encoding="utf-8") as f:
    text = f.read()

# Extract count of files
count = text.count('"path":')
print(f"Total real files embedded in workspaceFiles.ts: {count}")
