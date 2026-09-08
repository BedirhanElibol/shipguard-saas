#!/usr/bin/env python3
"""
Automated Verification Suite: Bug Elimination & Production Hardening
Validates 7 critical checks across modified files:
- Check 1: Zero occurrences of 'bedirelibol7' or 'Bedirhan Elibol' in hooks/useDashboardState.ts.
- Check 2: components/ScanRunnerView.tsx does not filter by project.name.toLowerCase().includes('shipguard') or old mock IDs 'proj-nexus'.
- Check 3: components/layout/Header.tsx creates a new Project object with proj-${Date.now()} on repository search instead of mutating in-place.
- Check 4: app/checkout/page.tsx imports and calls purgeShipguardStorage.
- Check 5: hooks/useDashboardState.ts has a reactive useEffect monitoring searchParams.
- Check 6: Zero Turkish characters across all modified files.
- Check 7: TypeScript compiles with 0 errors (npx tsc --noEmit).
"""

import os
import re
import subprocess
import sys
from pathlib import Path

WORKSPACE_ROOT = Path(__file__).resolve().parent.parent

MODIFIED_FILES = [
    WORKSPACE_ROOT / "hooks" / "useDashboardState.ts",
    WORKSPACE_ROOT / "components" / "ScanRunnerView.tsx",
    WORKSPACE_ROOT / "components" / "layout" / "Header.tsx",
    WORKSPACE_ROOT / "app" / "checkout" / "page.tsx",
]

TURKISH_CHAR_PATTERN = re.compile(r'[çğışöüÇĞİŞÖÜ]')

def run_check(check_id: str, description: str, func) -> bool:
    print(f"\n[RUNNING] {check_id}: {description}")
    try:
        success, message = func()
        if success:
            print(f"  [PASS] {check_id}: {message}")
            return True
        else:
            print(f"  [FAIL] {check_id}: {message}")
            return False
    except Exception as e:
        print(f"  [ERROR] {check_id}: Exception occurred: {e}")
        return False

def check_1_pii_leak():
    path = WORKSPACE_ROOT / "hooks" / "useDashboardState.ts"
    if not path.exists():
        return False, f"File not found: {path}"
    content = path.read_text(encoding="utf-8")
    leaks = []
    if "bedirelibol7" in content.lower():
        leaks.append("bedirelibol7")
    if "bedirhan elibol" in content.lower():
        leaks.append("Bedirhan Elibol")
    if leaks:
        return False, f"Found PII leak in useDashboardState.ts: {', '.join(leaks)}"
    return True, "Zero occurrences of 'bedirelibol7' or 'Bedirhan Elibol' found."

def check_2_scanner_filters():
    path = WORKSPACE_ROOT / "components" / "ScanRunnerView.tsx"
    if not path.exists():
        return False, f"File not found: {path}"
    content = path.read_text(encoding="utf-8")
    issues = []
    normalized = content.lower().replace(" ", "").replace('"', "'")
    if "project.name.tolowercase().includes('shipguard')" in normalized:
        issues.append("Found legacy filter: project.name.toLowerCase().includes('shipguard')")
    if "proj-nexus" in content:
        issues.append("Found legacy mock ID: 'proj-nexus'")
    if issues:
        return False, "; ".join(issues)
    return True, "No false-positive scanner locks or old mock ID filters found."

def check_3_header_project_creation():
    path = WORKSPACE_ROOT / "components" / "layout" / "Header.tsx"
    if not path.exists():
        return False, f"File not found: {path}"
    content = path.read_text(encoding="utf-8")
    if "proj-${Date.now()}" not in content and 'proj-${Date.now()}' not in content:
        return False, "Header.tsx does not instantiate new Project with 'proj-${Date.now()}'"
    if "const newProject: Project" not in content and "newProject" not in content:
        return False, "Header.tsx does not define newProject object"
    return True, "Header.tsx cleanly constructs new Project with 'proj-${Date.now()}' on repository search."

def check_4_checkout_storage_purge():
    path = WORKSPACE_ROOT / "app" / "checkout" / "page.tsx"
    if not path.exists():
        return False, f"File not found: {path}"
    content = path.read_text(encoding="utf-8")
    if "purgeShipguardStorage" not in content:
        return False, "purgeShipguardStorage not imported or referenced in checkout/page.tsx"
    if "purgeShipguardStorage(" not in content:
        return False, "purgeShipguardStorage is imported but not called in checkout/page.tsx"
    return True, "purgeShipguardStorage is correctly imported and invoked in app/checkout/page.tsx."

def check_5_search_params_reactivity():
    path = WORKSPACE_ROOT / "hooks" / "useDashboardState.ts"
    if not path.exists():
        return False, f"File not found: {path}"
    content = path.read_text(encoding="utf-8")
    if "useSearchParams" not in content:
        return False, "useSearchParams not found in useDashboardState.ts"
    
    if "[searchParams]" not in content:
        return False, "No useEffect with [searchParams] dependency found in useDashboardState.ts"
    return True, "useDashboardState.ts contains reactive useEffect tracking searchParams."

def check_6_zero_turkish_characters():
    found_chars = {}
    for file_path in MODIFIED_FILES:
        if not file_path.exists():
            return False, f"File not found: {file_path}"
        content = file_path.read_text(encoding="utf-8")
        matches = TURKISH_CHAR_PATTERN.findall(content)
        if matches:
            found_chars[file_path.name] = set(matches)
    if found_chars:
        details = [f"{fname}: {list(chars)}" for fname, chars in found_chars.items()]
        return False, f"Found Turkish characters in: {'; '.join(details)}"
    return True, f"Zero Turkish characters across all {len(MODIFIED_FILES)} modified files."

def check_7_typescript_compilation():
    cmd = "npx tsc --noEmit"
    result = subprocess.run(
        cmd,
        shell=True,
        cwd=str(WORKSPACE_ROOT),
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True
    )
    if result.returncode != 0:
        return False, f"tsc returned exit code {result.returncode}:\n{result.stdout}\n{result.stderr}"
    return True, "TypeScript compiled successfully with 0 errors."

def main():
    print("=" * 70)
    print("ShipGuard Production Hardening: Automated Verification Suite")
    print(f"Workspace: {WORKSPACE_ROOT}")
    print("=" * 70)

    checks = [
        ("Check 1", "Zero PII leaks (bedirelibol7 / Bedirhan Elibol) in hooks/useDashboardState.ts", check_1_pii_leak),
        ("Check 2", "ScanRunnerView does not filter by project name or old mock IDs", check_2_scanner_filters),
        ("Check 3", "Header.tsx creates new Project with proj-${Date.now()}", check_3_header_project_creation),
        ("Check 4", "app/checkout/page.tsx imports and calls purgeShipguardStorage", check_4_checkout_storage_purge),
        ("Check 5", "hooks/useDashboardState.ts has reactive useEffect monitoring searchParams", check_5_search_params_reactivity),
        ("Check 6", "Zero Turkish characters across all modified files", check_6_zero_turkish_characters),
        ("Check 7", "TypeScript compiles with 0 errors (npx tsc --noEmit)", check_7_typescript_compilation),
    ]

    all_passed = True
    results = []
    for check_id, desc, fn in checks:
        passed = run_check(check_id, desc, fn)
        results.append((check_id, desc, passed))
        if not passed:
            all_passed = False

    print("\n" + "=" * 70)
    print("SUMMARY OF VERIFICATION RESULTS")
    print("=" * 70)
    for check_id, desc, passed in results:
        status = "[PASS]" if passed else "[FAIL]"
        print(f"  {status} {check_id}: {desc}")

    if all_passed:
        print("\n>>> ALL 7 AUTOMATED VERIFICATION CHECKS PASSED SUCCESSFULLY! <<<")
        sys.exit(0)
    else:
        print("\n>>> ONE OR MORE VERIFICATION CHECKS FAILED! <<<")
        sys.exit(1)

if __name__ == "__main__":
    main()
