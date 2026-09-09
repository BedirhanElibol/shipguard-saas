import os
import re
import sys

def check_env_config():
    path = os.path.join("lib", "env-config.ts")
    assert os.path.exists(path), f"File missing: {path}"
    with open(path, "r", encoding="utf-8") as f:
        content = f.read()
    
    assert "export function isDevelopment(): boolean" in content, "isDevelopment missing"
    assert "export function isProduction(): boolean" in content, "isProduction missing"
    assert "export function canAccessLocalAudit(): boolean" in content, "canAccessLocalAudit missing"
    assert "localhost" in content and "127.0.0.1" in content, "localhost check missing"
    assert "NEXT_PUBLIC_ALLOW_LOCAL_AUDIT" in content, "test env var missing"
    assert "vercel.app" in content or "shipguard.dev" in content, "production domain check missing"
    print("[OK] lib/env-config.ts passed verification.")

def check_dashboard_state():
    path = os.path.join("hooks", "useDashboardState.ts")
    assert os.path.exists(path), f"File missing: {path}"
    with open(path, "r", encoding="utf-8") as f:
        content = f.read()

    assert "canAccessLocalAudit" in content, "canAccessLocalAudit not imported in useDashboardState"
    assert "v7_showcase_guest_mode_clean" in content, "v7 storage version missing"
    assert "proj-shipguard-self" in content, "proj-shipguard-self auto-heal check missing"
    assert "safeSetStorageItem('shipguard_selected_project_id'" in content, "selected project storage persist missing"
    print("[OK] hooks/useDashboardState.ts passed verification.")

def check_gate_check_api():
    path = os.path.join("app", "api", "v1", "gate-check", "route.ts")
    assert os.path.exists(path), f"File missing: {path}"
    with open(path, "r", encoding="utf-8") as f:
        content = f.read()

    assert "canAccessLocalAudit" in content, "canAccessLocalAudit not imported in gate-check route"
    assert "rawRepoUrl.toLowerCase() === 'local'" in content, "local check missing"
    assert "status: 403" in content, "status 403 missing"
    assert "Local workspace self-audit is restricted to local development environments." in content, "error message missing"
    print("[OK] app/api/v1/gate-check/route.ts passed verification.")

def check_scan_runner_view():
    path = os.path.join("components", "ScanRunnerView.tsx")
    assert os.path.exists(path), f"File missing: {path}"
    with open(path, "r", encoding="utf-8") as f:
        content = f.read()

    assert "canAccessLocalAudit" in content, "canAccessLocalAudit not imported in ScanRunnerView"
    assert "Local workspace self-audit is available only in local development." in content, "guard message missing"
    print("[OK] components/ScanRunnerView.tsx passed verification.")

def check_english_only():
    files_to_check = [
        os.path.join("lib", "env-config.ts"),
        os.path.join("hooks", "useDashboardState.ts"),
        os.path.join("app", "api", "v1", "gate-check", "route.ts"),
        os.path.join("components", "ScanRunnerView.tsx"),
    ]
    turkish_chars = set("ğĞıİşŞçÇöÖüÜ")
    for fpath in files_to_check:
        with open(fpath, "r", encoding="utf-8") as f:
            for line_idx, line in enumerate(f, start=1):
                found_chars = [c for c in line if c in turkish_chars]
                if found_chars:
                    print(f"Warning/Violation: Turkish character '{found_chars}' in {fpath}:{line_idx}")
                    sys.exit(1)
    print("[OK] Strict 100% Native English check passed (Zero Turkish characters).")

if __name__ == "__main__":
    check_env_config()
    check_dashboard_state()
    check_gate_check_api()
    check_scan_runner_view()
    check_english_only()
    print("\nALL SECURITY AUDITOR CHECKS PASSED SUCCESSFULLY!")
