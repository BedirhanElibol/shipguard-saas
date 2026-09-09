#!/usr/bin/env python3
"""
Guest Experience & Production Readiness Verification Suite
Phase 2 Test Engineer & Verification Specialist

Validates:
1. lib/env-config.ts existence and exports (isDevelopment, isProduction, canAccessLocalAudit)
2. canAccessLocalAudit() rejection of production hosts (*.vercel.app, shipguard.dev)
3. data/mockData.ts initial showcase project calibration (proj-saas-starter, score >= 85, PASSED, 0 criticals)
4. components/ProjectsView.tsx exclusion of internal self-audit presets
5. DemoShowcaseBanner presence in OverviewView and DashboardView
6. hooks/useDashboardState.ts storage version ('v7_showcase_guest_mode_clean') and auto-heal logic
7. app/api/v1/gate-check/route.ts 403 rejection for local audits in production
8. Zero Turkish characters across all modified files (100% Native English standard)
"""

import os
import sys
import re
import json
import subprocess
from pathlib import Path

WORKSPACE_ROOT = Path(__file__).resolve().parent.parent

class Colors:
    GREEN = '\033[92m'
    RED = '\033[91m'
    YELLOW = '\033[93m'
    CYAN = '\033[96m'
    BOLD = '\033[1m'
    RESET = '\033[0m'

def log_test_header(title: str):
    print(f"\n{Colors.BOLD}{Colors.CYAN}=== [TEST] {title} ==={Colors.RESET}")

def log_pass(msg: str):
    print(f"  {Colors.GREEN}[PASS]{Colors.RESET} {msg}")

def log_fail(msg: str):
    print(f"  {Colors.RED}[FAIL]{Colors.RESET} {msg}")

def log_info(msg: str):
    print(f"  {Colors.YELLOW}[INFO]{Colors.RESET} {msg}")

class GuestExperienceVerifier:
    def __init__(self, root: Path):
        self.root = root
        self.passed = 0
        self.failed = 0

    def assert_true(self, condition: bool, description: str):
        if condition:
            log_pass(description)
            self.passed += 1
        else:
            log_fail(description)
            self.failed += 1

    def test_env_config_exports(self):
        log_test_header("1. lib/env-config.ts Existence and Exports")
        file_path = self.root / "lib" / "env-config.ts"
        self.assert_true(file_path.exists(), f"File exists: {file_path.relative_to(self.root)}")

        if not file_path.exists():
            return

        content = file_path.read_text(encoding="utf-8")
        self.assert_true(
            bool(re.search(r"export\s+function\s+isDevelopment", content)),
            "Exports 'isDevelopment()'"
        )
        self.assert_true(
            bool(re.search(r"export\s+function\s+isProduction", content)),
            "Exports 'isProduction()'"
        )
        self.assert_true(
            bool(re.search(r"export\s+function\s+canAccessLocalAudit", content)),
            "Exports 'canAccessLocalAudit()'"
        )

    def test_can_access_local_audit_hosts(self):
        log_test_header("2. canAccessLocalAudit() Host Isolation & Rejection")
        file_path = self.root / "lib" / "env-config.ts"
        content = file_path.read_text(encoding="utf-8")

        # Static Code Analysis
        has_vercel_check = "vercel.app" in content
        has_shipguard_check = "shipguard.dev" in content
        self.assert_true(has_vercel_check, "Static check: inspects *.vercel.app domain")
        self.assert_true(has_shipguard_check, "Static check: inspects shipguard.dev domain")

        # Dynamic Execution via tsx
        runner_ts = """
import { canAccessLocalAudit } from '../lib/env-config';

// 1. Production host: vercel.app
(global as any).window = { location: { hostname: 'shipguard.vercel.app' } };
const vercelProd = canAccessLocalAudit();

// 2. Production host: shipguard.dev
(global as any).window = { location: { hostname: 'shipguard.dev' } };
const shipguardProd = canAccessLocalAudit();

// 3. Production host subdomain: app.shipguard.dev
(global as any).window = { location: { hostname: 'app.shipguard.dev' } };
const subShipguardProd = canAccessLocalAudit();

// 4. Local dev host: localhost
(global as any).window = { location: { hostname: 'localhost' } };
const localhostDev = canAccessLocalAudit();

// 5. Local dev host: 127.0.0.1
(global as any).window = { location: { hostname: '127.0.0.1' } };
const localIpDev = canAccessLocalAudit();

console.log(JSON.stringify({
  vercelProd,
  shipguardProd,
  subShipguardProd,
  localhostDev,
  localIpDev
}));
"""
        temp_file = self.root / "scratch" / "_temp_host_test.ts"
        try:
            temp_file.write_text(runner_ts, encoding="utf-8")
            res = subprocess.run(
                ["npx.cmd" if os.name == "nt" else "npx", "tsx", str(temp_file)],
                capture_output=True,
                text=True,
                shell=(os.name == "nt"),
                cwd=str(self.root)
            )
            if res.returncode == 0 and res.stdout.strip():
                data = json.loads(res.stdout.strip())
                self.assert_true(data["vercelProd"] is False, "Runtime: 'shipguard.vercel.app' rejected (returns false)")
                self.assert_true(data["shipguardProd"] is False, "Runtime: 'shipguard.dev' rejected (returns false)")
                self.assert_true(data["subShipguardProd"] is False, "Runtime: 'app.shipguard.dev' rejected (returns false)")
                self.assert_true(data["localhostDev"] is True, "Runtime: 'localhost' allowed in dev (returns true)")
                self.assert_true(data["localIpDev"] is True, "Runtime: '127.0.0.1' allowed in dev (returns true)")
            else:
                log_fail(f"tsx runner failed with code {res.returncode}: {res.stderr}")
                self.failed += 1
        except Exception as e:
            log_fail(f"Error running tsx host test: {e}")
            self.failed += 1
        finally:
            if temp_file.exists():
                temp_file.unlink()

    def test_mock_data_showcase_project(self):
        log_test_header("3. data/mockData.ts Showcase Project Calibration")
        file_path = self.root / "data" / "mockData.ts"
        self.assert_true(file_path.exists(), f"File exists: {file_path.relative_to(self.root)}")

        # Dynamic verification of MOCK_PROJECTS[0]
        runner_ts = """
import { MOCK_PROJECTS } from '../data/mockData';

const p0 = MOCK_PROJECTS[0];
console.log(JSON.stringify({
  id: p0.id,
  name: p0.name,
  score: p0.readinessScore,
  gateStatus: p0.gateStatus,
  criticalCount: p0.criticalCount,
  highCount: p0.highCount,
  mediumCount: p0.mediumCount,
  findingsCount: p0.findings ? p0.findings.length : 0
}));
"""
        temp_file = self.root / "scratch" / "_temp_mock_test.ts"
        try:
            temp_file.write_text(runner_ts, encoding="utf-8")
            res = subprocess.run(
                ["npx.cmd" if os.name == "nt" else "npx", "tsx", str(temp_file)],
                capture_output=True,
                text=True,
                shell=(os.name == "nt"),
                cwd=str(self.root)
            )
            if res.returncode == 0 and res.stdout.strip():
                data = json.loads(res.stdout.strip())
                self.assert_true(data["id"] == "proj-saas-starter", f"MOCK_PROJECTS[0].id is 'proj-saas-starter' (got '{data['id']}')")
                self.assert_true(data["score"] >= 85, f"MOCK_PROJECTS[0].readinessScore >= 85 (got {data['score']})")
                self.assert_true(data["gateStatus"] == "PASSED", f"MOCK_PROJECTS[0].gateStatus is 'PASSED' (got '{data['gateStatus']}')")
                self.assert_true(data["criticalCount"] == 0, f"MOCK_PROJECTS[0].criticalCount is 0 (got {data['criticalCount']})")
                self.assert_true(data["findingsCount"] > 0, f"MOCK_PROJECTS[0] contains realistic demo findings (count: {data['findingsCount']})")
            else:
                log_fail(f"tsx runner failed with code {res.returncode}: {res.stderr}")
                self.failed += 1
        except Exception as e:
            log_fail(f"Error running tsx mock test: {e}")
            self.failed += 1
        finally:
            if temp_file.exists():
                temp_file.unlink()

    def test_projects_view_self_audit_exclusion(self):
        log_test_header("4. components/ProjectsView.tsx Preset Hardening")
        file_path = self.root / "components" / "ProjectsView.tsx"
        self.assert_true(file_path.exists(), f"File exists: {file_path.relative_to(self.root)}")

        content = file_path.read_text(encoding="utf-8")
        self.assert_true(
            "proj-preset-self" not in content,
            "Does NOT contain deprecated 'proj-preset-self'"
        )
        self.assert_true(
            "ShipGuard (Self Audit)" not in content,
            "Does NOT contain 'ShipGuard (Self Audit)' in quick presets"
        )
        self.assert_true(
            "Next.js 15 SaaS Starter" in content,
            "Contains production demo preset 'Next.js 15 SaaS Starter'"
        )

    def test_demo_showcase_banner_integration(self):
        log_test_header("5. DemoShowcaseBanner Presence in Views")
        overview_path = self.root / "components" / "OverviewView.tsx"
        dashboard_path = self.root / "components" / "dashboard" / "DashboardView.tsx"

        self.assert_true(overview_path.exists(), "components/OverviewView.tsx exists")
        self.assert_true(dashboard_path.exists(), "components/dashboard/DashboardView.tsx exists")

        overview_content = overview_path.read_text(encoding="utf-8")
        dashboard_content = dashboard_path.read_text(encoding="utf-8")

        self.assert_true(
            "DemoShowcaseBanner" in overview_content,
            "OverviewView.tsx includes DemoShowcaseBanner"
        )
        self.assert_true(
            "DemoShowcaseBanner" in dashboard_content,
            "DashboardView.tsx includes DemoShowcaseBanner"
        )

    def test_use_dashboard_state_storage_and_autoheal(self):
        log_test_header("6. hooks/useDashboardState.ts Versioning & Auto-Heal")
        file_path = self.root / "hooks" / "useDashboardState.ts"
        self.assert_true(file_path.exists(), f"File exists: {file_path.relative_to(self.root)}")

        content = file_path.read_text(encoding="utf-8")
        expected_version = "v7_showcase_guest_mode_clean"
        self.assert_true(
            expected_version in content,
            f"Storage version matches '{expected_version}'"
        )

        has_auto_heal = (
            "Auto-heal" in content or
            "isStaleLocal" in content or
            ("shipguard_selected_project_id" in content and "MOCK_PROJECTS[0]" in content)
        )
        self.assert_true(
            has_auto_heal,
            "Contains auto-heal logic resetting stale local audit to MOCK_PROJECTS[0]"
        )

        has_sanitization = (
            "allowedLocal" in content and
            "proj-shipguard-self" in content and
            "filter" in content
        )
        self.assert_true(
            has_sanitization,
            "Contains environment-aware project filtering for production guests"
        )

    def test_gate_check_api_route(self):
        log_test_header("7. app/api/v1/gate-check/route.ts Local Audit 403 Guard")
        file_path = self.root / "app" / "api" / "v1" / "gate-check" / "route.ts"
        self.assert_true(file_path.exists(), f"File exists: {file_path.relative_to(self.root)}")

        content = file_path.read_text(encoding="utf-8")
        self.assert_true(
            "canAccessLocalAudit" in content,
            "Imports canAccessLocalAudit from @/lib/env-config"
        )

        has_403_rejection = bool(
            re.search(r"rawRepoUrl\.toLowerCase\(\)\s*===\s*['\"]local['\"].*canAccessLocalAudit", content, re.DOTALL) and
            "status: 403" in content
        )
        self.assert_true(
            has_403_rejection,
            "Rejects 'local' repository targets with HTTP 403 when canAccessLocalAudit() is false"
        )

    def test_zero_turkish_characters_audit(self):
        log_test_header("8. Codebase Language Audit (100% Native English)")
        modified_files = [
            "lib/env-config.ts",
            "data/mockData.ts",
            "hooks/useDashboardState.ts",
            "components/ProjectsView.tsx",
            "components/OverviewView.tsx",
            "components/dashboard/DashboardView.tsx",
            "components/layout/Header.tsx",
            "components/dashboard/GateStatusBanner.tsx",
            "components/ScanRunnerView.tsx",
            "app/api/v1/gate-check/route.ts",
            "app/dashboard/page.tsx",
            "lib/rules/ai-cliche-rules.ts",
        ]

        turkish_charset = set("çğıöşüÇĞİÖŞÜ")
        total_violations = 0

        for rel_path in modified_files:
            file_path = self.root / rel_path
            if not file_path.exists():
                log_info(f"Skipping non-existent file: {rel_path}")
                continue

            content = file_path.read_text(encoding="utf-8", errors="replace")
            violations = [c for c in content if c in turkish_charset]
            if violations:
                total_violations += len(violations)
                log_fail(f"{rel_path}: Found {len(violations)} Turkish characters ({set(violations)})")
            else:
                log_pass(f"{rel_path}: 0 Turkish characters (100% English)")

        self.assert_true(
            total_violations == 0,
            f"Zero Turkish characters across all modified files (Total violations: {total_violations})"
        )

    def run_all(self) -> bool:
        print(f"\n{Colors.BOLD}======================================================================{Colors.RESET}")
        print(f"{Colors.BOLD} SHIPGUARD PHASE 2: GUEST EXPERIENCE & VERIFICATION SUITE {Colors.RESET}")
        print(f"{Colors.BOLD}======================================================================{Colors.RESET}")

        self.test_env_config_exports()
        self.test_can_access_local_audit_hosts()
        self.test_mock_data_showcase_project()
        self.test_projects_view_self_audit_exclusion()
        self.test_demo_showcase_banner_integration()
        self.test_use_dashboard_state_storage_and_autoheal()
        self.test_gate_check_api_route()
        self.test_zero_turkish_characters_audit()

        print(f"\n{Colors.BOLD}======================================================================{Colors.RESET}")
        print(f"{Colors.BOLD} VERIFICATION SUMMARY {Colors.RESET}")
        print(f"{Colors.BOLD}======================================================================{Colors.RESET}")
        total = self.passed + self.failed
        print(f"Total Checks: {total}")
        print(f"{Colors.GREEN}Passed: {self.passed}{Colors.RESET}")
        if self.failed > 0:
            print(f"{Colors.RED}Failed: {self.failed}{Colors.RESET}")
            return False
        else:
            print(f"{Colors.BOLD}{Colors.GREEN}ALL VERIFICATION CHECKS PASSED (100% SUCCESS){Colors.RESET}\n")
            return True

if __name__ == "__main__":
    verifier = GuestExperienceVerifier(WORKSPACE_ROOT)
    success = verifier.run_all()
    sys.exit(0 if success else 1)
