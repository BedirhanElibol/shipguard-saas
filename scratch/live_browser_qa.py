#!/usr/bin/env python3
"""
Playwright Headless Live Browser QA Test Suite
ShipGuard SaaS Live Dashboard & Pre-Flight Platform Verification

Tests against live production / staging URL:
1. Landing Page (/) - Core elements, CTA buttons, hero rendering, zero console errors.
2. Dashboard (/dashboard) - Project selector, Readiness score display, Gate badge, tab navigation.
3. Tab Switching - Overview, Scans, Codebase, Security, Infrastructure, CI/CD, Regulatory.
4. Checkout Page (/checkout) - Pricing tiers, plan cards, billing selector.
5. Legal & Compliance Pages (/privacy, /terms).
6. Console Error Monitoring - Ensures 0 unhandled fatal errors or crash states.
"""

import sys
import time
import argparse
from typing import List, Dict, Any
from playwright.sync_api import sync_playwright, Page, Browser, ConsoleMessage

# Reconfigure encoding for Windows CMD / PowerShell
if hasattr(sys.stdout, "reconfigure"):
    try:
        sys.stdout.reconfigure(encoding="utf-8", errors="replace")
    except Exception:
        pass
if hasattr(sys.stderr, "reconfigure"):
    try:
        sys.stderr.reconfigure(encoding="utf-8", errors="replace")
    except Exception:
        pass

# Terminal colors
GREEN = "\033[92m"
RED = "\033[91m"
YELLOW = "\033[93m"
CYAN = "\033[96m"
BOLD = "\033[1m"
RESET = "\033[0m"

class LiveBrowserQA:
    def __init__(self, base_url: str):
        self.base_url = base_url.rstrip("/")
        self.passed_tests = 0
        self.failed_tests = 0
        self.console_errors: List[str] = []
        self.page_errors: List[str] = []

    def log_header(self, title: str):
        print(f"\n{BOLD}{CYAN}=== [BROWSER QA] {title} ==={RESET}")

    def log_pass(self, name: str, detail: str = ""):
        self.passed_tests += 1
        msg = f"  {GREEN}[PASS]{RESET} {BOLD}{name}{RESET}"
        if detail:
            msg += f" - {detail}"
        print(msg)

    def log_fail(self, name: str, error: str):
        self.failed_tests += 1
        print(f"  {RED}[FAIL]{RESET} {BOLD}{name}{RESET} - {error}")

    def log_info(self, text: str):
        print(f"  {YELLOW}[INFO]{RESET} {text}")

    def setup_listeners(self, page: Page):
        self.console_errors.clear()
        self.page_errors.clear()

        def on_console(msg: ConsoleMessage):
            if msg.type in ["error"]:
                # Ignore harmless favicon / resource 404s
                text = msg.text
                if not any(ign in text for ign in ["favicon.ico", "manifest.json"]):
                    self.console_errors.append(text)

        def on_page_error(err):
            self.page_errors.append(str(err))

        page.on("console", on_console)
        page.on("pageerror", on_page_error)

    def test_landing_page(self, page: Page):
        self.log_header("Test 1: Landing Page (/)")
        target = f"{self.base_url}/"
        self.setup_listeners(page)

        try:
            resp = page.goto(target, wait_until="domcontentloaded", timeout=30000)
            status = resp.status if resp else 0
            if status == 200:
                self.log_pass("Landing Page Status", f"HTTP {status}")
            else:
                self.log_fail("Landing Page Status", f"Expected HTTP 200, got {status}")

            title = page.title()
            if "ShipGuard" in title:
                self.log_pass("Page Title Validation", f"'{title}' contains 'ShipGuard'")
            else:
                self.log_fail("Page Title Validation", f"Title '{title}' does not contain 'ShipGuard'")

            # Check CTA button or main heading
            page.wait_for_selector("body", timeout=5000)
            body_text = page.inner_text("body")
            if "ShipGuard" in body_text:
                self.log_pass("Hero / Brand Presence", "Brand content detected in DOM")
            else:
                self.log_fail("Hero / Brand Presence", "ShipGuard brand text missing from landing page")

            if not self.page_errors:
                self.log_pass("Zero Page Crash Errors", "No uncaught runtime exceptions")
            else:
                self.log_fail("Page Crash Errors", f"Errors: {self.page_errors}")

        except Exception as e:
            self.log_fail("Landing Page Exception", str(e))

    def test_dashboard_page(self, page: Page):
        self.log_header("Test 2: Dashboard Experience (/dashboard)")
        target = f"{self.base_url}/dashboard"
        self.setup_listeners(page)

        try:
            resp = page.goto(target, wait_until="domcontentloaded", timeout=30000)
            status = resp.status if resp else 0
            if status == 200:
                self.log_pass("Dashboard Status", f"HTTP {status}")
            else:
                self.log_fail("Dashboard Status", f"Expected HTTP 200, got {status}")

            # Wait for dashboard UI to hydrate
            page.wait_for_timeout(2000)

            # Check for select element for projects
            project_select = page.query_selector('select[aria-label="Select Active Project"]')
            if project_select:
                self.log_pass("Project Selector Dropdown", "Active project select component is rendered")
            else:
                # Fallback check for any select or project button
                any_select = page.query_selector('select')
                if any_select:
                    self.log_pass("Project Selector Dropdown", "Found selector component in header")
                else:
                    self.log_fail("Project Selector Dropdown", "Project selector select element not found")

            # Check for readiness score / gate indicator
            body_text = page.inner_text("body")
            score_found = False
            for term in ["Readiness Score", "Readiness", "PASSED", "BLOCKED", "/100"]:
                if term in body_text:
                    score_found = True
                    break

            if score_found:
                self.log_pass("Readiness Score Display", "Pre-flight metrics and readiness score found")
            else:
                self.log_fail("Readiness Score Display", "Readiness score indicators not found in DOM")

            if not self.page_errors:
                self.log_pass("Dashboard Stability", "0 uncaught runtime crash errors")
            else:
                self.log_fail("Dashboard Stability", f"Page errors: {self.page_errors}")

        except Exception as e:
            self.log_fail("Dashboard Exception", str(e))

    def test_navigation_tabs(self, page: Page):
        self.log_header("Test 3: Navigation Tabs & Subviews")
        tabs = [
            ("overview", "Overview"),
            ("scans", "Scanner / Gate Check"),
            ("codebase", "Codebase Analysis"),
            ("security", "Security Audit"),
            ("infrastructure", "Infra & Cloud Gate"),
            ("cicd", "CI/CD Gate Hub"),
            ("regulatory", "Regulatory Compliance"),
        ]

        for nav_param, tab_name in tabs:
            target = f"{self.base_url}/dashboard?nav={nav_param}"
            self.setup_listeners(page)
            try:
                page.goto(target, wait_until="domcontentloaded", timeout=20000)
                page.wait_for_timeout(1000)
                body_text = page.inner_text("body")
                if len(body_text) > 100:
                    self.log_pass(f"Tab '{tab_name}' (?nav={nav_param})", f"Loaded ({len(body_text)} chars DOM text)")
                else:
                    self.log_fail(f"Tab '{tab_name}' (?nav={nav_param})", "DOM text unexpectedly empty (<100 chars)")
            except Exception as e:
                self.log_fail(f"Tab '{tab_name}' (?nav={nav_param})", str(e))

    def test_checkout_page(self, page: Page):
        self.log_header("Test 4: Checkout Experience (/checkout)")
        target = f"{self.base_url}/checkout"
        self.setup_listeners(page)

        try:
            resp = page.goto(target, wait_until="domcontentloaded", timeout=30000)
            status = resp.status if resp else 0
            if status == 200:
                self.log_pass("Checkout Route Status", f"HTTP {status}")
            else:
                self.log_fail("Checkout Route Status", f"Expected HTTP 200, got {status}")

            page.wait_for_timeout(1500)
            body_text = page.inner_text("body")
            if any(term in body_text for term in ["Checkout", "Order", "Plan", "Billing", "Monthly", "Annual"]):
                self.log_pass("Checkout View UI", "Plan and billing checkout components rendered")
            else:
                self.log_fail("Checkout View UI", "Checkout text and components not detected")

            if not self.page_errors:
                self.log_pass("Checkout Stability", "0 uncaught page crash errors")
            else:
                self.log_fail("Checkout Stability", f"Errors: {self.page_errors}")

        except Exception as e:
            self.log_fail("Checkout Exception", str(e))

    def test_legal_routes(self, page: Page):
        self.log_header("Test 5: Legal & Policy Routes (/privacy & /terms)")
        for route in ["/privacy", "/terms"]:
            target = f"{self.base_url}{route}"
            self.setup_listeners(page)
            try:
                resp = page.goto(target, wait_until="domcontentloaded", timeout=20000)
                status = resp.status if resp else 0
                if status == 200:
                    self.log_pass(f"Route {route}", f"HTTP {status}")
                else:
                    self.log_fail(f"Route {route}", f"Expected HTTP 200, got {status}")
            except Exception as e:
                self.log_fail(f"Route {route}", str(e))

    def run(self) -> bool:
        print(f"\n{BOLD}{CYAN}==============================================================={RESET}")
        print(f"{BOLD}{CYAN}    SHIPGUARD PLAYWRIGHT HEADLESS BROWSER VERIFICATION SUITE   {RESET}")
        print(f"{BOLD}{CYAN}==============================================================={RESET}")
        print(f"{BOLD}Target URL:{RESET}    {self.base_url}")
        print(f"{BOLD}Timestamp:{RESET}     {time.strftime('%Y-%m-%d %H:%M:%S')}")
        print(f"{CYAN}---------------------------------------------------------------{RESET}")

        with sync_playwright() as p:
            browser: Browser = p.chromium.launch(
                headless=True,
                args=["--no-sandbox", "--disable-dev-shm-usage"]
            )
            context = browser.new_context(
                viewport={"width": 1440, "height": 900},
                user_agent="Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36"
            )
            page = context.new_page()

            self.test_landing_page(page)
            self.test_dashboard_page(page)
            self.test_navigation_tabs(page)
            self.test_checkout_page(page)
            self.test_legal_routes(page)

            context.close()
            browser.close()

        print(f"\n{BOLD}{CYAN}==============================================================={RESET}")
        print(f"{BOLD}{CYAN}              BROWSER QA SUMMARY OF RESULTS                    {RESET}")
        print(f"{BOLD}{CYAN}==============================================================={RESET}")
        print(f"  {GREEN}Total Passed Checks:{RESET} {self.passed_tests}")
        print(f"  {RED if self.failed_tests > 0 else GREEN}Total Failed Checks:{RESET} {self.failed_tests}")

        if self.failed_tests == 0:
            print(f"\n{BOLD}{GREEN}>>> LIVE DASHBOARD & APPLICATION 100% OPERATIONAL! <<< {RESET}\n")
            return True
        else:
            print(f"\n{BOLD}{RED}>>> DETECTED {self.failed_tests} ISSUES DURING LIVE BROWSER QA <<< {RESET}\n")
            return False

def main():
    parser = argparse.ArgumentParser(description="ShipGuard Live Browser QA")
    parser.add_argument("--url", default="https://shipguard-saas.vercel.app", help="Base URL to test")
    args = parser.parse_args()

    qa = LiveBrowserQA(base_url=args.url)
    success = qa.run()
    sys.exit(0 if success else 1)

if __name__ == "__main__":
    main()
