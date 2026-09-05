"""
Automated Functional & Working Principles Verification Test Suite
ShipGuard AI Release Gate SaaS Engine

Tests:
1. /api/v1/gate-check (Health check, payload validation, local scan, blocked status)
2. /api/v1/badge (SVG generation, status badges, XSS escaping, parameter validation)
3. /api/v1/proxy (SSRF matrix: loopbacks, metadata, RFC1918, port restrictions, non-http protocols)
4. /api/v1/stripe-webhook (HMAC-SHA256 signature verification, replay tolerance, event dispatch)
"""

import sys
import json
import time
import hmac
import hashlib
import urllib.request
import urllib.error
import urllib.parse
from datetime import datetime

if sys.platform == "win32":
    try:
        sys.stdout.reconfigure(encoding='utf-8')
        sys.stderr.reconfigure(encoding='utf-8')
    except Exception:
        pass

import os

BASE_URL = os.environ.get("TEST_BASE_URL", "http://127.0.0.1:3000")
STRIPE_SECRET = "whsec_test_secret_12345"

class TestResult:
    def __init__(self, category, test_name, passed, status_code, details, error=None):
        self.category = category
        self.test_name = test_name
        self.passed = passed
        self.status_code = status_code
        self.details = details
        self.error = error

results = []

def make_request(method, path, body=None, headers=None):
    url = f"{BASE_URL}{path}"
    req_headers = headers.copy() if headers else {}
    req_headers.setdefault("x-forwarded-for", f"198.51.100.{len(results) % 250 + 1}")
    data = None
    
    if body is not None:
        if isinstance(body, (dict, list)):
            data = json.dumps(body).encode("utf-8")
            if "Content-Type" not in req_headers:
                req_headers["Content-Type"] = "application/json"
        elif isinstance(body, str):
            data = body.encode("utf-8")
        elif isinstance(body, bytes):
            data = body

    req = urllib.request.Request(url, data=data, headers=req_headers, method=method)
    
    try:
        with urllib.request.urlopen(req, timeout=10) as response:
            resp_body = response.read().decode("utf-8", errors="replace")
            # Normalize headers to lowercase keys for reliable cross-platform assertions
            resp_headers = {k.lower(): v for k, v in dict(response.headers).items()}
            return response.status, resp_headers, resp_body
    except urllib.error.HTTPError as e:
        resp_body = e.read().decode("utf-8", errors="replace")
        resp_headers = {k.lower(): v for k, v in dict(e.headers).items()}
        return e.code, resp_headers, resp_body
    except Exception as e:
        return 0, {}, str(e)


def record(category, name, passed, status, details, error=None):
    res = TestResult(category, name, passed, status, details, error)
    results.append(res)
    icon = "✅ PASS" if passed else "❌ FAIL"
    print(f"[{category}] {icon} | {name} (HTTP {status})")
    if details:
        preview = details if len(details) < 140 else details[:137] + "..."
        print(f"      Details: {preview}")
    if error:
        print(f"      Error: {error}")


def test_gate_check():
    print("\n" + "="*70)
    print(" 1. FUNCTIONAL AUDIT: /api/v1/gate-check")
    print("="*70)

    # 1.1 GET Service Discovery
    status, headers, body = make_request("GET", "/api/v1/gate-check")
    passed = status == 200 and "ShipGuard 3.0" in body
    record("GATE-CHECK", "GET Service Discovery", passed, status, body)

    # 1.2 POST Missing Body
    status, headers, body = make_request("POST", "/api/v1/gate-check", body="")
    passed = status == 400 and ("missing or malformed" in body or "Validation Error" in body)
    record("GATE-CHECK", "Reject Empty POST Body (400)", passed, status, body)

    # 1.3 POST Empty Object {}
    status, headers, body = make_request("POST", "/api/v1/gate-check", body={})
    passed = status == 400 and "repoUrl" in body
    record("GATE-CHECK", "Reject Payload Missing repoUrl/targetUrl (400)", passed, status, body)

    # 1.4 POST Invalid Repository URL
    payload = {"repoUrl": "invalid-repo-without-domain"}
    status, headers, body = make_request("POST", "/api/v1/gate-check", body=payload)
    passed = status == 400 and "neither a valid GitHub repository" in body
    record("GATE-CHECK", "Reject Malformed Repo URL (400)", passed, status, body)

    # 1.4b POST Reject 'newday' Bypass Keyword (Must be 400, not allowed as 'local')
    payload = {"repoUrl": "newday"}
    status, headers, body = make_request("POST", "/api/v1/gate-check", body=payload)
    passed = status == 400 and "neither a valid GitHub repository" in body
    record("GATE-CHECK", "Reject 'newday' Bypass Keyword (400)", passed, status, body)

    # 1.5 POST Valid Local Workspace Scan ("local")
    payload = {"repoUrl": "local"}
    status, headers, body = make_request("POST", "/api/v1/gate-check", body=payload)
    try:
        data = json.loads(body)
        has_gate_status = "gateStatus" in data
        has_metrics = "metrics" in data and "score" in data["metrics"]
        has_findings = "findings" in data and isinstance(data["findings"], list)
        passed = (status in (200, 422)) and has_gate_status and has_metrics and has_findings
        details = f"gateStatus={data.get('gateStatus')}, score={data.get('readinessScore')}%, findings={len(data.get('findings', []))}, blockers={data.get('metrics', {}).get('criticalCount')}"
    except Exception as e:
        passed = False
        details = body
    record("GATE-CHECK", "Execute Static Scan for 'local' (200/422)", passed, status, details)

    # 1.6 Webhook alert parameter validation
    payload = {"repoUrl": "local", "slackWebhookUrl": "http://insecure-slack.com"}
    status, headers, body = make_request("POST", "/api/v1/gate-check", body=payload)
    passed = status == 400 and "slackWebhookUrl must use HTTPS" in body
    record("GATE-CHECK", "Enforce HTTPS on Notification Webhooks (400)", passed, status, body)


def test_badge_generator():
    print("\n" + "="*70)
    print(" 2. FUNCTIONAL AUDIT: /api/v1/badge (Dynamic Shield Generator)")
    print("="*70)

    # 2.1 Standard PASSED Badge
    status, headers, body = make_request("GET", "/api/v1/badge?status=PASSED&score=98&label=ShipGuard")
    passed = status == 200 and "<svg" in body and "#10B981" in body and "PASSED 98%" in body and "ShipGuard" in body
    is_svg_content_type = "image/svg+xml" in headers.get("content-type", "")
    record("BADGE", "Generate Emerald PASSED Badge (98%)", passed and is_svg_content_type, status, f"SVG size: {len(body)}b, Content-Type: {headers.get('content-type')}")

    # 2.2 WARNING Badge
    status, headers, body = make_request("GET", "/api/v1/badge?status=WARNING&score=65&label=ReleaseGate")
    passed = status == 200 and "<svg" in body and "#F59E0B" in body and "WARNING 65%" in body
    record("BADGE", "Generate Amber WARNING Badge (65%)", passed, status, f"Color: #F59E0B, Text: WARNING 65%")

    # 2.3 FAILED Badge
    status, headers, body = make_request("GET", "/api/v1/badge?status=FAILED&score=25")
    passed = status == 200 and "<svg" in body and "#EF4444" in body and "FAILED (25%)" in body
    record("BADGE", "Generate Red FAILED Badge (25%)", passed, status, f"Color: #EF4444, Text: FAILED (25%)")

    # 2.4 Parameter Validation (Invalid Status)
    status, headers, body = make_request("GET", "/api/v1/badge?status=SUPER_CLEAN")
    passed = status == 400 and "status must be PASSED, WARNING, or FAILED" in body
    record("BADGE", "Reject Invalid Status Enum (400)", passed, status, body)

    # 2.5 Security: XSS & XML Injection Sanitization
    xss_label = "<script>alert('XSS')</script>"
    quoted_label = urllib.parse.quote(xss_label)
    status, headers, body = make_request("GET", f"/api/v1/badge?label={quoted_label}&status=PASSED")
    has_raw_script = "<script>" in body
    has_escaped = "&lt;script&gt;" in body
    csp_header = headers.get("content-security-policy", "")
    passed = status == 200 and not has_raw_script and has_escaped and "default-src" in csp_header
    record("BADGE", "Neutralize XSS in SVG Label + CSP Enforcement", passed, status, f"Escaped correctly: {has_escaped}, Raw script found: {has_raw_script}, CSP: {csp_header[:40]}...")


def test_ssrf_proxy():
    print("\n" + "="*70)
    print(" 3. FUNCTIONAL AUDIT: /api/v1/proxy (SSRF & Internal Probing Defense)")
    print("="*70)

    ssrf_targets = [
        ("127.0.0.1 Loopback IPv4", "http://127.0.0.1:80", 403, ["prohibited", "loopback", "internal host"]),
        ("localhost Hostname", "http://localhost:3000", 403, ["internal host", "prohibited"]),
        ("AWS/GCP Link-Local Metadata (169.254.169.254)", "http://169.254.169.254/latest/meta-data/", 403, ["prohibited", "private or loopback"]),
        ("RFC 1918 Class A (10.0.0.1)", "http://10.0.0.1/status", 403, ["prohibited", "private or loopback"]),
        ("RFC 1918 Class B (172.16.0.1)", "http://172.16.0.1/admin", 403, ["prohibited", "private or loopback"]),
        ("RFC 1918 Class C (192.168.1.1)", "http://192.168.1.1/", 403, ["prohibited", "private or loopback"]),
        ("Google Internal Metadata Hostname", "http://metadata.google.internal/computeMetadata/v1/", 403, ["internal host", "prohibited"]),
        ("Internal Database Port Probing (PostgreSQL 5432)", "http://example.com:5432", 403, ["restricted to prevent internal service probing"]),
        ("Dangerous SSH Port Probing (Port 22)", "http://example.com:22", 403, ["restricted to prevent internal service probing"]),
        ("Dangerous Redis Port Probing (Port 6379)", "http://example.com:6379", 403, ["restricted to prevent internal service probing"]),
        ("Embedded User Credentials", "http://admin:password@example.com", 400, ["embedded user credentials"]),
        ("Non-HTTP Protocol Scheme (ftp://)", "ftp://ftp.secure-bank.com", 400, ["valid http or https", "protocol"]),
        ("Missing url Parameter", None, 400, ["url parameter is required"]),
    ]

    for title, target_url, expected_code, expected_keywords in ssrf_targets:
        if target_url is None:
            path = "/api/v1/proxy"
        else:
            path = f"/api/v1/proxy?url={urllib.parse.quote(target_url)}"
        
        status, headers, body = make_request("GET", path)
        body_lower = body.lower()
        keyword_match = any(k in body_lower for k in expected_keywords)
        passed = (status == expected_code) and keyword_match
        record("PROXY-SSRF", f"Block {title}", passed, status, body)


def test_stripe_webhook():
    print("\n" + "="*70)
    print(" 4. FUNCTIONAL AUDIT: /api/v1/stripe-webhook (HMAC & Event Processing)")
    print("="*70)

    sample_event = {
        "id": "evt_test_1234567890",
        "object": "event",
        "api_version": "2023-10-16",
        "created": int(time.time()),
        "type": "checkout.session.completed",
        "data": {
            "object": {
                "id": "cs_test_sample",
                "object": "checkout.session",
                "amount_total": 9900,
                "customer_details": {
                    "email": "customer@enterprise.com",
                    "name": "Enterprise Tester"
                },
                "payment_status": "paid"
            }
        }
    }
    raw_payload = json.dumps(sample_event)

    # 4.1 Missing Signature Header
    status, headers, body = make_request("POST", "/api/v1/stripe-webhook", body=raw_payload)
    passed = status == 400 and "Missing stripe-signature header" in body
    record("STRIPE", "Reject Missing Signature Header (400)", passed, status, body)

    # 4.2 Tampered Signature
    bad_header = f"t={int(time.time())},v1=0000000000000000000000000000000000000000000000000000000000000000"
    status, headers, body = make_request("POST", "/api/v1/stripe-webhook", body=raw_payload, headers={"stripe-signature": bad_header})
    passed = status == 400 and "Invalid Stripe signature" in body
    record("STRIPE", "Reject Tampered / Forged HMAC Signature (400)", passed, status, body)

    # 4.3 Expired Signature (> 300s old / Replay Attack)
    old_timestamp = int(time.time()) - 600 # 10 minutes ago
    signed_payload = f"{old_timestamp}.{raw_payload}"
    old_sig = hmac.new(STRIPE_SECRET.encode("utf-8"), signed_payload.encode("utf-8"), hashlib.sha256).hexdigest()
    expired_header = f"t={old_timestamp},v1={old_sig}"
    status, headers, body = make_request("POST", "/api/v1/stripe-webhook", body=raw_payload, headers={"stripe-signature": expired_header})
    passed = status == 400 and "replay protection" in body
    record("STRIPE", "Reject Expired Signature (>300s Replay Attack) (400)", passed, status, body)

    # 4.4 Authentic HMAC Signature & checkout.session.completed Event
    current_time = int(time.time())
    valid_signed_payload = f"{current_time}.{raw_payload}"
    valid_sig = hmac.new(STRIPE_SECRET.encode("utf-8"), valid_signed_payload.encode("utf-8"), hashlib.sha256).hexdigest()
    valid_header = f"t={current_time},v1={valid_sig}"
    status, headers, body = make_request("POST", "/api/v1/stripe-webhook", body=raw_payload, headers={"stripe-signature": valid_header})
    passed = status == 200 and "received" in body and "evt_test_1234567890" in body
    record("STRIPE", "Accept Valid HMAC Signature & checkout.session.completed (200)", passed, status, body)

    # 4.5 Authentic HMAC Signature for subscription.created Event
    sub_event = {
        "id": "evt_sub_active_987",
        "object": "event",
        "created": current_time,
        "type": "customer.subscription.created",
        "data": {
            "object": {
                "id": "sub_test_core",
                "customer": "cus_test_abc",
                "status": "active"
            }
        }
    }
    raw_sub = json.dumps(sub_event)
    signed_sub = f"{current_time}.{raw_sub}"
    sub_sig = hmac.new(STRIPE_SECRET.encode("utf-8"), signed_sub.encode("utf-8"), hashlib.sha256).hexdigest()
    sub_header = f"t={current_time},v1={sub_sig}"
    status, headers, body = make_request("POST", "/api/v1/stripe-webhook", body=raw_sub, headers={"stripe-signature": sub_header})
    passed = status == 200 and "received" in body and "evt_sub_active_987" in body
    record("STRIPE", "Process customer.subscription.created Event (200)", passed, status, body)

    # 4.6 Signed but Malformed JSON Body
    malformed_body = "{invalid_json_format:::"
    signed_bad_json = f"{current_time}.{malformed_body}"
    bad_json_sig = hmac.new(STRIPE_SECRET.encode("utf-8"), signed_bad_json.encode("utf-8"), hashlib.sha256).hexdigest()
    bad_json_header = f"t={current_time},v1={bad_json_sig}"
    status, headers, body = make_request("POST", "/api/v1/stripe-webhook", body=malformed_body, headers={"stripe-signature": bad_json_header})
    passed = status == 400 and "Malformed JSON payload" in body
    record("STRIPE", "Reject Signed Malformed JSON (400)", passed, status, body)


def test_extended_ast_rules():
    print("\n" + "="*70)
    print(" 5. AST & STATIC SCAN VERIFICATION: Option A Security & Option B Frontend Rules")
    print("="*70)

    import subprocess

    runner_script = """
import { runStaticCodeScan } from '../lib/scanner-engine';

const testCases = [
  {
    name: 'SEC-20',
    files: [{ path: 'package.json', content: JSON.stringify({ dependencies: { 'unpinned-pkg': 'latest' } }, null, 2) }]
  },
  {
    name: 'SEC-21',
    files: [{ path: 'src/services/auth.ts', content: 'export function auth() { console.log(user_token); }' }]
  },
  {
    name: 'SEC-22',
    files: [{ path: 'components/ChatWidget.tsx', content: '"use client";\\nimport OpenAI from "openai";\\nexport function Chat() { return null; }' }]
  },
  {
    name: 'UI-26',
    files: [{ path: 'components/SearchBar.tsx', content: 'export function Search() { return <input className="w-full outline-none" />; }' }]
  },
  {
    name: 'UI-27',
    files: [{ path: 'components/HeroBanner.tsx', content: 'export function Hero() { return <img src="hero.png" alt="hero" />; }' }]
  },
  {
    name: 'IGNORE',
    files: [
      { path: '.shipguardignore', content: 'SEC-20\\nSEC-21\\nSEC-22\\nUI-26\\nUI-27' },
      { path: 'package.json', content: JSON.stringify({ dependencies: { 'unpinned-pkg': 'latest' } }, null, 2) },
      { path: 'src/services/auth.ts', content: 'export function auth() { console.log(user_token); }' },
      { path: 'components/ChatWidget.tsx', content: '"use client";\\nimport OpenAI from "openai";\\nexport function Chat() { return null; }' },
      { path: 'components/SearchBar.tsx', content: 'export function Search() { return <input className="w-full outline-none" />; }' },
      { path: 'components/HeroBanner.tsx', content: 'export function Hero() { return <img src="hero.png" alt="hero" />; }' }
    ]
  }
];

const results = testCases.map(tc => {
  const scan = runStaticCodeScan(tc.files);
  return {
    name: tc.name,
    score: scan.score,
    gateStatus: scan.gateStatus,
    findings: scan.findings.map(f => ({ ruleId: f.ruleId, title: f.title, file: f.filePath, lineRange: f.lineRange, severity: f.severity }))
  };
});

console.log(JSON.stringify(results));
"""
    import os
    temp_runner_path = os.path.join(os.path.dirname(__file__), "_temp_ast_runner.ts")
    try:
        with open(temp_runner_path, "w", encoding="utf-8") as f:
            f.write(runner_script)

        cmd = ['npx.cmd' if sys.platform == 'win32' else 'npx', 'tsx', temp_runner_path]
        p = subprocess.run(cmd, capture_output=True, encoding='utf-8', errors='replace', timeout=30)
        if p.returncode != 0:
            record("AST-ENGINE", "Execute AST Verification Harness", False, 500, f"Error: {p.stderr}")
            return
        data = json.loads(p.stdout)
        results_by_name = {item['name']: item for item in data}

        # 5.1 Test detection of package.json with wildcard "latest" (triggers SEC-20)
        sec20_res = results_by_name.get('SEC-20', {})
        findings20 = sec20_res.get('findings', [])
        has_sec20 = any(f.get('ruleId') == 20 for f in findings20)
        title20 = next((f.get('title') for f in findings20 if f.get('ruleId') == 20), 'None')
        record("AST-RULES", "Detect SEC-20: Wildcard Dependency ('latest' in package.json)", has_sec20, 200, f"Found rule 20: {title20}")

        # 5.2 Test detection of console.log(user_token) (triggers SEC-21)
        sec21_res = results_by_name.get('SEC-21', {})
        findings21 = sec21_res.get('findings', [])
        has_sec21 = any(f.get('ruleId') == 21 for f in findings21)
        title21 = next((f.get('title') for f in findings21 if f.get('ruleId') == 21), 'None')
        record("AST-RULES", "Detect SEC-21: PII & Token Leakage (console.log(user_token))", has_sec21, 200, f"Found rule 21: {title21}")

        # 5.3 Test detection of "use client" with import OpenAI from 'openai' (triggers SEC-22)
        sec22_res = results_by_name.get('SEC-22', {})
        findings22 = sec22_res.get('findings', [])
        has_sec22 = any(f.get('ruleId') == 22 for f in findings22)
        title22 = next((f.get('title') for f in findings22 if f.get('ruleId') == 22), 'None')
        record("AST-RULES", "Detect SEC-22: Client-Side LLM SDK Import ('use client')", has_sec22, 200, f"Found rule 22: {title22}")

        # 5.4 Test detection of <input className="outline-none" /> without focus ring (triggers UI-26)
        ui26_res = results_by_name.get('UI-26', {})
        findings26 = ui26_res.get('findings', [])
        has_ui26 = any(f.get('ruleId') in (26, 1026) for f in findings26)
        title26 = next((f.get('title') for f in findings26 if f.get('ruleId') in (26, 1026)), 'None')
        record("AST-RULES", "Detect UI-26: WCAG 2.1 AA Keyboard Focus Ring & Accessible Label", has_ui26, 200, f"Found rule 26/1026: {title26}")

        # 5.5 Test detection of <img src="hero.png" /> in Next.js component (triggers UI-27)
        ui27_res = results_by_name.get('UI-27', {})
        findings27 = ui27_res.get('findings', [])
        has_ui27 = any(f.get('ruleId') in (27, 1027) for f in findings27)
        title27 = next((f.get('title') for f in findings27 if f.get('ruleId') in (27, 1027)), 'None')
        record("AST-RULES", "Detect UI-27: Core Web Vitals & Next.js Image Optimization", has_ui27, 200, f"Found rule 27/1027: {title27}")

        # 5.6 Test suppression of new rules via .shipguardignore
        ignore_res = results_by_name.get('IGNORE', {})
        findings_ignore = ignore_res.get('findings', [])
        target_rule_ids = {20, 21, 22, 26, 27, 1026, 1027}
        unsuppressed = [f for f in findings_ignore if f.get('ruleId') in target_rule_ids]
        is_suppressed = len(unsuppressed) == 0
        record("AST-RULES", "Suppress SEC-20, SEC-21, SEC-22, UI-26, UI-27 via .shipguardignore", is_suppressed, 200, f"Unsuppressed count: {len(unsuppressed)}")

    except Exception as e:
        record("AST-ENGINE", "Execute AST Verification Harness", False, 500, str(e), error=str(e))
    finally:
        if os.path.exists(temp_runner_path):
            try:
                os.remove(temp_runner_path)
            except Exception:
                pass


def main():
    print("="*70)
    print(" 🚀 SHIPGUARD AI RELEASE GATE - FUNCTIONAL AUDIT TEST SUITE")
    print(f" Target Server: {BASE_URL}")
    print(f" Timestamp:     {datetime.now().isoformat()}")
    print("="*70)

    start_time = time.time()
    test_gate_check()
    test_badge_generator()
    test_ssrf_proxy()
    test_stripe_webhook()
    test_extended_ast_rules()
    elapsed = time.time() - start_time

    total = len(results)
    passed = sum(1 for r in results if r.passed)
    failed = total - passed

    print("\n" + "="*70)
    print(" 📊 VERIFICATION SUITE EXECUTION SUMMARY")
    print("="*70)
    print(f" Total Tests Executed: {total}")
    print(f" ✅ Passed:             {passed}")
    print(f" ❌ Failed:             {failed}")
    print(f" ⏱️  Duration:           {elapsed:.2f}s")
    print(f" 🎯 Success Rate:       {(passed/total)*100:.1f}%")
    print("="*70)

    if failed > 0:
        print("\n❌ FAILED TESTS SUMMARY:")
        for r in results:
            if not r.passed:
                print(f" - [{r.category}] {r.test_name} (HTTP {r.status_code}) -> {r.details}")
        sys.exit(1)
    else:
        print("\n✨ ALL FUNCTIONAL AND WORKING PRINCIPLE TESTS PASSED PERFECTLY! ✨\n")
        sys.exit(0)


if __name__ == "__main__":
    main()
