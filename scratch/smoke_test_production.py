#!/usr/bin/env python3
"""
ShipGuard Production Smoke Test Suite
--------------------------------------
Verifies 8 core deployment readiness checks against a target URL:
  1. GET / (HTTP 200)
  2. GET /dashboard (HTTP 200)
  3. GET /checkout (HTTP 200)
  4. GET /privacy & GET /terms (HTTP 200)
  5. GET /robots.txt & GET /sitemap.xml (HTTP 200)
  6. GET /api/v1/badge?status=PASSED&score=98 (HTTP 200 + SVG Content-Type)
  7. POST /api/v1/gate-check with {"repoUrl": "local"} (HTTP 200 + valid JSON response)
  8. GET /api/v1/proxy?url=http://127.0.0.1 (HTTP 403 SSRF blocked)

Usage:
    python scratch/smoke_test_production.py [--url http://127.0.0.1:3000]
    python scratch/smoke_test_production.py --url https://shipguard-saas.vercel.app
"""

import sys
import os
import time
import json
import argparse
import urllib.request
import urllib.error
from typing import Dict, Any, Tuple, Optional

# Reconfigure stdout/stderr to UTF-8 on Windows terminals if supported
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

# ANSI color codes for rich terminal feedback
GREEN = "\033[92m"
RED = "\033[91m"
YELLOW = "\033[93m"
CYAN = "\033[96m"
BOLD = "\033[1m"
RESET = "\033[0m"

def make_request(
    url: str,
    method: str = "GET",
    headers: Optional[Dict[str, str]] = None,
    data: Optional[bytes] = None,
    timeout: int = 60
) -> Tuple[int, Dict[str, str], str, float]:
    """
    Executes an HTTP request using urllib and returns:
    (status_code, response_headers_dict, response_body_text, duration_seconds)
    """
    req_headers = {
        "User-Agent": "ShipGuard-Smoke-Test-Runner/1.0",
        "Accept": "*/*"
    }
    if headers:
        req_headers.update(headers)

    req = urllib.request.Request(url, data=data, headers=req_headers, method=method)
    start_time = time.time()
    try:
        with urllib.request.urlopen(req, timeout=timeout) as response:
            duration = time.time() - start_time
            status_code = response.status
            resp_headers = {k.lower(): v for k, v in response.getheaders()}
            body = response.read().decode("utf-8", errors="replace")
            return status_code, resp_headers, body, duration
    except urllib.error.HTTPError as e:
        duration = time.time() - start_time
        resp_headers = {k.lower(): v for k, v in e.headers.items()}
        body = e.read().decode("utf-8", errors="replace")
        return e.code, resp_headers, body, duration
    except Exception as e:
        duration = time.time() - start_time
        raise ConnectionError(f"Connection failed to {url}: {str(e)}") from e


def run_smoke_tests(base_url: str) -> bool:
    base_url = base_url.rstrip("/")
    print(f"\n{BOLD}{CYAN}==============================================================={RESET}")
    print(f"{BOLD}{CYAN}      [SHIPGUARD] PRODUCTION SMOKE TEST RUNNER                {RESET}")
    print(f"{BOLD}{CYAN}==============================================================={RESET}")
    print(f"{BOLD}Target Base URL:{RESET} {base_url}")
    print(f"{BOLD}Timestamp:{RESET}       {time.strftime('%Y-%m-%d %H:%M:%S')}")
    print(f"{CYAN}---------------------------------------------------------------{RESET}\n")

    results = []

    # Check 1: GET /
    print(f"{BOLD}[Check 1/8]{RESET} Testing Root Route: {CYAN}GET /{RESET} ...", end=" ", flush=True)
    try:
        code, headers, body, dur = make_request(f"{base_url}/")
        if code == 200:
            print(f"{GREEN}PASSED{RESET} (HTTP {code}, {dur:.2f}s)")
            results.append(("Check 1: GET /", True, f"HTTP {code} ({dur:.2f}s)"))
        else:
            print(f"{RED}FAILED{RESET} (HTTP {code} expected 200)")
            results.append(("Check 1: GET /", False, f"HTTP {code} (expected 200)"))
    except Exception as ex:
        print(f"{RED}ERROR{RESET} ({ex})")
        results.append(("Check 1: GET /", False, str(ex)))

    # Check 2: GET /dashboard
    print(f"{BOLD}[Check 2/8]{RESET} Testing Dashboard Route: {CYAN}GET /dashboard{RESET} ...", end=" ", flush=True)
    try:
        code, headers, body, dur = make_request(f"{base_url}/dashboard")
        if code == 200:
            print(f"{GREEN}PASSED{RESET} (HTTP {code}, {dur:.2f}s)")
            results.append(("Check 2: GET /dashboard", True, f"HTTP {code} ({dur:.2f}s)"))
        else:
            print(f"{RED}FAILED{RESET} (HTTP {code} expected 200)")
            results.append(("Check 2: GET /dashboard", False, f"HTTP {code} (expected 200)"))
    except Exception as ex:
        print(f"{RED}ERROR{RESET} ({ex})")
        results.append(("Check 2: GET /dashboard", False, str(ex)))

    # Check 3: GET /checkout
    print(f"{BOLD}[Check 3/8]{RESET} Testing Checkout Route: {CYAN}GET /checkout{RESET} ...", end=" ", flush=True)
    try:
        code, headers, body, dur = make_request(f"{base_url}/checkout")
        if code == 200:
            print(f"{GREEN}PASSED{RESET} (HTTP {code}, {dur:.2f}s)")
            results.append(("Check 3: GET /checkout", True, f"HTTP {code} ({dur:.2f}s)"))
        else:
            print(f"{RED}FAILED{RESET} (HTTP {code} expected 200)")
            results.append(("Check 3: GET /checkout", False, f"HTTP {code} (expected 200)"))
    except Exception as ex:
        print(f"{RED}ERROR{RESET} ({ex})")
        results.append(("Check 3: GET /checkout", False, str(ex)))

    # Check 4: GET /privacy & GET /terms
    print(f"{BOLD}[Check 4/8]{RESET} Testing Legal Pages: {CYAN}GET /privacy{RESET} & {CYAN}GET /terms{RESET} ...", end=" ", flush=True)
    try:
        code_p, _, _, dur_p = make_request(f"{base_url}/privacy")
        code_t, _, _, dur_t = make_request(f"{base_url}/terms")
        if code_p == 200 and code_t == 200:
            print(f"{GREEN}PASSED{RESET} (/privacy: HTTP {code_p}, /terms: HTTP {code_t})")
            results.append(("Check 4: Legal (/privacy & /terms)", True, f"HTTP 200 both ({dur_p + dur_t:.2f}s)"))
        else:
            print(f"{RED}FAILED{RESET} (/privacy: HTTP {code_p}, /terms: HTTP {code_t})")
            results.append(("Check 4: Legal (/privacy & /terms)", False, f"privacy={code_p}, terms={code_t}"))
    except Exception as ex:
        print(f"{RED}ERROR{RESET} ({ex})")
        results.append(("Check 4: Legal (/privacy & /terms)", False, str(ex)))

    # Check 5: GET /robots.txt & GET /sitemap.xml
    print(f"{BOLD}[Check 5/8]{RESET} Testing SEO Metadata: {CYAN}GET /robots.txt{RESET} & {CYAN}GET /sitemap.xml{RESET} ...", end=" ", flush=True)
    try:
        code_r, _, body_r, dur_r = make_request(f"{base_url}/robots.txt")
        code_s, _, body_s, dur_s = make_request(f"{base_url}/sitemap.xml")
        r_ok = code_r == 200 and ("User-agent" in body_r or "user-agent" in body_r.lower())
        s_ok = code_s == 200 and ("<urlset" in body_s or "<url" in body_s)
        if r_ok and s_ok:
            print(f"{GREEN}PASSED{RESET} (robots.txt: HTTP {code_r}, sitemap.xml: HTTP {code_s})")
            results.append(("Check 5: SEO (robots.txt & sitemap.xml)", True, f"HTTP 200 both ({dur_r + dur_s:.2f}s)"))
        else:
            print(f"{RED}FAILED{RESET} (robots.txt={code_r}, sitemap.xml={code_s})")
            results.append(("Check 5: SEO (robots.txt & sitemap.xml)", False, f"robots={code_r}, sitemap={code_s}"))
    except Exception as ex:
        print(f"{RED}ERROR{RESET} ({ex})")
        results.append(("Check 5: SEO (robots.txt & sitemap.xml)", False, str(ex)))

    # Check 6: GET /api/v1/badge?status=PASSED&score=98
    print(f"{BOLD}[Check 6/8]{RESET} Testing Dynamic SVG Shield Badge: {CYAN}GET /api/v1/badge{RESET} ...", end=" ", flush=True)
    try:
        badge_url = f"{base_url}/api/v1/badge?status=PASSED&score=98"
        code, headers, body, dur = make_request(badge_url)
        content_type = headers.get("content-type", "")
        has_svg_type = "image/svg+xml" in content_type or "svg" in content_type
        has_svg_tag = "<svg" in body and "</svg>" in body

        if code == 200 and has_svg_type and has_svg_tag:
            print(f"{GREEN}PASSED{RESET} (HTTP 200, Content-Type: {content_type}, {dur:.2f}s)")
            results.append(("Check 6: SVG Badge Generator", True, f"HTTP 200, SVG OK ({dur:.2f}s)"))
        else:
            fail_reason = []
            if code != 200: fail_reason.append(f"HTTP {code}")
            if not has_svg_type: fail_reason.append(f"Bad content-type: {content_type}")
            if not has_svg_tag: fail_reason.append("Missing <svg> tags")
            print(f"{RED}FAILED{RESET} ({', '.join(fail_reason)})")
            results.append(("Check 6: SVG Badge Generator", False, ', '.join(fail_reason)))
    except Exception as ex:
        print(f"{RED}ERROR{RESET} ({ex})")
        results.append(("Check 6: SVG Badge Generator", False, str(ex)))

    # Check 7: POST /api/v1/gate-check with {"repoUrl": "local"}
    print(f"{BOLD}[Check 7/8]{RESET} Testing Release Gate Check API: {CYAN}POST /api/v1/gate-check{RESET} ...", end=" ", flush=True)
    try:
        gate_url = f"{base_url}/api/v1/gate-check"
        payload = json.dumps({"repoUrl": "https://github.com/octocat/Hello-World"}).encode("utf-8")
        code, headers, body, dur = make_request(
            gate_url,
            method="POST",
            headers={"Content-Type": "application/json"},
            data=payload,
            timeout=60
        )
        try:
            parsed_json = json.loads(body)
            has_status = "gateStatus" in parsed_json or "status" in parsed_json
        except Exception:
            parsed_json = None
            has_status = False

        if code == 200 and has_status:
            gate_status = parsed_json.get("gateStatus", "N/A")
            score = parsed_json.get("readinessScore", parsed_json.get("metrics", {}).get("score", "N/A"))
            print(f"{GREEN}PASSED{RESET} (HTTP 200, Status: {gate_status}, Score: {score}, {dur:.2f}s)")
            results.append(("Check 7: Gate Check API", True, f"HTTP 200, Status={gate_status}, Score={score} ({dur:.2f}s)"))
        else:
            reason = f"HTTP {code}" if code != 200 else "Invalid or missing JSON fields"
            print(f"{RED}FAILED{RESET} ({reason})")
            results.append(("Check 7: Gate Check API", False, reason))
    except Exception as ex:
        print(f"{RED}ERROR{RESET} ({ex})")
        results.append(("Check 7: Gate Check API", False, str(ex)))

    # Check 8: GET /api/v1/proxy?url=http://127.0.0.1 (HTTP 403 SSRF blocked)
    print(f"{BOLD}[Check 8/8]{RESET} Testing SSRF Security Boundary: {CYAN}GET /api/v1/proxy?url=http://127.0.0.1{RESET} ...", end=" ", flush=True)
    try:
        proxy_url = f"{base_url}/api/v1/proxy?url=http://127.0.0.1"
        code, headers, body, dur = make_request(proxy_url)
        if code == 403:
            print(f"{GREEN}PASSED{RESET} (HTTP 403 SSRF correctly blocked, {dur:.2f}s)")
            results.append(("Check 8: SSRF Protection", True, f"HTTP 403 Blocked ({dur:.2f}s)"))
        else:
            print(f"{RED}FAILED{RESET} (Expected HTTP 403, got HTTP {code})")
            results.append(("Check 8: SSRF Protection", False, f"Expected HTTP 403, got {code}"))
    except Exception as ex:
        print(f"{RED}ERROR{RESET} ({ex})")
        results.append(("Check 8: SSRF Protection", False, str(ex)))

    # Summary Table
    print(f"\n{BOLD}{CYAN}==============================================================={RESET}")
    print(f"{BOLD}{CYAN}                   SMOKE TEST RESULTS SUMMARY                 {RESET}")
    print(f"{BOLD}{CYAN}==============================================================={RESET}")
    total_checks = len(results)
    passed_checks = sum(1 for _, ok, _ in results if ok)
    failed_checks = total_checks - passed_checks

    for name, ok, detail in results:
        status_badge = f"{GREEN}[PASS]{RESET}" if ok else f"{RED}[FAIL]{RESET}"
        print(f" {status_badge} {name:<40} {detail}")

    print(f"{CYAN}---------------------------------------------------------------{RESET}")
    print(f"Total: {total_checks} | Passed: {GREEN}{passed_checks}{RESET} | Failed: {RED if failed_checks > 0 else GREEN}{failed_checks}{RESET}")

    if failed_checks == 0:
        print(f"\n{GREEN}{BOLD}[SUCCESS] ALL PRODUCTION SMOKE TESTS PASSED CLEANLY! Ready for launch.{RESET}\n")
        return True
    else:
        print(f"\n{RED}{BOLD}[FAILURE] {failed_checks} SMOKE TEST(S) FAILED. Please inspect before deploying.{RESET}\n")
        return False


def main():
    parser = argparse.ArgumentParser(description="ShipGuard Production Smoke Test Suite")
    parser.add_argument(
        "--url",
        type=str,
        default="http://127.0.0.1:3000",
        help="Base URL of deployed or local application (default: http://127.0.0.1:3000)"
    )
    args = parser.parse_args()

    success = run_smoke_tests(args.url)
    sys.exit(0 if success else 1)


if __name__ == "__main__":
    main()
