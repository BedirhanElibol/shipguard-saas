import urllib.request
import urllib.error
import json
import time
import sys

BASE_URL = "http://localhost:3000"

ROUTES = [
    {"path": "/", "name": "Landing Page / Root", "expected_status": [200], "method": "GET"},
    {"path": "/landing", "name": "Landing Secondary", "expected_status": [200], "method": "GET"},
    {"path": "/dashboard", "name": "Dashboard Main App", "expected_status": [200], "method": "GET"},
    {"path": "/checkout", "name": "Checkout Page", "expected_status": [200], "method": "GET"},
    {"path": "/privacy", "name": "Privacy Policy", "expected_status": [200], "method": "GET"},
    {"path": "/terms", "name": "Terms of Service", "expected_status": [200], "method": "GET"},
    {"path": "/robots.txt", "name": "Robots Metadata", "expected_status": [200], "method": "GET"},
    {"path": "/sitemap.xml", "name": "Sitemap XML", "expected_status": [200], "method": "GET"},
    {"path": "/manifest.webmanifest", "name": "PWA Webmanifest", "expected_status": [200], "method": "GET"},
    {"path": "/opengraph-image", "name": "Edge OG Image Generator", "expected_status": [200], "method": "GET"},
    {"path": "/_not-found", "name": "404 Not Found System Route", "expected_status": [200, 404], "method": "GET"},
    {"path": "/api/v1/badge?status=PASSED", "name": "Badge API (GET)", "expected_status": [200], "method": "GET"},
    {"path": "/api/v1/gate-check", "name": "Gate Check Service Discovery (GET)", "expected_status": [200], "method": "GET"},
    {"path": "/api/v1/gate-check", "name": "Gate Check Run (POST)", "expected_status": [200, 400, 422], "method": "POST", "body": {"repoUrl": "local"}},
    {"path": "/api/v1/github-proxy?repoUrl=vercel/next.js", "name": "GitHub Proxy API (GET)", "expected_status": [200, 400, 403], "method": "GET"},
    {"path": "/api/v1/proxy?url=http://127.0.0.1", "name": "SSRF Proxy Defense (GET)", "expected_status": [403], "method": "GET"},
    {"path": "/api/v1/stripe-webhook", "name": "Stripe Webhook Defense (POST)", "expected_status": [400], "method": "POST", "body": {}},
]

def audit():
    print("=" * 80)
    print("SHIPGUARD 17-ROUTE HEALTH, LATENCY & COMPILATION PERFORMANCE AUDIT")
    print(f"Target: {BASE_URL}")
    print("=" * 80)

    results = []
    total_latency = 0

    for route in ROUTES:
        url = f"{BASE_URL}{route['path']}"
        start = time.perf_counter()
        req_body = None
        headers = {"User-Agent": "ShipGuard-QA-Auditor/1.0"}

        if route.get("body") is not None:
            req_body = json.dumps(route["body"]).encode("utf-8")
            headers["Content-Type"] = "application/json"

        req = urllib.request.Request(url, data=req_body, headers=headers, method=route["method"])
        status = 0
        content_type = ""
        body_len = 0

        try:
            with urllib.request.urlopen(req, timeout=15) as resp:
                status = resp.status
                content_type = resp.headers.get("Content-Type", "")
                data = resp.read()
                body_len = len(data)
        except urllib.error.HTTPError as e:
            status = e.code
            content_type = e.headers.get("Content-Type", "")
            data = e.read()
            body_len = len(data)
        except Exception as ex:
            status = -1
            content_type = str(ex)

        elapsed = (time.perf_counter() - start) * 1000.0
        total_latency += elapsed
        passed = status in route["expected_status"]

        results.append({
            "name": route["name"],
            "path": route["path"],
            "method": route["method"],
            "status": status,
            "expected": route["expected_status"],
            "latency_ms": elapsed,
            "content_type": content_type,
            "size_bytes": body_len,
            "passed": passed
        })

        icon = "PASS" if passed else "FAIL"
        print(f"[{icon}] {route['method']} {route['path']:<45} | HTTP {status:<3} | {elapsed:>7.2f} ms | {body_len:>7} B | {content_type.split(';')[0]}")

    print("=" * 80)
    avg_latency = total_latency / len(results)
    pass_count = sum(1 for r in results if r["passed"])
    print(f"SUMMARY: {pass_count}/{len(results)} routes verified. Avg Latency: {avg_latency:.2f} ms. Total Latency: {total_latency:.2f} ms.")
    print("=" * 80)

if __name__ == "__main__":
    audit()
