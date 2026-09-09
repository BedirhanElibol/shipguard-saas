import urllib.request, re
url = "https://shipguard-saas.vercel.app/dashboard"
req = urllib.request.Request(url, headers={"User-Agent": "Mozilla/5.0"})
html = urllib.request.urlopen(req).read().decode("utf-8")
scripts = re.findall(r'src="(/_next/static/chunks/[^"]+)"', html)
print(f"Total scripts found: {len(scripts)}")
for s in scripts:
    s_url = "https://shipguard-saas.vercel.app" + s
    try:
        content = urllib.request.urlopen(urllib.request.Request(s_url, headers={"User-Agent": "Mozilla/5.0"})).read().decode("utf-8", errors="ignore")
        if "v7_showcase_guest_mode_clean" in content:
            print(">>> ACTIVE ON VERCEL: v7_showcase_guest_mode_clean in", s)
        elif "v5_authentic_scanned_data_only" in content:
            print(">>> STILL OLD ON VERCEL: v5 in", s)
    except Exception as e:
        pass
