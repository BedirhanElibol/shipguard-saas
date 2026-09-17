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
        if "Setup CI/CD Gate" in content:
            print(">>> ACTIVE ON VERCEL: 'Setup CI/CD Gate' found in", s)
        if "Dependencies (SCA)" in content:
            print(">>> ACTIVE ON VERCEL: 'Dependencies (SCA)' found in", s)
    except Exception as e:
        pass
