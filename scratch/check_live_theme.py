import urllib.request
import re

url = "https://shipguard-saas.vercel.app"
req = urllib.request.Request(url, headers={"User-Agent": "Mozilla/5.0"})
html = urllib.request.urlopen(req).read().decode("utf-8")

print("1. HTML check:")
print(" - Scan Repository in HTML:", "Scan Repository" in html)
print(" - from-amber in HTML:", "from-amber" in html)
print(" - Dot icon in HTML:", "●" in html)

dot_indices = [m.start() for m in re.finditer(r'●|•', html)]
print("3. Dot occurrences count:", len(dot_indices))
for idx in dot_indices:
    snippet = html[max(0, idx-80):min(len(html), idx+80)]
    print(" - Snippet:", snippet.encode('ascii', errors='replace').decode('ascii'))

