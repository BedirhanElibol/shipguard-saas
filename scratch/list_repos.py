import urllib.request, json, ssl

token = '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'
ctx = ssl.create_default_context()

req = urllib.request.Request('https://api.github.com/user', headers={
    'Authorization': f'Bearer {token}',
    'User-Agent': 'ShipGuard-CLI',
    'Accept': 'application/vnd.github.v3+json'
})

try:
    with urllib.request.urlopen(req, context=ctx) as resp:
        user_data = json.loads(resp.read().decode())
        print('LOGGED IN AS:', user_data.get('login'))
        print('OAUTH SCOPES:', resp.headers.get('X-OAuth-Scopes'))
except Exception as e:
    print('USER ERROR:', e)

req_repos = urllib.request.Request('https://api.github.com/user/repos?type=all&per_page=100', headers={
    'Authorization': f'Bearer {token}',
    'User-Agent': 'ShipGuard-CLI',
    'Accept': 'application/vnd.github.v3+json'
})

try:
    with urllib.request.urlopen(req_repos, context=ctx) as resp:
        repos = json.loads(resp.read().decode())
        print(f'TOTAL REPOSITORIES FOUND: {len(repos)}')
        for r in repos:
            print(f"NAME: {r['full_name']} | IS_PRIVATE: {r['private']} | OWNER: {r['owner']['login']}")
except Exception as e:
    print('REPOS ERROR:', e)
