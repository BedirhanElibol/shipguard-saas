with open('data/workspaceFiles.ts', 'r', encoding='utf-8') as f:
    content = f.read()

# 1. Clean hardcoded secrets
content = content.replace('"sk_live_51M394x9281...EXPOSED"', 'process.env.STRIPE_SECRET_KEY')
content = content.replace('"sk-proj-9482103921...EXPOSED"', 'process.env.OPENAI_API_KEY')

# 2. Clean RLS policy
content = content.replace('USING (true)', 'USING (auth.uid() = user_id)')

# 3. Clean CORS wildcard
content = content.replace("origin: '*'", "origin: process.env.PRODUCTION_CLIENT_URL")
content = content.replace("Access-Control-Allow-Origin: *", "Access-Control-Allow-Origin: process.env.PRODUCTION_CLIENT_URL")

# 4. Clean silent catch
content = content.replace('catch (e) {}', 'catch (e) { console.error("Logged Context Error", e); }')
content = content.replace('catch {}', 'catch (e) { console.error("Logged Context Error", e); }')

# 5. Clean model pin
content = content.replace("'gpt-4o'", "'gpt-4o-2024-08-06'")

with open('data/workspaceFiles.ts', 'w', encoding='utf-8') as f:
    f.write(content)

print("data/workspaceFiles.ts cleaned successfully!")
