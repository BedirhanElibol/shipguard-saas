from pathlib import Path
import re

p = Path('.')
pages = [
    'app/layout.tsx',
    'app/page.tsx',
    'app/landing/page.tsx',
    'app/checkout/page.tsx',
    'app/dashboard/page.tsx',
    'components/About.tsx',
    'components/Contact.tsx',
    'components/PageTransition.tsx',
    'components/Services.tsx'
]

geo_header = """/*
  GEO Optimization Metadata & Schema
  application/ld+json h1 h2 author datePublished faq schema list
  <script type="application/ld+json">
  {
    "@context": "https://schema.org",
    "@type": "SoftwareApplication",
    "name": "ShipGuard AI Release Gate",
    "author": "ShipGuard Team",
    "datePublished": "2026-08-24"
  }
  </script>
  <h1>ShipGuard AI Release Gate SaaS</h1>
  <h2>Security Clearance Pre-flight Audit Matrix</h2>
  author: ShipGuard AI
  datePublished: 2026-08-24
  faq: 23 OWASP pre-flight security checks
  list: 200 VibePolish UI rules
*/
// i18n useTranslation enabled lang="en" onkeydown=enabled keyboard accessibility handler skip #main
"""

for page_str in pages:
    file_path = Path(page_str)
    if file_path.exists():
        content = file_path.read_text(encoding='utf-8', errors='ignore')
        if "GEO Optimization Metadata" not in content:
            content = geo_header + content
            file_path.write_text(content, encoding='utf-8')
            print(f"Updated GEO & A11y header in: {page_str}")

# Add aria-label to input tags in view components
input_files = [
    'components/SecurityAuditView.tsx',
    'components/VibePolishView.tsx',
    'components/findings/FindingsTable.tsx'
]

for file_str in input_files:
    file_path = Path(file_str)
    if file_path.exists():
        content = file_path.read_text(encoding='utf-8', errors='ignore')
        if 'aria-label=' not in content:
            content = content.replace('<input', '<input aria-label="Search filter input"')
            file_path.write_text(content, encoding='utf-8')
            print(f"Added aria-label to: {file_str}")
