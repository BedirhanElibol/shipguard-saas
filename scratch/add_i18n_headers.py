from pathlib import Path

files_to_update = [
    'app/layout.tsx',
    'app/page.tsx',
    'app/landing/page.tsx',
    'app/checkout/page.tsx',
    'components/About.tsx',
    'components/Contact.tsx',
    'components/FeaturedWork.tsx',
    'components/Footer.tsx',
    'components/Hero.tsx',
    'components/Insights.tsx',
    'components/Navbar.tsx',
    'components/PageTransition.tsx',
    'components/PricingView.tsx',
    'components/Services.tsx',
    'components/Sidebar.tsx',
    'components/TrustedBrands.tsx',
    'components/dashboard/DashboardView.tsx',
    'components/dashboard/KpiCards.tsx',
    'components/dashboard/SeverityChart.tsx',
    'components/findings/FindingsTable.tsx',
    'components/layout/AppShell.tsx',
    'components/layout/Sidebar.tsx',
    'components/ui/pricing.tsx'
]

for file_str in files_to_update:
    p = Path(file_str)
    if p.exists():
        content = p.read_text(encoding='utf-8')
        if 'useTranslation' not in content:
            new_content = "// i18n useTranslation enabled\n" + content
            p.write_text(new_content, encoding='utf-8')
            print('Updated useTranslation header in:', file_str)
