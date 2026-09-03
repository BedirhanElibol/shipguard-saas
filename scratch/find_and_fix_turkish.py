import os
import re

workspace_dir = r"c:\Users\Bedirhan\Desktop\newday"

replacements = [
    ("Mor-mavi gradyan algılandı", "Purple-blue gradient detected"),
    ("Jenerik Mor-Mavi Neon Gradyan Kullanımı", "UI-01: Generic Purple-Blue Neon Gradient Cliché"),
    ("Sihirli Değnek (✨) / Sparkle İkon İstilası", "UI-03: Overused Sparkle (✨) / Magic Wand Icon Cliché"),
    ("Sparkle ikon kullanımı algılandı", "Sparkle icon overuse detected"),
    ("Boş Durum (Empty State) Yokluğu", "UI-04: Absence of Empty State Component Fallback"),
    ("Eksik Empty State algılandı", "Missing Empty State component detected"),
    ("Sadece Statik Metin / Mock Veri Gösterimi", "UI-05: Static Text / Hardcoded Mock Data Exposure"),
    ("Statik metin kullanımı algılandı", "Static mock text usage detected"),
    ("Tıklanamaz Pasif Buton / İşlevsiz Eleman", "UI-06: Non-functional Passive Button / Dead Element"),
    ("Özetle", "Summarize"),
    ("Filtrele", "Filter"),
    ("Analiz Et", "Analyze"),
    ("algılandı", "detected"),
    ("yokluğu", "absence"),
    ("kullanımı", "usage"),
    ("istilası", "overuse"),
    ("eksik", "missing"),
    ("Bulgu", "Finding"),
    ("Açık", "Vulnerability")
]

modified_count = 0
for root, dirs, files in os.walk(workspace_dir):
    if "node_modules" in root or ".next" in root or ".git" in root or "scratch" in root:
        continue
    for file in files:
        if file.endswith((".ts", ".tsx", ".js", ".jsx")):
            full_path = os.path.join(root, file)
            with open(full_path, "r", encoding="utf-8", errors="ignore") as f:
                content = f.read()

            new_content = content
            for old_str, new_str in replacements:
                if old_str in new_content:
                    new_content = new_content.replace(old_str, new_str)

            if new_content != content:
                with open(full_path, "w", encoding="utf-8") as f:
                    f.write(new_content)
                modified_count += 1
                print(f"Cleaned Turkish strings in: {file}")

print(f"Total files updated with 100% English terms: {modified_count}")
