import os

file_path = r"c:\Users\Bedirhan\Desktop\newday\lib\scanner-engine.ts"
with open(file_path, "r", encoding="utf-8") as f:
    content = f.read()

translations_2 = [
    ("Aşırı \"any\" usage detected", "Excessive 'any' type usage detected"),
    ("Monolitik Dosya Üretimi (> 400 satırlık bileşen)", "Monolithic File Overuse (>400 Lines)"),
    ("Monolitik Aşırı Uzun Dosya (> 400 Satır)", "UI-115: Monolithic Overly Long Source File (>400 Lines)"),
    ("Monolitik aşırı uzun dosya detected", "Monolithic long file detected"),
    ("Bellek Sızıntısı Oluşturan Dinleyiciler", "Uncleaned Event Listener Memory Leaks"),
    ("Bellek Sızıntısı Oluşturan Temizlenmemiş Event Listener", "UI-117: Uncleaned Event Listener Memory Leak"),
    ("Streaming olmayan senkron LLM çağrısı detected", "Non-streaming synchronous LLM call detected"),
    ("Tarayıcı Bellek Şişmesi (Un-virtualized Chat History DOM Leaks)", "Unvirtualized Long List DOM Memory Leaks"),
    ("Tarayıcı Bellek Şişmesi ve Sanallaştırma Yokluğu (Missing Virtual Scrolling)", "UI-134: Unvirtualized Long List (Missing Virtual Scrolling)"),
    ("Sanallaştırılmamış uzun liste detected", "Unvirtualized long list detected"),
    ("Kayıp İstek Yönetimi Yokluğu (Missing Abort Signal Listener)", "Missing Request Abort Signal Listener"),
    ("Kayıp İstek Yönetimi ve İptal Dinleyicisi Eksikliği", "UI-139: Missing Request Cancellation AbortSignal Listener"),
    ("İptal dinleyicisi missing streaming detected", "Missing request cancellation listener detected"),
    ("Token İsrafı (Missing Max Tokens Limit)", "Unbounded Token Usage Waste"),
    ("Sınırsız Token Tüketim İsrafı (Missing max_tokens Bound)", "UI-141: Unbounded Token Consumption (Missing max_tokens Limit)"),
    ("Sınırsız max_tokens parametresi detected", "Unbounded max_tokens parameter detected"),
    ("Kullanıcı Başına Maliyet Takipsizliği (Missing User Quotas)", "Unmonitored Per-User Token Spend"),
    ("Kullanıcı Başına Token / Maliyet Takipsizliği", "UI-143: Unmonitored Per-User Token Spend & Quota"),
    ("Kullanıcı token takipsizliği detected", "Unmonitored user token usage detected"),
    ("Otomatik Kapatma (Circuit Breaker) Yokluğu", "Missing Spend Circuit Breaker"),
    ("Harcama Fırlamalarına Karşı Otomatik Circuit Breaker Yokluğu", "UI-160: Missing Automated Budget Circuit Breaker"),
    ("Circuit breaker bütçe kapatıcısı missingliği detected", "Missing budget circuit breaker detected"),
    ("Kullanıcı Geri Bildirimini Toplayamamak (Missing Feedback Module)", "Missing User Feedback Component"),
    ("Kullanıcı Geri Bildirimi (Feedback Module) Eksikliği", "UI-185: Missing User Feedback Component"),
    ("Geri bildirim modülü missingliği detected", "Missing user feedback component detected"),
    ("Gelişmiş Ayarların Basit Kullanıcıyı Boğması", "Exposing Raw Model Parameters"),
    ("Karmaşık Model Parametrelerinin Arayüze Doğrudan Açılması", "UI-195: Exposing Raw Hyper-parameters to End Users"),
    ("Karmaşık parametre girdisi detected", "Raw hyper-parameter input detected"),
    ("Model Güncellemesi Sonrası Çöken Akışlar (Unpinned Model Tag)", "Unpinned Generic Model Alias"),
    ("bilgi bulunamadı", "information not found"),
    ("Veritabanı taranıyor...", "Scanning database models..."),
    ("Sonuçlar derleniyor...", "Compiling audit findings...")
]

for old_s, new_s in translations_2:
    content = content.replace(old_s, new_s)

with open(file_path, "w", encoding="utf-8") as f:
    f.write(content)

print("Successfully translated Part 2 of scanner-engine.ts to pure English!")
