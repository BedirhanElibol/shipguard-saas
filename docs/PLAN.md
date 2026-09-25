# Zelsis (ShipGuard) SaaS — Bağımsız Doğrulama Raporu Kapsamlı Çözüm Planı (PLAN.md)
**Referans Rapor:** Zelsis (ShipGuard) SaaS Doğrulama Raporu — Düzeltmelerin Yeniden Testi (23 Eylül 2026)  
**Hedef:** Raporda listelenen 47 bulgu + 6 yeni keşif (V-01 – V-06) arasından açık veya kısmen düzeltilmiş olan **hiçbir bulguyu atlamadan** eksiksiz ve dürüst şekilde gidermek.  
**Orkestrasyon Ajanları:** `project-planner`, `security-auditor`, `backend-specialist`, `frontend-specialist`, `devops-engineer`, `test-engineer`.

---

## 1. Kapsam ve Görev Dağılımı (4 Ana Kulvar)

### 📌 KULVAR 1: Kural Motoru Dürüstlüğü & Sentinellerin Temizlenmesi (`security-auditor` + `backend-specialist`)
* **V-05 & F-10 (En Yüksek Öncelik):** 
  * 326 kuraldaki `cleanContent.includes(sentinelA) || (regex && cleanContent.includes(sentinelB))` gizlenmiş ölü kod desenini tespit edip temizleme.
  * Tüm kuralları `&& cleanContent.includes('camelCaseFake')` bağımlılığından kurtarıp doğrudan gerçek AST/Regex ifadesine bağlama.
  * Tetikleyici oranındaki yapay sentinel bağımlılığını %0'a indirme.
* **V-02 (SSRF İstemci Muafiyeti):**
  * SSRF kuralına (`lib/rules/security-rules.ts`) dosya bağlam kontrolü ekleme: Yalnızca `app/api/**`, server components ve `'use server'` dosyalarını tarama; `utils/helpers.ts` ve React istemci bileşenlerini SSRF kuralından muaf tutma.
* **F-12 (Doğru Satır Numarası Tespiti):**
  * Kural motorlarında `lines.findIndex(...)` ile sadece ilk satırı değil, regex'in tam eşleştiği gerçek satır numarasını (`match.index` üzerinden) hesaplama.
* **F-25 (16 Kasıtlı Zafiyet Eksiklerinin Giderilmesi):**
  * Hâlâ kaçan 4 zafiyet sınıfını yakalayan deterministik kurallar:
    1. Kullanıcı girdili sunucu tarafı `fetch` (gerçek SSRF).
    2. `httpOnly: false` ile yazılan güvensiz çerezler.
    3. `NextResponse.redirect(untrusted)` açık yönlendirme (Open Redirect).
    4. CORS `origin: '*'` ile birlikte `credentials: true` kombinasyonu.
* **F-44 & F-45 (Çok Dilli & Çoklu Veritabanı Derinleştirme):**
  * MySQL string birleştirmeli ham sorgu analizi (`mysql.query("SELECT..." + id)`).
  * `docker-compose.yml` içinde açık portlar (`0.0.0.0:3306`, `0.0.0.0:5432`) ve varsayılan şifre uyarıları.

---

### 📌 KULVAR 2: Güvenlik, Kimlik & Sır Saklama (`security-auditor`)
* **F-01 (Sır Taramasında scratch/ ve .agent/ Muafiyetinin Kaldırılması):**
  * `lib/scanner-engine.ts` içindeki `scratch/` ve `.agent/` koşulsuz atlama mantığını kaldırma; üretim API anahtarlarını (`sk_live_`, `ghp_`, `AKIA`) konumu ne olursa olsun yakalama.
* **F-08 (GitHub PAT Token Güvenliği):**
  * Kullanıcının girdiği GitHub PAT'in `localStorage`'da düz metin saklanmasını sonlandırma. Web Crypto API (`crypto.subtle`) ile istemci tarafında şifreli saklama veya sadece oturum süresince bellekte tutma.
* **F-15 (Sabit Fallback Supabase URL'lerinin Temizlenmesi):**
  * `app/api/v1/user/export/route.ts`, `app/api/v1/gate-check/route.ts` ve `app/api/v1/quota/route.ts` dosyalarındaki `|| 'https://afzpaydfkmycrwuxmzkk.supabase.co'` sabit fallback'lerini kaldırma; ortam değişkeni yoksa açıkça `500 Missing Environment Variable` fırlatma.
* **F-32 (Kullanıcı Profilinin HttpOnly Çerezine Taşınması):**
  * İstemci tarafında `document.cookie` ile `zelsis_user` yazma kalıntılarını sıfırlama; oturum yönetimini Next.js Server Action / Route Handler üzerinden `httpOnly: true; Secure; SameSite=Lax` çerezlere taşıma.
* **V-03 (Gerçek Kriptografik SHA-256 Rapor İmzası):**
  * `lib/report-exporter.ts` içindeki `Math.random().toString(36) + Date.now()` sahte hash üretimini kaldırıp Node.js `crypto.createHash('sha256')` ve Web Crypto `crypto.subtle.digest` ile rapor içeriğinin gerçek SHA-256 özetini üretme.
* **F-31 (Atomik Kota Güncellemesi):**
  * `gate-check` rotasında kota düşümünde etkilenen satır sayısını (`count === 1`) doğrulayarak yarış durumlarını (race condition) engelleme.

---

### 📌 KULVAR 3: DevOps, CI/CD & Test Altyapısı (`devops-engineer` + `test-engineer`)
* **F-07 / V-04 (Gerçek CI/CD Kapısı):**
  * `.github/workflows/zelsis-audit-gate.yml` dosyasındaki sahte `echo "Running 23 OWASP Rules..."` satırlarını kaldırma.
  * Yerine gerçek `npm test` (`npx tsx tests/test_suite.ts`) ve `npx tsx scripts/self_scan.ts` adımlarını ekleme; zafiyet durumunda pipeline'ı kıran gerçek kapı oluşturma.
* **F-18 (CSP ve CORS Sıkılaştırma):**
  * `middleware.ts` ve `lib/security-headers.ts` içindeki `'unsafe-inline'` politikalarını gözden geçirme, mümkün olan yerlerde hash/nonce yapısına hazırlık yapma.
* **F-22 (Kapsamlı Regresyon Test Paketi):**
  * Raporun ampirik test setini (NodeGoat, 16-vuln matriksi, kendi kendini tarama, SSRF istemci testi) otomatik çalıştıran regresyon testlerini `tests/test_suite.ts` içerisine ekleme.

---

### 📌 KULVAR 4: Mimari, Paket Hijyeni & Kod Kalitesi (`frontend-specialist` + `backend-specialist`)
* **F-24 (Motorun İstemci Paketinden Ayrıştırılması):**
  * `scanner-engine.ts` ve kural dosyalarının istemci bundle'ına (`ScanRunnerView.tsx`, `TerminalLogWindow.tsx`) doğrudan girmesini engelleme; taramayı sunucu API uç noktası (`/api/v1/scans/run`) üzerinden yürütme veya `next/dynamic` ile izole etme.
* **F-23 (Kod Kalitesi Temizliği):**
  * Kritik `any` ve gereksiz `console.*` loglarını temizleme.
  * `next.config.mjs` içindeki `eslint.ignoreDuringBuilds: true` direktifini kaldırarak lint kontrollerini etkinleştirme.
* **F-11 (Dürüst Terminoloji):**
  * `InteractiveAnalyzer.tsx` ve arayüzdeki "Live AST Inspector" metinlerini dürüstçe "Deterministic Pattern & Lexical Analyzer" olarak güncelleme.
* **F-33 (Yasal Metinler & KVKK):**
  * `app/privacy/page.tsx` ve `app/terms/page.tsx` sayfalarına KVKK, veri sorumlusu kimliği ve gerçekçi yargı yetkisi maddelerini ekleme.
* **F-36 & F-47 (Pazarlama Metinlerinin Dürüstleştirilmesi):**
  * `docs/` klasöründeki "7,850 kural" ve karşılığı olmayan "Multi-Org Security Gates" şişirmelerini temizleyip mevcut mimariyi yansıtan dürüst sayılarla güncelleme.

---

## 2. Doğrulama ve Kabul Kriterleri (Exit Criteria)

1. **V-05 Doğrulaması:** `git grep "cleanContent.includes(" lib/rules/` çalıştırıldığında sahte sentinel VE'lemeleri sıfır olmalıdır.
2. **Kendi Kendini Tarama Doğrulaması:** `npx tsx scripts/self_scan.ts` çalıştırıldığında sahte kritik hata çıkmamalıdır.
3. **16-Zafiyet Matriksi:** 16 kasıtlı zafiyetin 16'sı da (%100) yakalanmalıdır.
4. **Test Paketi:** `npx tsx tests/test_suite.ts` tüm yeni kurallarla birlikte %100 PASS vermelidir.
5. **CI Kapısı:** `zelsis-audit-gate.yml` dosyasında sıfır sahte `echo` satırı olmalıdır.
