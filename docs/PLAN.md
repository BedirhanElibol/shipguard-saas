# Zelsis SaaS - Landing Page Plan Farkları & Veritabanı Mimarisi Düzenleme Planı

## 1. Görev Özeti & Kapsam
Landing page üzerinde sunulan planlar (Free, Pro, Enterprise) arasındaki operasyonel limitler, özellik setleri, veritabanı şeması ve arka uç kota denetimleri arasındaki tutarsızlıkların ve potansiyel açıkların (bug) sıfıra indirilmesi.

---

## 2. Tespit Edilen Tutarsızlıklar ve İnceleme

### A. Landing Page & Arayüz Tutarsızlıkları
1. **Fiyat Kartları ile Karşılaştırma Tablosu Uyumu:**
   - `data/pricing-plans.ts` ve `components/ui/pricing.tsx` sadece **Zelsis Pro** ($19/ay) ve **Zelsis Enterprise** ($99/ay) kartlarını gösterirken; `components/saas/ComparisonTable.tsx` ve `components/pricing/TierDetailsModal.tsx` **Free ($0)**, **Pro ($19)** ve **Enterprise ($99)** olarak 3 sütunlu yapı sergilemektedir.
   - Kullanıcı ilk girişte Free planın sınırlarını net olarak görmeli, "Start Free" çağrısı fiyat kartlarında da şeffaf bir Free kartı ile desteklenmelidir.

2. **Özellik Sınırlarının Kodla Eşleşmesi (Enforcement):**
   - **Free ($0):**
     - Aylık 3 tarama hakkı (Strict cap, IP + Kullanıcı hesabı).
     - 1 adet aktif açık kaynak (Public) proje sınırı (Private repo kilitli).
     - 1 adet örnek AI düzeltme istemi (Prompt).
     - PDF Rapor dışa aktarma: Kilitli (Ödeme duvarı modalı açılır).
     - CI/CD Gate anahtarları: Kilitli.
   - **Pro ($19/ay | Yıllık $15/ay):**
     - Sınırsız tarama ve analiz.
     - Sınırsız Public ve Private repo bağlama.
     - Sınırsız Claude / Cursor AI düzeltme istemi.
     - İmzalı Kriptografik PDF Uyumluluk Sertifikası.
     - GitHub Actions & CI/CD Gate erişimi.
     - 90 gün denetim geçmişi.
   - **Enterprise ($99/ay | Yıllık $79/ay):**
     - Pro'daki her şey + Özel Kurumsal Kural Setleri (Custom Policy Catalog).
     - Beyaz Etiket (White-Label) Kurumsal PDF & SOC 2 Rapor Paketi.
     - Çoklu Organizasyon (Multi-Org) Takım ve Rol Yönetimi.
     - Sınırsız denetim geçmişi ve özel SLA desteği.

### B. Veritabanı (Supabase PostgreSQL) Tutarsızlıkları & Sağlamlaştırma
1. **Subscriptions & Profiles Tablosu:**
   - `public.profiles.tier` ve `public.subscriptions.plan_tier` ('Free', 'Pro', 'Enterprise') enum tiplerinin birebir örtüşmesi.
   - `monthly_scan_quota`: Free için `3`, Pro ve Enterprise için `-1` (veya `999999` - sınırsız).
   - `scans_used_this_month`: Her fatura dönemi yenilenmesinde otomatik sıfırlanma trigger veya fonksiyonu.
2. **Kritik RLS Güvenliği:**
   - `sql/05_rls_tier_protection.sql` ile istemciden gelen doğrudan yetki yükseltme saldırılarının (CWE-285) bloklanması; yalnızca `service_role` anahtarının (Polar Webhook & Auth API) tier güncelleyebilmesi.

---

## 3. Ajan Görev Dağılımı (Orchestration Matrix)

| Ajan | Odak Alanı | Sorumluluk |
|------|------------|------------|
| `database-architect` | PostgreSQL & RLS | Tablo varsayılanları, kota alanları, tier enum doğrulaması ve SQL betiklerinin konsolidasyonu. |
| `backend-specialist` | API & Quota Gates | `/api/v1/quota`, `/api/v1/subscription/sync` ve `/api/v1/gate-check` rotalarında Free vs Pro vs Enterprise kurallarının eksiksiz çalıştırılması. |
| `frontend-specialist` | UI & Comparison | `ComparisonTable.tsx`, `pricing.tsx`, `TierDetailsModal.tsx` ve `pricing-plans.ts` arasındaki metin, buton ve limit tutarsızlıklarının giderilmesi. |
| `test-engineer` | Doğrulama & Derleme | Uçtan uca 108 testin çalıştırılması, test senaryolarına plan sınırlarının eklenmesi ve `npm run build` doğrulaması. |

---

## 4. Uygulama Adımları

1. **Adım 1 (Database):** `sql/` ve `supabase/migrations/` dosyalarını tarayıp plan ve kota yapılarını mükemmel senkronize eden SQL yamasını hazırlamak.
2. **Adım 2 (Frontend Matrix):** Landing page üzerindeki Fiyatlandırma (`pricing.tsx`) ve Karşılaştırma Tablosunu (`ComparisonTable.tsx`) 3 planlı (Free, Pro, Enterprise) tam uyumlu hale getirmek.
3. **Adım 3 (Backend Enforcement):** Özel kuralların ve PDF ihracının Free kullanıcılar için kapalı olduğunu ve Pro/Enterprise için açık olduğunu kesinleştirmek.
4. **Adım 4 (Test & Build):** Tüm testleri (`tests/test_suite.ts`) ve Next.js derlemesini çalıştırmak.
