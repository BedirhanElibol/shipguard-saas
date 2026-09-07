# 🛡️ SHIPGUARD AI RELEASE GATE - MASTER AUTH & POLAR RECOVERY PLAN

## Problem ve Olay Analizi (Root Cause Diagnosis)

Kullanıcımızın karşılaştığı iki kritik hata tespit edilmiş ve kök nedenleri izole edilmiştir:

1. **Problem 1: GitHub / Google ile Giriş Yaparken Mock Form Açılması ("saçma bir şekilde kalıyor")**
   - **Görülen Durum:** Kullanıcı "Continue with GitHub" dediğinde gerçek GitHub OAuth sayfasına yönlendirilmek yerine `"GitHub Username: @ e.g. octocat"` yazan simülasyon modalı açılmakta; "Continue with Google" dediğinde ise `"Demo Developer"` ve `"Custom Google Account"` formu açılmaktadır.
   - **Kök Neden:**
     1. `lib/supabase.ts` dosyası Supabase bağlantı bilgilerini `process.env.NEXT_PUBLIC_SUPABASE_URL` ve `process.env.NEXT_PUBLIC_SUPABASE_ANON_KEY` ortam değişkenlerinden okumaktadır.
     2. Vercel paneline bu ortam değişkenleri manuel eklenmediği için, Vercel client-side derlemesinde `isSupabaseConfigured()` fonksiyonu `false` dönmektedir.
     3. `AuthModal.tsx`, `isSupabaseConfigured() === false` olduğunda doğrudan bu kafa karıştırıcı simülasyon formlarına düşmektedir.
     4. Oysaki Supabase veritabanında (`https://afzpaydfkmycrwuxmzkk.supabase.co`) gerçek GitHub OAuth (`client_id=Ov23lipZro2U0SyZYojq`) ve Google OAuth altyapısı mevcuttur.

2. **Problem 2: Polar ile Ödeme Yapınca Siteden Atma ve Oturum Kapanması**
   - **Görülen Durum:** Kullanıcı Polar üzerinden 0.50$ ödeme yaptıktan sonra siteye döndüğünde oturumunun kapandığını ve giriş yapamadığını görmüştür.
   - **Kök Neden:**
     1. Polar checkout harici bir etki alanında (`buy.polar.sh`) çalışmaktadır. Kullanıcı oraya yönlendiğinde ve geri döndüğünde `localStorage` oturumunun canlı Supabase oturumuyla eşzamanlanmasında kopukluk oluşmaktadır.
     2. Polar'ın `success_url` adresi `https://shipguard-saas.vercel.app/dashboard` adresine dönmektedir; ancak kullanıcı `https://shipguard-saas.vercel.app/checkout` sayfasında `?success=true` bekleyen mantıktan bağımsız yönlendirildiği için Pro tier otomatik aktive olmamıştır.
     3. Kullanıcının oturumu cookie tabanlı persistent bir oturum olarak saklanmadığı için, cross-origin dönüşünde tarayıcı misafir moduna düşmüştür.

---

## User Review Required

> [!IMPORTANT]
> **Yapılacak Kritik Değişiklikler:**
> 1. Sahte `@ e.g. octocat` ve `Demo Developer` formları **tamamen kaldırılacak**. GitHub ve Google butonları doğrudan **resmi yetkilendirme ekranlarına (OAuth popup/redirect)** gidecek.
> 2. Supabase Public Anon Key kod seviyesinde garanti altına alınacak; böylece Vercel ortam değişkeni eksik olsa dahi canlı sitede girişler asla kesilmeyecek.
> 3. Oturumlar `localStorage`'a ek olarak tarayıcı `cookie`'sinde de saklanacak; böylece Polar ödeme sayfasına gidip dönüldüğünde oturum ASLA kapanmayacak.
> 4. Ödeme yapan kullanıcının hesabı anında **Pro Tier**'a yükseltilecek ve lisans anahtarı üretilecek.

---

## Proposed Changes

### [Authentication & Supabase Layer]

#### [MODIFY] [lib/supabase.ts](file:///C:/Users/Bedirhan/Desktop/newday/lib/supabase.ts)
- `process.env.NEXT_PUBLIC_SUPABASE_URL` ve `NEXT_PUBLIC_SUPABASE_ANON_KEY` için güvenli public anon fallback değerleri tanımlanacak.
- `supabaseSignInWithOAuth('github')` ve `supabaseSignInWithOAuth('google')` fonksiyonları doğrudan canlı Supabase OAuth uç noktasına yönlendirecek.
- Oturum yönetimi hem Supabase SDK hem cookie fallback ile güçlendirilecek.

### [Frontend & Modal Layer]

#### [MODIFY] [components/auth/AuthModal.tsx](file:///C:/Users/Bedirhan/Desktop/newday/components/auth/AuthModal.tsx)
- Sahte `@ e.g. octocat` ekranı tamamen silinecek.
- Sahte "Demo Developer" Google ekranı tamamen silinecek.
- "Continue with GitHub" tıklandığı anda doğrudan GitHub yetkilendirme ekranına yönlendirilecek.
- "Continue with Google" tıklandığı anda doğrudan Google yetkilendirme ekranına yönlendirilecek.
- E-posta/şifre girişi ve şifre sıfırlama akışları temiz tutulacak.

#### [MODIFY] [app/auth/callback/page.tsx](file:///C:/Users/Bedirhan/Desktop/newday/app/auth/callback/page.tsx)
- OAuth dönüşünde oturum token'ı hem `localStorage`'a hem `document.cookie`'ye kaydedilecek.
- Başarılı girişten sonra `/dashboard` yönlendirmesi kesintisiz yapılacak.

### [Checkout & Dashboard Return Layer]

#### [MODIFY] [hooks/useDashboardState.ts](file:///C:/Users/Bedirhan/Desktop/newday/hooks/useDashboardState.ts)
- Sayfa açılışında oturumu hem `cookie`'den hem `localStorage`'dan hem de `supabase.auth.getSession()` üzerinden rehydrate edecek.
- URL'de Polar dönüş parametresi varsa (`?polar_success=true` veya Polar dönüşü), kullanıcının Pro lisansını anında aktive edecek.

---

## Verification Plan

### Automated Tests
- `npx tsc --noEmit` ile sıfır TypeScript hatası doğrulanacak.
- `node` üzerinden Supabase OAuth URL üretimi ve yönlendirme testi çalıştırılacak.
- `scratch/sync_to_desktop.py` ile GitHub'a pushlanıp Vercel canlı dağıtımı tamamlanacak.

### Manual Verification
- Canlı sitede (`shipguard-saas.vercel.app`) "Continue with GitHub" tıklanarak doğrudan `github.com` yetkilendirme sayfasına yönlenildiği görülecek.
- Giriş sonrası oturumun açık kaldığı ve Pro planın aktif olduğu doğrulanacak.
