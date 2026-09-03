# Web Projesi Canlıya Alma Kontrol Listesi (Production-Ready Checklist) — %100 TAMAMLANDI

> Vibe-coding prototipini gerçek, güvenilir ve yayına hazır profesyonel bir web ürününe dönüştüren 20 temel gereksinim.

---

## 1. UI / UX, Etkileşim ve Dönüşüm (CRO)

- [x] **01. Custom 404 Page (Özel 404 Hata Sayfası)** (`app/not-found.tsx`)  
  Varsayılan sunucu hatası yerine kullanıcıyı anasayfaya veya arama kutusuna yönlendiren samimi, marka diline uygun sayfa.

- [x] **02. CTA Above the Fold (İlk Ekranda Harekete Geçirici Mesaj)** (`components/Hero.tsx`)  
  Kullanıcı sayfayı aşağı kaydırmadan doğrudan görünen, net bir değer önerisi ve belirgin aksiyon/kayıt butonu.

- [x] **10. Mobile Breakpoints (Duyarlı / Responsive Ekran Düzeni)**  
  Mobil, tablet ve geniş masaüstü ekranlarında yatay taşma (`overflow-x`) olmayan, akıcı CSS medya sorguları.

- [x] **11. Sticky Mobile CTA (Mobilde Sabit Kalan Aksiyon Butonu)** (`components/StickyMobileCTA.tsx`)  
  Mobil ekranlarda sayfa kaydırıldıkça ekranın altında sabit kalarak dönüşüm kaybını önleyen aksiyon çubuğu.

- [x] **12. Loading States (Yüklenme Bildirimleri)**  
  Veri çekilirken veya buton tıklandığında beliren spinner, skeleton ekranlar ve donma hissini engelleyen görsel geri bildirimler.

- [x] **13. Form Error States (Form Doğrulama ve Hata Durumları)**  
  Eksik veya hatalı alanlarda kullanıcı dostu inline uyarılar, kırmızı kenarlıklar ve anlaşılır düzeltme mesajları.

- [x] **14. Thank-you Page (Teşekkür / Dönüşüm Sayfası)**  
  Form gönderimi veya satın alma sonrası işlemi teyit eden, sonraki adımları aktaran ve analitik conversion event'lerini tetikleyen sayfa.

---

## 2. SEO, İndekslenme ve Sosyal Paylaşım

- [x] **03. Meta Title Per Page (Sayfa Başına Özel Başlık)** (`app/layout.tsx`)  
  Her alt sayfa için optimize edilmiş, anahtar kelime ve marka içeren dinamik `<title>` etiketi.

- [x] **04. Meta Description Per Page (Sayfa Başına Özel Açıklama)** (`app/layout.tsx`)  
  Google arama sonuçlarında (SERP) tıklama oranını (CTR) artıran 140-160 karakterlik özet açıklamalar.

- [x] **05. Open Graph Image (OG / Sosyal Medya Önizleme Görseli)** (`app/opengraph-image.tsx`)  
  Twitter, WhatsApp, LinkedIn paylaşımlarında çıkan 1200x630px boyutunda profesyonel marka önizleme kartı.

- [x] **06. Favicon Set (Tüm Platformlar İçin Favicon Paketi)** (`public/favicon.ico`, `manifest.ts`)  
  `favicon.ico` (32x32), `apple-touch-icon.png` (180x180) ve `site.webmanifest` ikonlarını içeren eksiksiz set.

- [x] **07. robots.txt (Arama Motoru Tarama Kuralları)** (`app/robots.ts`)  
  Botlara hangi sayfaların taranıp taranmayacağını bildiren ve sitemap yolunu tanımlayan kök dizin dosyası.

- [x] **08. sitemap.xml (Site Haritası)** (`app/sitemap.ts`)  
  Tüm canlı sayfaları listeleyen ve Google Search Console'a iletilen güncel XML site haritası.

- [x] **09. Alt Text on Every Image (Görsel Alternatif Metinleri)**  
  Ekran okuyucular (erişilebilirlik) ve görsel SEO için tüm `<img>` etiketlerinde açıklayıcı `alt` özniteliği.

---

## 3. Hukuki Uyumluluk, Güven ve Altyapı

- [x] **15. Privacy Policy Page (Gizlilik Politikası / KVKK / GDPR)** (`app/privacy/page.tsx`)  
  Kullanıcı verilerinin nasıl işlendiğini, saklandığını ve üçüncü partilerle paylaşımını açıklayan yasal metin.

- [x] **16. Terms & Conditions (Kullanım Şartları ve Koşulları)** (`app/terms/page.tsx`)  
  Hizmet sınırlarını, telif haklarını, sorumluluk reddini ve kullanıcı yükümlülüklerini belirten yasal sözleşme.

- [x] **17. Cookie Banner (Çerez Onay Bildirimi)** (`components/CookieBanner.tsx`)  
  Ziyaretçilere analitik ve pazarlama çerezlerini kabul/reddetme imkanı tanıyan mevzuata uygun onay bandı.

- [x] **18. Analytics Installed (Web Analitik ve Etkinlik Takibi)**  
  Trafik, hemen çıkma oranı ve dönüşüm hunisini takip eden araç entegrasyonu (GA4, PostHog, Plausible vb.).

- [x] **19. Real Contact Address (Gerçek İletişim & Şirket Bilgileri)** (`components/Contact.tsx`)  
  Spam filtrelerini ve güven şüphelerini aşmak için gerçek fiziki adres, kurumsal domain e-postası ve iletişim formu.

- [x] **20. Custom Domain, SSL & Security Headers (Özel Domain ve Güvenlik)** (`next.config.mjs`)  
  Özel domain yapılandırması, zorunlu HTTPS/SSL sertifikası, CSP ve HSTS güvenlik başlıkları.