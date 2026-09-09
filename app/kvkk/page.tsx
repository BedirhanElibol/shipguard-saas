'use client';

import React from 'react';
import Link from 'next/link';
import { ArrowLeft, Shield, FileText, Lock, Globe, Scale } from 'lucide-react';
import { ZelsisLogo } from '@/components/ui/ZelsisLogo';

export default function KvkkPage() {
  return (
    <div className="min-h-screen bg-[#0A0A0A] text-[#EDEDED] font-sans antialiased selection:bg-emerald-500/30 selection:text-emerald-300">
      <header className="border-b border-white/10 bg-[#0A0A0A]/80 backdrop-blur-md sticky top-0 z-40">
        <div className="max-w-5xl mx-auto px-4 sm:px-6 h-16 flex items-center justify-between">
          <Link href="/" className="flex items-center gap-2 group">
            <ZelsisLogo size="md" />
          </Link>
          <div className="flex items-center gap-4">
            <Link
              href="/privacy"
              className="text-xs text-[#A1A1AA] hover:text-white transition-colors"
            >
              Privacy (EN)
            </Link>
            <Link
              href="/"
              className="inline-flex items-center gap-1.5 text-xs text-[#A1A1AA] hover:text-white transition-colors bg-white/5 hover:bg-white/10 px-3 py-1.5 rounded-lg border border-white/10"
            >
              <ArrowLeft size={13} />
              <span>Ana Sayfaya Dön</span>
            </Link>
          </div>
        </div>
      </header>

      <main className="max-w-4xl mx-auto px-4 sm:px-6 py-12">
        <div className="flex items-center gap-2 mb-3">
          <span className="text-[11px] font-mono font-bold uppercase tracking-wider text-emerald-400 bg-emerald-500/10 border border-emerald-500/30 px-2.5 py-0.5 rounded-full">
            6698 Sayılı KVKK Uyarınca
          </span>
          <span className="text-xs text-[#71717A]">Son Güncelleme: 10 Eylül 2026</span>
        </div>

        <h1 className="text-3xl sm:text-4xl font-extrabold tracking-tight text-white mb-4">
          Kişisel Verilerin Korunması ve İşlenmesi Aydınlatma Metni
        </h1>

        <p className="text-sm text-[#A1A1AA] leading-relaxed mb-8">
          Bu Aydınlatma Metni, 6698 sayılı Kişisel Verilerin Korunması Kanunu (&quot;KVKK&quot;) ve ilgili mevzuat uyarınca, veri sorumlusu sıfatıyla <strong>Zelsis</strong> (&quot;Şirket&quot; veya &quot;Zelsis SaaS&quot;) tarafından sunulan web sitesi, güvenlik tarama motoru ve abonelik hizmetlerinden yararlanan kullanıcıların kişisel verilerinin toplanması, işlenmesi ve korunmasına ilişkin usul ve esasları açıklamaktadır.
        </p>

        <div className="space-y-8 text-sm text-[#D4D4D8] leading-relaxed">
          {/* Section 1 */}
          <section className="bg-[#141414] border border-white/10 rounded-2xl p-6 sm:p-8">
            <h2 className="text-lg font-bold text-white flex items-center gap-2 mb-3">
              <Scale size={18} className="text-emerald-400" />
              1. Veri Sorumlusunun Kimliği
            </h2>
            <p className="text-xs text-[#A1A1AA] mb-3">
              KVKK Madde 10 kapsamında veri sorumlusu:
            </p>
            <div className="bg-[#0A0A0A] border border-white/10 rounded-xl p-4 text-xs font-mono space-y-1.5 text-[#E4E4E7]">
              <div><strong>Hizmet / Platform:</strong> Zelsis Release Gate SaaS</div>
              <div><strong>İletişim E-Posta:</strong> contact@zelsis.com</div>
              <div><strong>Veri Koruma Yetkilisi (DPO):</strong> privacy@zelsis.com</div>
              <div><strong>Yetkili Yargı Çevresi:</strong> İstanbul Mahkemeleri ve İcra Daireleri</div>
            </div>
          </section>

          {/* Section 2 */}
          <section className="bg-[#141414] border border-white/10 rounded-2xl p-6 sm:p-8">
            <h2 className="text-lg font-bold text-white flex items-center gap-2 mb-3">
              <FileText size={18} className="text-emerald-400" />
              2. İşlenen Kişisel Veriler
            </h2>
            <ul className="list-disc list-inside space-y-2 text-xs text-[#A1A1AA]">
              <li><strong>Kimlik ve İletişim Bilgileri:</strong> Ad, soyad, e-posta adresi, GitHub profil kimliği (OAuth ile giriş yapıldığında).</li>
              <li><strong>İşlem ve Kullanım Güvenliği Verileri:</strong> IP adresi, oturum çerezleri, tarayıcı türü, oturum açma tarih/saat bilgileri.</li>
              <li><strong>Proje ve Kaynak Kod Telemetrisi:</strong> Taranan GitHub depo URL adresleri, statik güvenlik kuralı ihlal raporları, açık kaynak paket bağımlılıkları. (Kaynak kodlar asla sunucu tarafında kalıcı olarak depolanmaz; tarama işlemi anlık AST analiziyle gerçekleştirilir).</li>
              <li><strong>Abonelik ve Ödeme Bilgileri:</strong> Abonelik türü (Free/Pro/Enterprise), fatura bilgileri, lisans anahtarı. Kredi kartı bilgileri sistemlerimizde saklanmaz; PCI-DSS Seviye 1 uyumlu ödeme aracıları (Polar / Stripe) tarafından tokenlaştırılır.</li>
            </ul>
          </section>

          {/* Section 3 */}
          <section className="bg-[#141414] border border-white/10 rounded-2xl p-6 sm:p-8">
            <h2 className="text-lg font-bold text-white flex items-center gap-2 mb-3">
              <Lock size={18} className="text-emerald-400" />
              3. Kişisel Verilerin İşlenme Amaçları ve Hukuki Sebepleri
            </h2>
            <p className="text-xs text-[#A1A1AA] mb-3">
              Kişisel verileriniz, KVKK&apos;nın 5. maddesinde belirtilen aşağıdaki hukuki sebeplere dayanarak işlenmektedir:
            </p>
            <ul className="list-disc list-inside space-y-2 text-xs text-[#A1A1AA]">
              <li><strong>Sözleşmenin Kurulması ve İfası (KVKK m.5/2-c):</strong> Kullanıcı hesabı oluşturulması, güvenlik tarama motorunun çalıştırılması, abonelik yönetimi ve faturalandırma.</li>
              <li><strong>Veri Sorumlusunun Meşru Menfaati (KVKK m.5/2-f):</strong> Hizmet kalitesinin artırılması, kötüye kullanım ve siber saldırıların engellenmesi, hata ayıklama.</li>
              <li><strong>Hukuki Yükümlülüğün Yerine Getirilmesi (KVKK m.5/2-ç):</strong> 5651 sayılı İnternet Ortamında Yapılan Yayınların Düzenlenmesi Kanunu uyarınca erişim ve trafik kayıtlarının tutulması.</li>
            </ul>
          </section>

          {/* Section 4 */}
          <section className="bg-[#141414] border border-white/10 rounded-2xl p-6 sm:p-8">
            <h2 className="text-lg font-bold text-white flex items-center gap-2 mb-3">
              <Globe size={18} className="text-emerald-400" />
              4. Kişisel Verilerin Yurt Dışına Aktarımı
            </h2>
            <p className="text-xs text-[#A1A1AA] leading-relaxed">
              Zelsis SaaS altyapısı; güvenli veritabanı yönetimi (Supabase - AWS AB/ABD bölgesi), statik barındırma ve sunucusuz kenar bilişim (Vercel Inc. - ABD) ve uluslararası ödeme altyapısı (Polar Inc. / Stripe Inc.) ile entegre çalışmaktadır. Kişisel verileriniz, KVKK m. 9 uyarınca açık rızanıza istinaden veya ilgili uluslararası sözleşmesel güvenceler tahtında yalnızca belirtilen hizmetlerin ifası amacıyla yurt dışı sunucularına aktarılabilmektedir.
            </p>
          </section>

          {/* Section 5 */}
          <section className="bg-[#141414] border border-white/10 rounded-2xl p-6 sm:p-8">
            <h2 className="text-lg font-bold text-white flex items-center gap-2 mb-3">
              <Shield size={18} className="text-emerald-400" />
              5. İlgili Kişinin (Veri Sahibinin) Hakları
            </h2>
            <p className="text-xs text-[#A1A1AA] mb-3">
              KVKK&apos;nın 11. maddesi uyarınca veri sahipleri aşağıdaki haklara sahiptir:
            </p>
            <ul className="list-disc list-inside space-y-1.5 text-xs text-[#A1A1AA]">
              <li>Kişisel verilerinizin işlenip işlenmediğini öğrenme,</li>
              <li>İşlenmişse buna ilişkin bilgi talep etme,</li>
              <li>İşlenme amacını ve bunların amacına uygun kullanılıp kullanılmadığını öğrenme,</li>
              <li>Yurt içinde veya yurt dışında kişisel verilerin aktarıldığı üçüncü kişileri bilme,</li>
              <li>Eksik veya yanlış işlenmiş olması hâlinde bunların düzeltilmesini isteme,</li>
              <li><strong>KVKK m. 7 ve GDPR m. 17 uyarınca kişisel verilerin silinmesini veya yok edilmesini isteme (Unutulma Hakkı),</strong></li>
              <li>İşlenen verilerin münhasıran otomatik sistemler vasıtasıyla analiz edilmesi suretiyle aleyhinize bir sonucun ortaya çıkmasına itiraz etme.</li>
            </ul>
            <p className="text-xs text-emerald-400 mt-4">
              Haklarınızı kullanmak veya hesabınızı veritabanlarımızdan kalıcı olarak silmek için Kullanıcı Ayarları panelindeki &quot;GDPR / KVKK Data Erasure&quot; özelliğini kullanabilir veya <a href="mailto:privacy@zelsis.com" className="underline font-bold">privacy@zelsis.com</a> adresine yazılı talep iletebilirsiniz.
            </p>
          </section>
        </div>
      </main>
    </div>
  );
}
