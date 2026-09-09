'use client';

import React from 'react';
import Link from 'next/link';
import { ArrowLeft, Scale, CreditCard, ShieldCheck, FileCheck } from 'lucide-react';
import { ZelsisLogo } from '@/components/ui/ZelsisLogo';

export default function MesafeliSatisPage() {
  return (
    <div className="min-h-screen bg-[#0A0A0A] text-[#EDEDED] font-sans antialiased selection:bg-emerald-500/30 selection:text-emerald-300">
      <header className="border-b border-white/10 bg-[#0A0A0A]/80 backdrop-blur-md sticky top-0 z-40">
        <div className="max-w-5xl mx-auto px-4 sm:px-6 h-16 flex items-center justify-between">
          <Link href="/" className="flex items-center gap-2 group">
            <ZelsisLogo size="md" />
          </Link>
          <div className="flex items-center gap-4">
            <Link
              href="/checkout"
              className="text-xs text-[#A1A1AA] hover:text-white transition-colors"
            >
              Satın Alma Ekranı
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
            6502 Sayılı TKHK &amp; Mesafeli Sözleşmeler Yönetmeliği
          </span>
          <span className="text-xs text-[#71717A]">Son Güncelleme: 10 Eylül 2026</span>
        </div>

        <h1 className="text-3xl sm:text-4xl font-extrabold tracking-tight text-white mb-4">
          Mesafeli Satış Sözleşmesi ve Ön Bilgilendirme Formu
        </h1>

        <p className="text-sm text-[#A1A1AA] leading-relaxed mb-8">
          Bu sözleşme, 6502 sayılı Tüketicinin Korunması Hakkında Kanun ve Mesafeli Sözleşmeler Yönetmeliği hükümleri uyarınca, Zelsis platformu üzerinden dijital güvenlik denetimi yazılımı (&quot;SaaS&quot;) aboneliği satın alan ALICI ile SATICI arasındaki hak ve yükümlülükleri düzenler.
        </p>

        <div className="space-y-8 text-sm text-[#D4D4D8] leading-relaxed">
          {/* Madde 1: Taraflar */}
          <section className="bg-[#141414] border border-white/10 rounded-2xl p-6 sm:p-8">
            <h2 className="text-lg font-bold text-white flex items-center gap-2 mb-3">
              <Scale size={18} className="text-emerald-400" />
              Madde 1: Taraflar
            </h2>
            <div className="space-y-3 text-xs text-[#A1A1AA]">
              <div className="bg-[#0A0A0A] border border-white/10 rounded-xl p-4 font-mono text-[#E4E4E7]">
                <div><strong>SATICI:</strong> Zelsis Release Gate SaaS</div>
                <div><strong>E-Posta:</strong> contact@zelsis.com / billing@zelsis.com</div>
                <div><strong>Müşteri Destek:</strong> support@zelsis.com</div>
              </div>
              <p>
                <strong>ALICI:</strong> Zelsis web sitesi üzerinden üye olan ve ödeme adımlarını tamamlayarak dijital abonelik veya lisans anahtarı edinen gerçek veya tüzel kişidir.
              </p>
            </div>
          </section>

          {/* Madde 2: Sözleşmenin Konusu ve Hizmet */}
          <section className="bg-[#141414] border border-white/10 rounded-2xl p-6 sm:p-8">
            <h2 className="text-lg font-bold text-white flex items-center gap-2 mb-3">
              <FileCheck size={18} className="text-emerald-400" />
              Madde 2: Hizmetin Niteliği ve İfa Şekli
            </h2>
            <p className="text-xs text-[#A1A1AA] leading-relaxed mb-3">
              Sözleşmenin konusu, ALICI&apos;nın Zelsis platformu üzerinden elektronik ortamda siparişini verdiği dijital güvenlik ve kod denetimi SaaS aboneliğinin (Pro veya Enterprise planı) satışı ve teslimidir.
            </p>
            <p className="text-xs text-[#A1A1AA] leading-relaxed">
              Hizmet, ödemenin başarıyla tamamlanmasının ardından ALICI&apos;nın hesabına anında tanımlanır veya e-posta yoluyla lisans aktivasyon kodu olarak elektronik ortamda anında teslim edilir. Fiziki kargo veya teslimat söz konusu değildir.
            </p>
          </section>

          {/* Madde 3: Fiyat ve KDV */}
          <section className="bg-[#141414] border border-white/10 rounded-2xl p-6 sm:p-8">
            <h2 className="text-lg font-bold text-white flex items-center gap-2 mb-3">
              <CreditCard size={18} className="text-emerald-400" />
              Madde 3: Hizmet Bedeli ve Vergilendirme
            </h2>
            <p className="text-xs text-[#A1A1AA] leading-relaxed">
              Hizmet bedelleri web sitesindeki fiyatlandırma sayfasında belirtildiği gibidir. Türkiye Cumhuriyeti vergi mevzuatı gereğince, Türkiye mukimi kullanıcılara yapılan satışlarda yasal <strong>%20 KDV (Katma Değer Vergisi)</strong> uygulanır.
            </p>
          </section>

          {/* Madde 4: Cayma Hakkı İstisnası */}
          <section className="bg-[#141414] border border-white/10 rounded-2xl p-6 sm:p-8">
            <h2 className="text-lg font-bold text-white flex items-center gap-2 mb-3">
              <ShieldCheck size={18} className="text-emerald-400" />
              Madde 4: Cayma Hakkı ve İstisnaları
            </h2>
            <div className="bg-amber-500/10 border border-amber-500/30 rounded-xl p-4 text-xs text-amber-200/90 leading-relaxed space-y-2">
              <p>
                <strong>ÖNEMLİ YASAL BİLGİLENDİRME:</strong> Mesafeli Sözleşmeler Yönetmeliği&apos;nin 15. maddesinin 1. fıkrasının (ğ) bendi uyarınca:
              </p>
              <p className="font-mono text-[11px] text-amber-100">
                &quot;Elektronik ortamda anında ifa edilen hizmetler veya tüketiciye anında teslim edilen gayrimaddi mallara ilişkin sözleşmelerde cayma hakkı kullanılamaz.&quot;
              </p>
              <p>
                Zelsis SaaS aboneliği ödeme yapıldığı anda kullanıcının hesabına tanımlanarak kaynak kod taraması ve raporlama özelliklerini anında erişime açtığından, hizmetin ifasına başlandıktan sonra cayma hakkı bulunmamaktadır. Ancak teknik bir hata veya hizmet kesintisi yaşanması halinde ALICI müşteri desteğiyle iletişime geçerek iade talebinde bulunabilir.
              </p>
            </div>
          </section>

          {/* Madde 5: Uyuşmazlıkların Çözümü */}
          <section className="bg-[#141414] border border-white/10 rounded-2xl p-6 sm:p-8">
            <h2 className="text-lg font-bold text-white flex items-center gap-2 mb-3">
              <Scale size={18} className="text-emerald-400" />
              Madde 5: Yetkili Mahkeme ve İcra Daireleri
            </h2>
            <p className="text-xs text-[#A1A1AA] leading-relaxed">
              İşbu sözleşmenin uygulanmasından doğabilecek uyuşmazlıklarda, Ticaret Bakanlığı&apos;nca ilan edilen parasal sınırlar dahilinde ALICI&apos;nın yerleşim yerindeki Tüketici Hakem Heyetleri veya Tüketici Mahkemeleri; ticari nitelikteki işlemlerde ise İstanbul (Çağlayan) Mahkemeleri ve İcra Daireleri yetkilidir.
            </p>
          </section>
        </div>
      </main>
    </div>
  );
}
