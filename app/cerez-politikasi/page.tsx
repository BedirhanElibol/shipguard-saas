'use client';

import React from 'react';
import Link from 'next/link';
import { ArrowLeft, Cookie, Shield, CheckCircle2, Lock } from 'lucide-react';
import { ZelsisLogo } from '@/components/ui/ZelsisLogo';

export default function CerezPolitikasiPage() {
  return (
    <div className="min-h-screen bg-[#0A0A0A] text-[#EDEDED] font-sans antialiased selection:bg-emerald-500/30 selection:text-emerald-300">
      <header className="border-b border-white/10 bg-[#0A0A0A]/80 backdrop-blur-md sticky top-0 z-40">
        <div className="max-w-5xl mx-auto px-4 sm:px-6 h-16 flex items-center justify-between">
          <Link href="/" className="flex items-center gap-2 group">
            <ZelsisLogo size="md" />
          </Link>
          <div className="flex items-center gap-4">
            <Link
              href="/kvkk"
              className="text-xs text-[#A1A1AA] hover:text-white transition-colors"
            >
              KVKK Metni
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
            Çerez Politikası (Cookie Policy)
          </span>
          <span className="text-xs text-[#71717A]">Son Güncelleme: 10 Eylül 2026</span>
        </div>

        <h1 className="text-3xl sm:text-4xl font-extrabold tracking-tight text-white mb-4">
          Çerez (Cookie) Kullanımı ve Gizlilik Politikası
        </h1>

        <p className="text-sm text-[#A1A1AA] leading-relaxed mb-8">
          Zelsis olarak, kullanıcılarımızın güvenliğini ve gizliliğini en üst düzeyde tutmaktayız. Web sitemizde yalnızca sistemin temel çalışmasını, oturum güvenliğini ve güvenlik tercihlerini sağlayan <strong>zorunlu (essential) çerezler</strong> kullanılmaktadır. Platformumuzda üçüncü taraf reklam veya istilacı takip çerezleri (invasive tracking cookies) kullanılmamaktadır.
        </p>

        <div className="space-y-8 text-sm text-[#D4D4D8] leading-relaxed">
          {/* Section 1: Cookie Matrix */}
          <section className="bg-[#141414] border border-white/10 rounded-2xl p-6 sm:p-8">
            <h2 className="text-lg font-bold text-white flex items-center gap-2 mb-4">
              <Cookie size={18} className="text-emerald-400" />
              Kullanılan Çerezler Matrisi (Cookie Table)
            </h2>

            <div className="overflow-x-auto">
              <table className="w-full text-left text-xs font-mono border-collapse">
                <thead>
                  <tr className="border-b border-white/15 text-[#A1A1AA] bg-white/5">
                    <th className="py-2.5 px-3">Çerez Adı</th>
                    <th className="py-2.5 px-3">Türü</th>
                    <th className="py-2.5 px-3">Süre</th>
                    <th className="py-2.5 px-3">Amacı ve İşlevi</th>
                  </tr>
                </thead>
                <tbody className="divide-y divide-white/10 text-[#D4D4D8]">
                  <tr>
                    <td className="py-3 px-3 text-emerald-400 font-bold">zelsis_user</td>
                    <td className="py-3 px-3">Zorunlu / Güvenlik</td>
                    <td className="py-3 px-3">30 Gün</td>
                    <td className="py-3 px-3 font-sans text-xs">Oturum açmış kullanıcının kimlik doğrulama durumunu, plan derecesini ve oturum güvenliğini sağlar. (Secure &amp; SameSite=Lax bayrakları ile korunur).</td>
                  </tr>
                  <tr>
                    <td className="py-3 px-3 text-emerald-400 font-bold">zelsis_cookie_consent</td>
                    <td className="py-3 px-3">İşlevsel / Tercih</td>
                    <td className="py-3 px-3">1 Yıl</td>
                    <td className="py-3 px-3 font-sans text-xs">Kullanıcının çerez politikası onay ve tercih durumunu hatırlar.</td>
                  </tr>
                  <tr>
                    <td className="py-3 px-3 text-emerald-400 font-bold">zelsis_data_version</td>
                    <td className="py-3 px-3">İşlevsel (Local)</td>
                    <td className="py-3 px-3">Kalıcı (Local)</td>
                    <td className="py-3 px-3 font-sans text-xs">Tarayıcı önbelleğindeki güvenlik kuralları kataloğunun güncel sürümünü doğrular.</td>
                  </tr>
                </tbody>
              </table>
            </div>
          </section>

          {/* Section 2: How to Manage */}
          <section className="bg-[#141414] border border-white/10 rounded-2xl p-6 sm:p-8">
            <h2 className="text-lg font-bold text-white flex items-center gap-2 mb-3">
              <Lock size={18} className="text-emerald-400" />
              Çerez Tercihlerini Yönetme ve Engelleme
            </h2>
            <p className="text-xs text-[#A1A1AA] mb-3">
              Dilediğiniz zaman tarayıcınızın ayarlarından çerezleri silebilir veya engelleyebilirsiniz. Ancak zorunlu oturum çerezlerini engellemeniz durumunda, Zelsis platformuna oturum açamayabilir veya kayıtlı güvenlik taramalarınıza erişemeyebilirsiniz.
            </p>
            <div className="bg-[#0A0A0A] border border-white/10 rounded-xl p-4 text-xs text-[#CBD5E1] space-y-1 font-mono">
              <div>• Google Chrome: Ayarlar &gt; Gizlilik ve Güvenlik &gt; Çerezler</div>
              <div>• Mozilla Firefox: Seçenekler &gt; Gizlilik ve Güvenlik &gt; Çerezler</div>
              <div>• Apple Safari: Tercihler &gt; Gizlilik &gt; Çerezleri Engelle</div>
            </div>
          </section>
        </div>
      </main>
    </div>
  );
}
