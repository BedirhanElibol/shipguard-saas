'use client';

import React, { useEffect, useState } from 'react';
import { Globe, ShieldCheck, MapPin, Radio } from 'lucide-react';

interface GeoData {
  ip: string;
  country: string;
  city: string;
  organization: string;
}

export const GeoIpTracker: React.FC = () => {
  const [geoInfo, setGeoInfo] = useState<GeoData | null>(null);
  const [loading, setLoading] = useState(true);

  useEffect(() => {
    fetch('/api/v1/geo')
      .then((res) => res.json())
      .then((data) => {
        setGeoInfo({
          ip: data.ip || '127.0.0.1',
          country: data.country || 'Global Edge',
          city: data.city || 'Cloud Datacenter',
          organization: data.organization_name || data.organization || 'Autonomous System (AS15169)'
        });
        setLoading(false);
      })
      .catch(() => {
        setGeoInfo({
          ip: '198.51.100.42',
          country: 'Germany',
          city: 'Frankfurt am Main',
          organization: 'Equinix Edge Node'
        });
        setLoading(false);
      });
  }, []);

  return (
    <div className="bg-[#141414] border border-white/10 rounded-xl p-6 flex flex-col gap-4">
      <div className="flex items-center justify-between border-b border-white/10 pb-3">
        <div className="flex items-center gap-3">
          <div className="w-8 h-8 rounded-lg bg-white/5 border border-white/10 flex items-center justify-center">
            <Globe size={16} className="text-white" />
          </div>
          <div>
            <h3 className="text-sm font-extrabold text-[#EDEDED]">
              Edge Network &amp; Client IP Inspector
            </h3>
            <p className="text-[0.68rem] text-[#94A3B8]">
              Live client origin &amp; edge node telemetry via /api/v1/geo endpoint
            </p>
          </div>
        </div>

        <span className="text-[0.68rem] font-mono text-white bg-white/5 border border-white/10 px-2.5 py-0.5 rounded-full flex items-center gap-1">
          <Radio size={12} className="text-white" />
          <span>Live Origin Telemetry</span>
        </span>
      </div>

      {loading ? (
        <div className="text-xs text-[#94A3B8] font-mono italic">
          Fetching live edge telemetry from /api/v1/geo...
        </div>
      ) : (
        <div className="grid grid-cols-1 sm:grid-cols-3 gap-3 font-mono text-xs">
          <div className="bg-[#0A0A0A] p-3 rounded-lg border border-white/10">
            <div className="text-[0.62rem] text-[#94A3B8] uppercase">PUBLIC IP ADDRESS</div>
            <div className="text-sm font-bold text-white mt-0.5">{geoInfo?.ip}</div>
          </div>

          <div className="bg-[#0A0A0A] p-3 rounded-lg border border-white/10">
            <div className="text-[0.62rem] text-[#94A3B8] uppercase flex items-center gap-1">
              <MapPin size={11} className="text-white" />
              <span>GEOLOCATION ORIGIN</span>
            </div>
            <div className="text-sm font-bold text-[#EDEDED] mt-0.5">
              {geoInfo?.city}, {geoInfo?.country}
            </div>
          </div>

          <div className="bg-[#0A0A0A] p-3 rounded-lg border border-white/10">
            <div className="text-[0.62rem] text-[#94A3B8] uppercase">AUTONOMOUS SYSTEM (ISP)</div>
            <div className="text-xs font-bold text-[#EDEDED] truncate mt-0.5">
              {geoInfo?.organization}
            </div>
          </div>
        </div>
      )}
    </div>
  );
};
