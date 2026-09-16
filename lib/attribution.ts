/**
 * Attribution & Marketing Campaign Tracking Engine
 * Captures and persists UTM parameters, Google Click ID (gclid),
 * and Meta Click ID (fbclid) across client-side page navigations.
 */

export interface AttributionData {
  utm_source?: string;
  utm_medium?: string;
  utm_campaign?: string;
  utm_term?: string;
  utm_content?: string;
  gclid?: string;
  fbclid?: string;
  referrer?: string;
  landing_page?: string;
  captured_at?: string;
}

const STORAGE_KEY = 'zelsis_attribution';
const COOKIE_DAYS = 30;

function setCookie(name: string, value: string, days: number): void {
  if (typeof document === 'undefined') return;
  const expires = new Date(Date.now() + days * 864e5).toUTCString();
  const secure = window.location.protocol === 'https:' ? '; Secure' : '';
  document.cookie = `${name}=${encodeURIComponent(value)}; expires=${expires}; path=/; SameSite=Lax${secure}`;
}

function getCookie(name: string): string | null {
  if (typeof document === 'undefined') return null;
  const match = document.cookie.match(new RegExp('(^|;\\s*)(' + name + ')=([^;]*)'));
  return match ? decodeURIComponent(match[3]) : null;
}

/**
 * Parses current URL search params and captures any active campaign parameters.
 * Should be invoked on root layout or app mount.
 */
export function captureAttribution(): AttributionData | null {
  if (typeof window === 'undefined') return null;

  try {
    const params = new URLSearchParams(window.location.search);
    const utmSource = params.get('utm_source');
    const utmMedium = params.get('utm_medium');
    const utmCampaign = params.get('utm_campaign');
    const utmTerm = params.get('utm_term');
    const utmContent = params.get('utm_content');
    const gclid = params.get('gclid');
    const fbclid = params.get('fbclid');

    const hasAttribution = Boolean(
      utmSource || utmMedium || utmCampaign || utmTerm || utmContent || gclid || fbclid
    );

    if (hasAttribution) {
      const currentData: AttributionData = {
        utm_source: utmSource || undefined,
        utm_medium: utmMedium || undefined,
        utm_campaign: utmCampaign || undefined,
        utm_term: utmTerm || undefined,
        utm_content: utmContent || undefined,
        gclid: gclid || undefined,
        fbclid: fbclid || undefined,
        referrer: document.referrer || undefined,
        landing_page: window.location.pathname,
        captured_at: new Date().toISOString()
      };

      const serialized = JSON.stringify(currentData);
      sessionStorage.setItem(STORAGE_KEY, serialized);
      setCookie(STORAGE_KEY, serialized, COOKIE_DAYS);
      return currentData;
    }

    // Fallback: Read existing saved attribution from session or cookie
    const saved = sessionStorage.getItem(STORAGE_KEY) || getCookie(STORAGE_KEY);
    if (saved) {
      return JSON.parse(saved) as AttributionData;
    }
  } catch (err) {
    // Fail gracefully without breaking UI
    console.debug('[Attribution] Warning parsing campaign metadata:', err);
  }

  return null;
}

/**
 * Returns stored attribution data for attaching to checkout or user profile.
 */
export function getAttributionData(): AttributionData | null {
  if (typeof window === 'undefined') return null;
  try {
    const saved = sessionStorage.getItem(STORAGE_KEY) || getCookie(STORAGE_KEY);
    if (saved) {
      return JSON.parse(saved) as AttributionData;
    }
  } catch {
    return null;
  }
  return null;
}

/**
 * Formats attribution metadata as a concise key-value map for Stripe/Polar metadata.
 */
export function getAttributionMetadata(): Record<string, string> {
  const data = getAttributionData();
  if (!data) return {};

  const meta: Record<string, string> = {};
  if (data.utm_source) meta.utm_source = data.utm_source.slice(0, 100);
  if (data.utm_medium) meta.utm_medium = data.utm_medium.slice(0, 100);
  if (data.utm_campaign) meta.utm_campaign = data.utm_campaign.slice(0, 100);
  if (data.gclid) meta.gclid = data.gclid.slice(0, 100);
  if (data.fbclid) meta.fbclid = data.fbclid.slice(0, 100);
  if (data.landing_page) meta.landing_page = data.landing_page.slice(0, 100);

  return meta;
}
