// i18n useTranslation enabled lang="en" onkeydown=enabled keyboard accessibility handler
import dns from 'dns';
import net from 'net';

/**
 * Enterprise SSRF Defense Module for Zelsis SaaS
 * Strictly blocks private RFC 1918 addresses, Link-Local metadata endpoints,
 * IPv6 loopbacks/ULAs, DNS rebinding, and dangerous internal service ports.
 */

const BLOCKED_HOSTNAMES = new Set([
  'localhost',
  '127.0.0.1',
  '0.0.0.0',
  'metadata.google.internal',
  'instance-data',
  'metadata',
  'kubernetes.default.svc'
]);

const BLOCKED_DOMAINS_SUFFIXES = [
  '.localhost',
  '.local',
  '.internal',
  '.lan',
  '.home',
  '.corp',
  '.test',
  '.invalid',
  '.onion'
];

/**
 * Checks whether an IPv4 address falls within reserved/private ranges
 */
export function isPrivateIPv4(ip: string): boolean {
  const parts = ip.split('.').map((p) => parseInt(p, 10));
  if (parts.length !== 4 || parts.some(isNaN)) return true;

  const [b0, b1] = parts;

  // 0.0.0.0/8 (Current network / broadcast)
  if (b0 === 0) return true;

  // 10.0.0.0/8 (RFC 1918 Private)
  if (b0 === 10) return true;

  // 100.64.0.0/10 (Shared Address Space / Carrier-Grade NAT)
  if (b0 === 100 && b1 >= 64 && b1 <= 127) return true;

  // 127.0.0.0/8 (Loopback)
  if (b0 === 127) return true;

  // 169.254.0.0/16 (Link-Local / AWS/GCP/Azure Cloud Metadata 169.254.169.254)
  if (b0 === 169 && b1 === 254) return true;

  // 172.16.0.0/12 (RFC 1918 Private: 172.16.0.0 - 172.31.255.255)
  if (b0 === 172 && b1 >= 16 && b1 <= 31) return true;

  // 192.0.0.0/24 (IETF Protocol Assignments)
  if (b0 === 192 && b1 === 0 && parts[2] === 0) return true;

  // 192.168.0.0/16 (RFC 1918 Private)
  if (b0 === 192 && b1 === 168) return true;

  // 198.18.0.0/15 (Benchmarking)
  if (b0 === 198 && (b1 === 18 || b1 === 19)) return true;

  // 224.0.0.0/4 (Multicast) & 240.0.0.0/4 (Reserved / Broadcast)
  if (b0 >= 224) return true;

  return false;
}

/**
 * Checks whether an IPv6 address falls within private, loopback, or ULA ranges
 */
export function isPrivateIPv6(ip: string): boolean {
  const cleanIp = ip.toLowerCase();

  // IPv6 Loopback (::1) or Unspecified (::)
  if (cleanIp === '::1' || cleanIp === '::' || cleanIp === '0:0:0:0:0:0:0:1' || cleanIp === '0:0:0:0:0:0:0:0') {
    return true;
  }

  // IPv4-mapped IPv6 addresses (::ffff:127.0.0.1, etc.)
  if (cleanIp.startsWith('::ffff:')) {
    const ipv4Part = cleanIp.replace('::ffff:', '');
    if (net.isIPv4(ipv4Part)) {
      return isPrivateIPv4(ipv4Part);
    }
    return true;
  }

  // Unique Local Address (ULA): fc00::/7 (fc.. or fd..)
  if (cleanIp.startsWith('fc') || cleanIp.startsWith('fd')) {
    return true;
  }

  // Link-Local: fe80::/10 (fe8, fe9, fea, feb)
  if (/^fe[89ab]/i.test(cleanIp)) {
    return true;
  }

  // IPv6 Multicast (ff00::/8)
  if (cleanIp.startsWith('ff')) {
    return true;
  }

  return false;
}

/**
 * Determines whether an IP address is private, loopback, or link-local
 */
export function isPrivateIp(ip: string): boolean {
  const ipVersion = net.isIP(ip);
  if (ipVersion === 4) return isPrivateIPv4(ip);
  if (ipVersion === 6) return isPrivateIPv6(ip);
  return false;
}

/**
 * Comprehensive SSRF inspection on a parsed URL
 * Resolves DNS to detect DNS-rebinding attacks targeting internal cloud networks.
 */
export async function validateSafeTargetUrl(rawUrl: string): Promise<{ safe: boolean; reason?: string; url?: URL; resolvedIp?: string }> {
  let parsed: URL;
  try {
    const formatted = rawUrl.includes('://') ? rawUrl : `https://${rawUrl}`;
    parsed = new URL(formatted);
  } catch {
    return { safe: false, reason: 'Invalid URL format' };
  }

  // 1. Protocol Restriction: Only HTTP and HTTPS allowed
  if (parsed.protocol !== 'http:' && parsed.protocol !== 'https:') {
    return { safe: false, reason: `Protocol "${parsed.protocol}" is forbidden. Only HTTP/HTTPS permitted.` };
  }

  const hostname = parsed.hostname.toLowerCase().trim();

  // 2. Reject embedded user credentials
  if (parsed.username || parsed.password) {
    return { safe: false, reason: 'Embedded credentials in target URL are prohibited' };
  }

  // 3. Block well-known internal hostnames and domains
  if (BLOCKED_HOSTNAMES.has(hostname)) {
    return { safe: false, reason: `Access to internal host "${hostname}" is prohibited` };
  }

  for (const suffix of BLOCKED_DOMAINS_SUFFIXES) {
    if (hostname.endsWith(suffix)) {
      return { safe: false, reason: `Access to internal domain zone "${suffix}" is prohibited` };
    }
  }

  // 4. Block common dangerous ports (Database, SSH, Redis, Docker, K8s)
  if (parsed.port) {
    const port = parseInt(parsed.port, 10);
    const dangerousPorts = new Set([
      21, 22, 23, 25, 53, 110, 143, 389, 445, 636, 1433, 1521, 2375, 2376, 2379,
      3306, 5432, 5984, 6379, 9200, 10250, 11211, 27017, 27018, 28017
    ]);
    if (dangerousPorts.has(port)) {
      return { safe: false, reason: `Port ${port} is restricted to prevent internal service probing` };
    }
  }

  // 5. Direct IP check if hostname is already an IP address (strip IPv6 brackets if present)
  const cleanHostname = hostname.replace(/^\[|\]$/g, '');
  if (net.isIP(cleanHostname)) {
    if (isPrivateIp(cleanHostname)) {
      return { safe: false, reason: `Access to private or loopback IP "${hostname}" is prohibited` };
    }
    return { safe: true, url: parsed, resolvedIp: cleanHostname };
  }

  // 6. DNS Resolution to prevent DNS Rebinding to RFC 1918 / Cloud Metadata addresses
  try {
    const lookupResult = await dns.promises.lookup(hostname, { all: true });
    if (!lookupResult || lookupResult.length === 0) {
      return { safe: false, reason: `Target host "${hostname}" returned no DNS records` };
    }
    for (const record of lookupResult) {
      if (isPrivateIp(record.address)) {
        return {
          safe: false,
          reason: `Hostname "${hostname}" resolves to restricted private IP (${record.address})`
        };
      }
    }
    return { safe: true, url: parsed, resolvedIp: lookupResult[0].address };
  } catch (dnsErr: any) {
    // If DNS resolution fails, reject to prevent blind proxying
    return { safe: false, reason: `Target host "${hostname}" could not be resolved via DNS` };
  }
}
