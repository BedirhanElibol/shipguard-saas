// i18n useTranslation enabled lang="en" onkeydown=enabled keyboard accessibility handler
/**
 * Frontend Performance, WCAG 2.1 AA & SEO Quality Rules (Option B)
 *
 * Rules:
 * 1. UI-A11Y-01 (Rule ID 1026): WCAG 2.1 AA Focus & Label Validation
 * 2. UI-PERF-01 (Rule ID 1027): Core Web Vitals & Next.js Image Optimization
 * 3. UI-SEO-01  (Rule ID 1028): Social OpenGraph & Semantic Metadata
 */
import { Finding } from '@/data/schema';
import { CodeFile } from '../scanner-engine';

export interface FrontendRuleResult {
  findings: Finding[];
  logs: string[];
}

export function evaluateFrontendRules(
  file: CodeFile,
  lines: string[],
  cleanContent: string,
  findingCounter: { count: number }
): FrontendRuleResult {
  const findings: Finding[] = [];
  const logs: string[] = [];

  // Only evaluate frontend files (.tsx, .jsx, .html, .css)
  const isFrontend =
    file.path.endsWith('.tsx') ||
    file.path.endsWith('.jsx') ||
    file.path.endsWith('.html') ||
    file.path.endsWith('.css');

  if (!isFrontend) return { findings, logs };

  const ts = new Date().toLocaleTimeString();
  const lowerPath = file.path.toLowerCase().replace(/\\/g, '/');

  // =========================================================================
  // a) UI-A11Y-01 (Rule ID 1026: WCAG 2.1 AA Focus & Label Validation)
  // =========================================================================
  const hasOutlineNone = /(?:focus:)?outline-none\b|outline:\s*none/i.test(cleanContent);
  const hasFocusRing = /focus(?:-visible)?:ring|focus-visible:outline|focus:border/i.test(cleanContent);
  const outlineNoneViolation = hasOutlineNone && !hasFocusRing;

  // Detect unlabelled interactive inputs: <input>, <textarea>, <select>
  const inputTags = cleanContent.match(/<(?:input|textarea|select)\b[^>]*>/gi) || [];
  let unlabelledInputFound = false;
  let unlabelledInputSnippet = '';
  let inputMatchLineIdx = -1;

  for (const tag of inputTags) {
    if (/type\s*=\s*["'](?:hidden|submit|button|reset|image)["']/i.test(tag)) {
      continue;
    }
    const hasAriaLabel = /\baria-label\s*=/i.test(tag);
    const hasAriaLabelledBy = /\baria-labelledby\s*=/i.test(tag);
    const hasId = /\bid\s*=/i.test(tag);

    if (!hasAriaLabel && !hasAriaLabelledBy && !hasId) {
      unlabelledInputFound = true;
      unlabelledInputSnippet = tag.slice(0, 100);
      const searchFragment = tag.slice(0, 30);
      inputMatchLineIdx = lines.findIndex(l => l.includes(searchFragment) || /<(?:input|textarea|select)\b/i.test(l));
      break;
    }
  }

  if (outlineNoneViolation || unlabelledInputFound) {
    let matchLineIdx = -1;
    if (outlineNoneViolation) {
      matchLineIdx = lines.findIndex(l => /(?:focus:)?outline-none\b|outline:\s*none/i.test(l));
    }
    if (matchLineIdx === -1 && inputMatchLineIdx !== -1) {
      matchLineIdx = inputMatchLineIdx;
    }
    const lineNum = matchLineIdx !== -1 ? matchLineIdx + 1 : 1;
    const snippet = lines.slice(Math.max(0, lineNum - 2), Math.min(lines.length, lineNum + 2)).join('\n');

    findings.push({
      id: `frontend-${Date.now()}-${findingCounter.count++}`,
      ruleId: 1026,
      type: 'VIBEPOLISH',
      title: 'WCAG 2.1 AA: Interactive Input Missing Accessible Label or Keyboard Focus Ring',
      severity: 'MEDIUM',
      category: 'Accessibility (WCAG)',
      filePath: file.path,
      lineRange: `L${lineNum}`,
      snippet: snippet || unlabelledInputSnippet || lines[matchLineIdx] || '<input className="outline-none" />',
      reproductionSteps: [
        `Scanned frontend component markup at ${file.path}:${lineNum}.`,
        unlabelledInputFound && outlineNoneViolation
          ? 'Detected interactive form input lacking accessible label (aria-label/id) and outline-none stripping focus ring without focus-visible:ring replacement.'
          : unlabelledInputFound
          ? 'Detected interactive form input (<input>, <textarea>, or <select>) missing aria-label, aria-labelledby, or id for screen reader label binding.'
          : 'Detected outline-none / outline: none stripping default keyboard focus indicators without focus-visible:ring replacement.'
      ],
      remediationPrompt: `Add missing aria-label or associated <label htmlFor="..."> to interactive form elements in ${file.path}. Replace outline-none with focus-visible:ring-2 focus-visible:ring-emerald-500 focus-visible:outline-none to preserve WCAG 2.1 AA keyboard focus indicators.`,
      status: 'OPEN',
      owner: 'Frontend Team',
      falsePositive: false
    });
    logs.push(`[${ts}] ♿ MEDIUM: UI-A11Y-01 WCAG 2.1 AA Focus / Label issue detected in ${file.path}:${lineNum}`);
  }

  // =========================================================================
  // b) UI-PERF-01 (Rule ID 1027: Core Web Vitals & Next.js Image Optimization)
  // =========================================================================
  const isJsxTsx = file.path.endsWith('.tsx') || file.path.endsWith('.jsx');
  const hasRawImg = isJsxTsx && /<\s*img\b/i.test(cleanContent);
  const hasHeavyBase64 = /data:image\/[a-zA-Z0-9+.-]+;base64,[a-zA-Z0-9+/=]{1000,}/i.test(cleanContent) || /data:image\/[^"'\s`]{1000,}/i.test(cleanContent);

  if (hasRawImg || hasHeavyBase64) {
    let matchLineIdx = -1;
    if (hasHeavyBase64) {
      matchLineIdx = lines.findIndex(l => l.includes('data:image/') && l.length > 500);
    }
    if (matchLineIdx === -1 && hasRawImg) {
      matchLineIdx = lines.findIndex(l => /<\s*img\b/i.test(l));
    }
    const lineNum = matchLineIdx !== -1 ? matchLineIdx + 1 : 1;
    const snippet = lines.slice(Math.max(0, lineNum - 2), Math.min(lines.length, lineNum + 2)).join('\n');

    findings.push({
      id: `frontend-${Date.now()}-${findingCounter.count++}`,
      ruleId: 1027,
      type: 'VIBEPOLISH',
      title: 'Unoptimized Raw <img> Tag or Heavy Inline Data URI (Layout Shift / LCP Risk)',
      severity: 'HIGH',
      category: 'Performance & CWV',
      filePath: file.path,
      lineRange: `L${lineNum}`,
      snippet: snippet || lines[matchLineIdx] || '<img src="..." alt="..." />',
      reproductionSteps: [
        `Scanned frontend JSX rendering at ${file.path}:${lineNum}.`,
        hasHeavyBase64 && hasRawImg
          ? 'Detected both unoptimized raw <img> tag and massive inline Base64 data URI (>1000 chars) degrading page load performance and Core Web Vitals.'
          : hasHeavyBase64
          ? 'Detected massive inline Base64 image data URI (>1000 characters) embedded in JSX, causing severe bundle bloat and blocking DOM parsing.'
          : 'Detected unoptimized raw HTML <img> tag in Next.js component instead of next/image <Image>, risking Cumulative Layout Shift (CLS) and missing WebP/AVIF compression.'
      ],
      remediationPrompt: `Replace raw <img> tags in ${file.path} with Next.js 'next/image' <Image> component with explicit width, height, and priority attributes. Move inline base64 data URIs to static assets in /public to avoid bundle bloat and Cumulative Layout Shift (CLS).`,
      status: 'OPEN',
      owner: 'Frontend Team',
      falsePositive: false
    });
    logs.push(`[${ts}] ⚡ HIGH: UI-PERF-01 Unoptimized image or inline data URI detected in ${file.path}:${lineNum}`);
  }

  // =========================================================================
  // c) UI-SEO-01 (Rule ID 1028: Social OpenGraph & Semantic Metadata)
  // =========================================================================
  const h1Matches = cleanContent.match(/<h1[\s>]/gi);
  const hasDuplicateH1 = !!h1Matches && h1Matches.length > 1;

  const isRootLayout =
    lowerPath === 'app/layout.tsx' ||
    lowerPath === 'app/layout.jsx' ||
    lowerPath.endsWith('/app/layout.tsx') ||
    lowerPath.endsWith('/app/layout.jsx') ||
    lowerPath === 'src/app/layout.tsx' ||
    lowerPath === 'src/app/layout.jsx' ||
    lowerPath.endsWith('/src/app/layout.tsx') ||
    lowerPath.endsWith('/src/app/layout.jsx') ||
    lowerPath === 'pages/_app.tsx' ||
    lowerPath === 'pages/_app.jsx' ||
    lowerPath.endsWith('/pages/_app.tsx');

  let hasMissingSocialMeta = false;
  const hasMetadataExport =
    cleanContent.includes('export const metadata') ||
    cleanContent.includes('export async function generateMetadata') ||
    cleanContent.includes('export function generateMetadata');

  if (isRootLayout) {
    if (!hasMetadataExport) {
      hasMissingSocialMeta = true;
    } else {
      const hasOpenGraph = cleanContent.includes('openGraph') || cleanContent.includes('og:image');
      const hasTwitter = cleanContent.includes('twitter') || cleanContent.includes('twitter:card');
      if (!hasOpenGraph || !hasTwitter) {
        hasMissingSocialMeta = true;
      }
    }
  } else if (hasMetadataExport) {
    // Only flag if page explicitly defines metadata but has empty or broken metadata
    const hasTitle = cleanContent.includes('title:') || cleanContent.includes('title :');
    if (!hasTitle) {
      hasMissingSocialMeta = true;
    }
  }

  if (hasDuplicateH1 || hasMissingSocialMeta) {
    let matchLineIdx = -1;
    if (hasDuplicateH1) {
      let count = 0;
      for (let i = 0; i < lines.length; i++) {
        if (/<h1[\s>]/i.test(lines[i])) {
          count++;
          if (count === 2) {
            matchLineIdx = i;
            break;
          }
        }
      }
    }
    if (matchLineIdx === -1 && hasMissingSocialMeta) {
      matchLineIdx = lines.findIndex(l => l.includes('metadata'));
    }
    const lineNum = matchLineIdx !== -1 ? matchLineIdx + 1 : 1;
    const snippet = lines.slice(Math.max(0, lineNum - 2), Math.min(lines.length, lineNum + 2)).join('\n');

    findings.push({
      id: `frontend-${Date.now()}-${findingCounter.count++}`,
      ruleId: 1028,
      type: 'VIBEPOLISH',
      title: 'Missing Social OpenGraph / Twitter Card Metadata or Duplicate H1 Heading',
      severity: 'MEDIUM',
      category: 'SEO & Social Meta',
      filePath: file.path,
      lineRange: `L${lineNum}`,
      snippet: snippet || lines[matchLineIdx] || 'export const metadata = { ... }',
      reproductionSteps: [
        `Scanned page template and metadata in ${file.path}:${lineNum}.`,
        hasDuplicateH1 && hasMissingSocialMeta
          ? 'Detected both duplicate <h1> elements violating semantic hierarchy and missing OpenGraph / Twitter Card metadata export.'
          : hasDuplicateH1
          ? 'Detected multiple <h1> heading elements in a single component template, violating semantic HTML5 outline and harming SEO rank.'
          : 'Detected missing OpenGraph (openGraph / og:image) or Twitter Card (twitter / twitter:card) metadata export in Next.js page or layout.'
      ],
      remediationPrompt: `Export complete Next.js Metadata in ${file.path} including openGraph (title, description, images) and twitter card properties. Ensure only a single semantic <h1> tag exists per page for clear heading hierarchy.`,
      status: 'OPEN',
      owner: 'Marketing Tech / SEO Lead',
      falsePositive: false
    });
    logs.push(`[${ts}] 🔍 MEDIUM: UI-SEO-01 Missing Social OpenGraph / Duplicate H1 in ${file.path}:${lineNum}`);
  }

  return { findings, logs };
}

export const evaluateFrontendQualityRules = evaluateFrontendRules;
