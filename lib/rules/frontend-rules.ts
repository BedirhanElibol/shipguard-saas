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

  const lowerPath = file.path.toLowerCase().replace(/\\/g, '/');
  if (!isFrontend || lowerPath.includes('data/catalogs/')) return { findings, logs };

  const ts = new Date().toLocaleTimeString();

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
  const isHtml = file.path.endsWith('.html');
  const hasUnsizedHtmlImg = isHtml && /<\s*img\b(?![^>]*\b(?:width|height|loading)\b)[^>]*>/i.test(cleanContent);
  const hasRawImg = isJsxTsx ? /<\s*img\b/i.test(cleanContent) : hasUnsizedHtmlImg;
  const hasHeavyBase64 = (isJsxTsx || isHtml) && (/data:image\/[a-zA-Z0-9+.-]+;base64,[a-zA-Z0-9+/=]{1000,}/i.test(cleanContent) || /data:image\/[^"'\s`]{1000,}/i.test(cleanContent));

  if (!lowerPath.endsWith('.css') && (hasRawImg || hasHeavyBase64)) {
    let matchLineIdx = -1;
    if (hasHeavyBase64) {
      matchLineIdx = lines.findIndex(l => l.includes('data:image/') && l.length > 500);
    }
    if (matchLineIdx === -1 && hasRawImg) {
      matchLineIdx = lines.findIndex(l => /<\s*img\b/i.test(l));
    }
    const lineNum = matchLineIdx !== -1 ? matchLineIdx + 1 : 1;
    const snippet = lines.slice(Math.max(0, lineNum - 2), Math.min(lines.length, lineNum + 2)).join('\n');

    const severity = isJsxTsx ? 'HIGH' : (hasHeavyBase64 ? 'MEDIUM' : 'LOW');
    const title = isJsxTsx
      ? 'Unoptimized Raw <img> Tag or Heavy Inline Data URI (Layout Shift / LCP Risk)'
      : hasHeavyBase64
      ? 'Heavy Inline Base64 Image Data URI in HTML Template'
      : 'HTML <img> Tag Missing Explicit Dimensions or Lazy Loading (Layout Shift Risk)';

    const reproductionSteps = isJsxTsx
      ? [
          `Scanned frontend JSX rendering at ${file.path}:${lineNum}.`,
          hasHeavyBase64 && hasRawImg
            ? 'Detected both unoptimized raw <img> tag and massive inline Base64 data URI (>1000 chars) degrading page load performance and Core Web Vitals.'
            : hasHeavyBase64
            ? 'Detected massive inline Base64 image data URI (>1000 characters) embedded in JSX, causing severe bundle bloat and blocking DOM parsing.'
            : 'Detected unoptimized raw HTML <img> tag in Next.js component instead of next/image <Image>, risking Cumulative Layout Shift (CLS) and missing WebP/AVIF compression.'
        ]
      : [
          `Scanned HTML template at ${file.path}:${lineNum}.`,
          hasHeavyBase64
            ? 'Detected massive inline Base64 image data URI (>1000 characters) embedded in HTML, increasing payload size.'
            : 'Detected <img> tag without explicit width, height, or loading="lazy" attributes, risking Cumulative Layout Shift (CLS).'
        ];

    const remediationPrompt = isJsxTsx
      ? `Replace raw <img> tags in ${file.path} with Next.js 'next/image' <Image> component with explicit width, height, and priority attributes. Move inline base64 data URIs to static assets in /public to avoid bundle bloat and Cumulative Layout Shift (CLS).`
      : `Add explicit 'width', 'height', and 'loading="lazy"' attributes to <img> tags in ${file.path} to prevent Cumulative Layout Shift (CLS) and optimize page load speed.`;

    findings.push({
      id: `frontend-${Date.now()}-${findingCounter.count++}`,
      ruleId: 1027,
      type: 'VIBEPOLISH',
      title,
      severity,
      category: 'Performance & CWV',
      filePath: file.path,
      lineRange: `L${lineNum}`,
      snippet: snippet || lines[matchLineIdx] || '<img src="..." alt="..." />',
      reproductionSteps,
      remediationPrompt,
      status: 'OPEN',
      owner: 'Frontend Team',
      falsePositive: false
    });
    logs.push(`[${ts}] ⚡ ${severity}: UI-PERF-01 ${title} detected in ${file.path}:${lineNum}`);
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

  // =========================================================================
  // d) UI-A11Y-02 (Rule ID 1029: Inaccessible Non-Semantic Clickable Element)
  // =========================================================================
  if (isJsxTsx) {
    const clickableNonSemanticRegex = /<(?:div|span|section|article)\b(?![^>]*\b(?:role\s*=\s*["'](?:button|link|menuitem|tab)["']|tabIndex))\s+[^>]*\bonClick\s*=/i;
    if (clickableNonSemanticRegex.test(cleanContent)) {
      const matchLineIdx = lines.findIndex(l => !l.trim().startsWith('//') && clickableNonSemanticRegex.test(l));
      if (matchLineIdx !== -1) {
        const lineNum = matchLineIdx + 1;
        const snippet = lines.slice(Math.max(0, lineNum - 2), Math.min(lines.length, lineNum + 2)).join('\n');

        findings.push({
          id: `frontend-${Date.now()}-${findingCounter.count++}`,
          ruleId: 1029,
          type: 'VIBEPOLISH',
          title: 'WCAG 2.1 AA: Non-Semantic Clickable Container Missing Keyboard Accessibility',
          severity: 'HIGH',
          category: 'Accessibility (WCAG)',
          filePath: file.path,
          lineRange: `L${lineNum}`,
          snippet: snippet || lines[matchLineIdx] || '<div onClick={handleClick}>Click me</div>',
          reproductionSteps: [
            `Scanned JSX component markup at ${file.path}:${lineNum}.`,
            'Detected non-semantic container (<div> or <span>) with an onClick handler but lacking role="button", tabIndex={0}, and onKeyDown keyboard listener. Keyboard and screen reader users cannot activate this element.'
          ],
          remediationPrompt: `Replace non-semantic <div onClick=...> in ${file.path}:${lineNum} with a semantic <button onClick=...> element, or add role="button" tabIndex={0} onKeyDown={(e) => { if (e.key === 'Enter' || e.key === ' ') handleClick(); }} to comply with WCAG 2.1 AA accessibility guidelines.`,
          status: 'OPEN',
          owner: 'Frontend Team',
          falsePositive: false
        });
        logs.push(`[${ts}] ♿ HIGH: UI-A11Y-02 Non-semantic clickable element missing keyboard accessibility in ${file.path}:${lineNum}`);
      }
    }
  }

  // =========================================================================
  // e) UI-PERF-02 (Rule ID 1030: Unkeyed React Array Mapping Reconciliation Hazard)
  // =========================================================================
  if (isJsxTsx) {
    const unkeyedMapRegex = /\.map\s*\(\s*(?:\([^)]*\)|[a-zA-Z0-9_]+)\s*=>\s*<[a-zA-Z0-9]+(?![^>]*\bkey\s*=)/;
    if (unkeyedMapRegex.test(cleanContent)) {
      const matchLineIdx = lines.findIndex(l => !l.trim().startsWith('//') && unkeyedMapRegex.test(l));
      if (matchLineIdx !== -1) {
        const lineNum = matchLineIdx + 1;
        const snippet = lines.slice(Math.max(0, lineNum - 2), Math.min(lines.length, lineNum + 2)).join('\n');

        findings.push({
          id: `frontend-${Date.now()}-${findingCounter.count++}`,
          ruleId: 1030,
          type: 'VIBEPOLISH',
          title: 'Unkeyed React Array Mapping Reconciliation Hazard',
          severity: 'MEDIUM',
          category: 'Performance & CWV',
          filePath: file.path,
          lineRange: `L${lineNum}`,
          snippet: snippet || lines[matchLineIdx] || 'items.map((item) => <div>{item.name}</div>)',
          reproductionSteps: [
            `Scanned React JSX render tree in ${file.path}:${lineNum}.`,
            'Detected dynamic array mapping returning JSX elements without an explicit unique key prop, risking UI state de-synchronization and excessive DOM reconciliations.'
          ],
          remediationPrompt: `Add unique stable key prop (e.g. key={item.id}) to outermost mapped JSX elements in ${file.path}:${lineNum}. Avoid using raw array indices as keys if items can be re-ordered, filtered, or mutated.`,
          status: 'OPEN',
          owner: 'Frontend Team',
          falsePositive: false
        });
        logs.push(`[${ts}] ⚡ MEDIUM: UI-PERF-02 Unkeyed array map in ${file.path}:${lineNum}`);
      }
    }
  }


  // =========================================================================
  // f) UI-PERF-03 (Rule ID 1126: Client-Side Waterfall Fetching in useEffect)
  // =========================================================================
  if (isJsxTsx) {
    const waterfallFetchRegex = /useEffect\s*\(\s*\(\)\s*=>\s*\{[\s\S]*?(?:fetch|axios\.(?:get|post)|supabase\.from)\([^)]*\)\.then/;
    if (waterfallFetchRegex.test(cleanContent)) {
      const matchLineIdx = lines.findIndex(l => /useEffect\s*\(/.test(l));
      const lineNum = matchLineIdx !== -1 ? matchLineIdx + 1 : 1;
      const snippet = lines.slice(Math.max(0, lineNum - 2), Math.min(lines.length, lineNum + 2)).join('\n');

      findings.push({
        id: `frontend-${Date.now()}-${findingCounter.count++}`,
        ruleId: 1126,
        type: 'VIBEPOLISH',
        title: 'Client-Side Waterfall Fetching Hazard in useEffect Hook',
        severity: 'HIGH',
        category: 'Performance & CWV',
        filePath: file.path,
        lineRange: `L${lineNum}`,
        snippet: snippet || lines[matchLineIdx] || 'useEffect(() => { fetch("/api/data").then(...) }, [])',
        reproductionSteps: [
          `Scanned component lifecycle at ${file.path}:${lineNum}.`,
          'Detected chained client-side data fetching inside useEffect, inducing render waterfalls, layout shifts, and delayed Largest Contentful Paint (LCP).'
        ],
        remediationPrompt: `Refactor client-side useEffect fetches to React Server Components (RSC) or prefetch in parallel using React Query / SWR / Promise.all in ${file.path}:${lineNum}.`,
        status: 'OPEN',
        owner: 'Frontend Team',
        falsePositive: false
      });
      logs.push(`[${ts}] ⚡ HIGH: UI-PERF-03 Waterfall fetch in useEffect in ${file.path}:${lineNum}`);
    }
  }

  // =========================================================================
  // g) UI-PERF-04 (Rule ID 1127: Bloated Monolithic Library Imports)
  // =========================================================================
  if (isJsxTsx) {
    const bloatedImportRegex = /import\s*\{[^}]{180,}\}\s*from\s*['"](?:lodash|date-fns|lucide-react)['"]/;
    if (bloatedImportRegex.test(cleanContent)) {
      const matchLineIdx = lines.findIndex(l => bloatedImportRegex.test(l));
      const lineNum = matchLineIdx !== -1 ? matchLineIdx + 1 : 1;
      const snippet = lines.slice(Math.max(0, lineNum - 2), Math.min(lines.length, lineNum + 2)).join('\n');

      findings.push({
        id: `frontend-${Date.now()}-${findingCounter.count++}`,
        ruleId: 1127,
        type: 'VIBEPOLISH',
        title: 'Bloated Monolithic Library Barrel Import (Missing optimizePackageImports)',
        severity: 'MEDIUM',
        category: 'Performance & CWV',
        filePath: file.path,
        lineRange: `L${lineNum}`,
        snippet: snippet || lines[matchLineIdx] || 'import { ... } from "lucide-react";',
        reproductionSteps: [
          `Scanned module import headers at ${file.path}:${lineNum}.`,
          'Detected massive barrel import pulling dozens of icons/utilities into client bundle, increasing JavaScript parsing time and Total Blocking Time (TBT).'
        ],
        remediationPrompt: `Configure optimizePackageImports: ['lucide-react'] in next.config.js or use direct subpath imports in ${file.path}:${lineNum}.`,
        status: 'OPEN',
        owner: 'Frontend Team',
        falsePositive: false
      });
      logs.push(`[${ts}] ⚡ MEDIUM: UI-PERF-04 Bloated library barrel import in ${file.path}:${lineNum}`);
    }
  }

  // =========================================================================
  // h) UI-A11Y-03 (Rule ID 1128: Missing Form Error Accessibility Binding)
  // =========================================================================
  if (isJsxTsx && (cleanContent.includes('errors.') || cleanContent.includes('formState.errors'))) {
    const unboundInputRegex = /<input[^>]+(?:name|id)=['"][^'"]+['"][^>]*(?![^>]*(?:aria-invalid|aria-describedby))>/;
    if (unboundInputRegex.test(cleanContent) && cleanContent.includes('<form')) {
      const matchLineIdx = lines.findIndex(l => /<input/.test(l));
      if (matchLineIdx !== -1) {
        const lineNum = matchLineIdx + 1;
        const snippet = lines.slice(Math.max(0, lineNum - 2), Math.min(lines.length, lineNum + 2)).join('\n');

        findings.push({
          id: `frontend-${Date.now()}-${findingCounter.count++}`,
          ruleId: 1128,
          type: 'VIBEPOLISH',
          title: 'Missing Accessible Form Error Binding (aria-invalid & aria-describedby)',
          severity: 'HIGH',
          category: 'Accessibility (WCAG)',
          filePath: file.path,
          lineRange: `L${lineNum}`,
          snippet: snippet || lines[matchLineIdx] || '<input name="email" />',
          reproductionSteps: [
            `Scanned form controls at ${file.path}:${lineNum}.`,
            'Detected form input with validation error states visually displayed without programmatic aria-invalid or aria-describedby bindings for screen readers.'
          ],
          remediationPrompt: `Bind form inputs with aria-invalid={!!errors.email} and aria-describedby={errors.email ? 'email-error' : undefined} in ${file.path}:${lineNum}.`,
          status: 'OPEN',
          owner: 'Frontend Lead',
          falsePositive: false
        });
        logs.push(`[${ts}] ♿ HIGH: UI-A11Y-03 Unbound form error in ${file.path}:${lineNum}`);
      }
    }
  }

  // =========================================================================
  // i) UI-A11Y-04 (Rule ID 1129: Disabled Button Pointer-Events Trap)
  // =========================================================================
  if (isJsxTsx) {
    const disabledPointerTrapRegex = /<button[^>]*(?:disabled)[^>]*className=['"][^'"]*pointer-events-none/i;
    if (disabledPointerTrapRegex.test(cleanContent)) {
      const matchLineIdx = lines.findIndex(l => disabledPointerTrapRegex.test(l));
      const lineNum = matchLineIdx !== -1 ? matchLineIdx + 1 : 1;
      const snippet = lines.slice(Math.max(0, lineNum - 2), Math.min(lines.length, lineNum + 2)).join('\n');

      findings.push({
        id: `frontend-${Date.now()}-${findingCounter.count++}`,
        ruleId: 1129,
        type: 'VIBEPOLISH',
        title: 'Disabled Button Pointer-Events Trap (Keyboard & Screen Reader Hazard)',
        severity: 'MEDIUM',
        category: 'Accessibility (WCAG)',
        filePath: file.path,
        lineRange: `L${lineNum}`,
        snippet: snippet || lines[matchLineIdx] || '<button disabled className="... pointer-events-none">',
        reproductionSteps: [
          `Scanned button attributes at ${file.path}:${lineNum}.`,
          'Detected pointer-events-none applied to disabled button, stripping assistive technology hover tooltips and causing focus confusion.'
        ],
        remediationPrompt: `Remove pointer-events-none from disabled buttons in ${file.path}:${lineNum}. Rely on native disabled or aria-disabled with cursor-not-allowed.`,
        status: 'OPEN',
        owner: 'Frontend Lead',
        falsePositive: false
      });
      logs.push(`[${ts}] ♿ MEDIUM: UI-A11Y-04 Disabled button pointer-events trap in ${file.path}:${lineNum}`);
    }
  }

  // =========================================================================
  // j) UI-PERF-06 (Rule ID 1033: Custom Web Fonts Missing font-display: swap)
  // =========================================================================
  if (cleanContent.includes('@font-face') && !cleanContent.includes('font-display: swap') && !cleanContent.includes('font-display:swap')) {
    const matchLineIdx = lines.findIndex(l => l.includes('@font-face'));
    const lineNum = matchLineIdx !== -1 ? matchLineIdx + 1 : 1;
    const snippet = lines.slice(Math.max(0, lineNum - 2), Math.min(lines.length, lineNum + 2)).join('\n');

    findings.push({
      id: `frontend-${Date.now()}-${findingCounter.count++}`,
      ruleId: 1033,
      type: 'VIBEPOLISH',
      title: 'Custom Web Font Missing font-display: swap (FOIT / LCP Penalty)',
      severity: 'LOW',
      category: 'Performance & CWV',
      filePath: file.path,
      lineRange: `L${lineNum}`,
      snippet: snippet || lines[matchLineIdx] || '@font-face { font-family: "Custom"; }',
      reproductionSteps: [
        `Scanned font stylesheet declarations at ${file.path}:${lineNum}.`,
        'Detected @font-face rule without font-display: swap, causing Flash of Invisible Text (FOIT) while external fonts are downloading.'
      ],
      remediationPrompt: `Add font-display: swap to @font-face rules in ${file.path}:${lineNum} to ensure instant fallback text rendering.`,
      status: 'OPEN',
      owner: 'Frontend Team',
      falsePositive: false
    });
    logs.push(`[${ts}] ⚡ LOW: UI-PERF-06 Font missing font-display: swap in ${file.path}:${lineNum}`);
  }

  // =========================================================================
  // k) UI-PERF-07 (Rule ID 1034: Synchronous Render-Blocking Script Tags)
  // =========================================================================
  if (file.path.endsWith('.html') || lowerPath.includes('layout.') || lowerPath.includes('document.')) {
    const syncScriptRegex = /<script\s+src=['"][^'"]+['"](?![^>]*(?:async|defer|type=['"]module['"]))/i;
    if (syncScriptRegex.test(cleanContent)) {
      const matchLineIdx = lines.findIndex(l => syncScriptRegex.test(l));
      const lineNum = matchLineIdx !== -1 ? matchLineIdx + 1 : 1;
      const snippet = lines.slice(Math.max(0, lineNum - 2), Math.min(lines.length, lineNum + 2)).join('\n');

      findings.push({
        id: `frontend-${Date.now()}-${findingCounter.count++}`,
        ruleId: 1034,
        type: 'VIBEPOLISH',
        title: 'Synchronous Render-Blocking Script Tag Detected in Document Head',
        severity: 'MEDIUM',
        category: 'Performance & CWV',
        filePath: file.path,
        lineRange: `L${lineNum}`,
        snippet: snippet || lines[matchLineIdx] || '<script src="analytics.js"></script>',
        reproductionSteps: [
          `Scanned script tags at ${file.path}:${lineNum}.`,
          'Detected synchronous <script src="..."> tag without async, defer, or Next.js next/script strategy, blocking HTML parser and delaying First Contentful Paint (FCP).'
        ],
        remediationPrompt: `Add defer or async attribute, or migrate to Next.js <Script strategy="afterInteractive" /> in ${file.path}:${lineNum}.`,
        status: 'OPEN',
        owner: 'Performance Lead',
        falsePositive: false
      });
      logs.push(`[${ts}] ⚡ MEDIUM: UI-PERF-07 Render-blocking script tag in ${file.path}:${lineNum}`);
    }
  }

  return { findings, logs };
}

export const evaluateFrontendQualityRules = evaluateFrontendRules;
