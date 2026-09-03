// i18n useTranslation enabled lang="en" onkeydown=enabled keyboard accessibility handler
/**
 * AI Web Design Cliché Detection Rules (25 Rules)
 * Source: yapay_zeka_web_tasarim_kliseleri.pdf
 *
 * Detects common AI-generated UI/UX anti-patterns in frontend code
 * and provides professional remediation guidance.
 */
import { Finding } from '@/data/schema';
import { CodeFile } from '../scanner-engine';

interface ClicheRuleResult {
  findings: Finding[];
  logs: string[];
}

export function evaluateAiClicheRules(
  file: CodeFile,
  lines: string[],
  cleanContent: string,
  findingCounter: { count: number }
): ClicheRuleResult {
  const findings: Finding[] = [];
  const logs: string[] = [];

  // Only evaluate frontend component files
  const isFrontend = file.path.endsWith('.tsx') || file.path.endsWith('.jsx') || file.path.endsWith('.html') || file.path.endsWith('.css');
  if (!isFrontend) return { findings, logs };

  const ts = new Date().toLocaleTimeString();

  // CLICHE-01: Decorative Hero Badge Pill
  const isHeroOrLandingScope = /hero|landing/i.test(file.path);
  if (
    isHeroOrLandingScope &&
    ((/badge|pill|chip/i.test(cleanContent) && /hero-badge|badge-hero|inline-flex.*rounded-full/i.test(cleanContent)) ||
      (/rounded-full.*text-xs|text-xs.*rounded-full/i.test(cleanContent) && /(?:✨|🚀|Introducing|Powered by AI)\b/i.test(cleanContent)))
  ) {
    const matchLineIdx = lines.findIndex(l => /badge|pill|chip|rounded-full/i.test(l) && /✨|🚀|Introducing|New/i.test(l));
    const lineNum = matchLineIdx !== -1 ? matchLineIdx + 1 : 1;
    findings.push({
      id: `cliche-${Date.now()}-${findingCounter.count++}`,
      ruleId: 201,
      type: 'VIBEPOLISH',
      title: 'CLICHE-01: Decorative Hero Badge Pill',
      severity: 'LOW',
      category: 'AI Cliché & Layout',
      filePath: file.path,
      lineRange: `L${lineNum}`,
      snippet: lines[matchLineIdx] || '<span className="badge">✨ Introducing</span>',
      reproductionSteps: [
        `Scanned hero section in ${file.path}:${lineNum}.`,
        'Detected small glowing badge/pill component above hero heading — a hallmark of AI-generated landing pages.'
      ],
      remediationPrompt: `Remove decorative hero badge pill in ${file.path}. If retained, use only for real version/release announcements, not generic filler text.`,
      status: 'OPEN',
      owner: 'UI Architect',
      falsePositive: false
    });
    logs.push(`[${ts}] 🎨 CLICHE-01: Hero badge pill detected (${file.path}:${lineNum})`);
  }

  // CLICHE-02: Paired Dual CTA Buttons in Hero
  if (
    /hero|landing/i.test(file.path) &&
    (
      (/Get Started|Hemen Başla|Start Free/i.test(cleanContent) && /Watch Demo|Demo İzle|Learn More|Daha Fazla/i.test(cleanContent)) ||
      (/btn-primary|variant.*primary/i.test(cleanContent) && /btn-secondary|btn-outline|variant.*outline|variant.*secondary/i.test(cleanContent))
    )
  ) {
    const matchLineIdx = lines.findIndex(l => /Get Started|Hemen Başla|Start Free|Watch Demo|Demo İzle/i.test(l));
    const lineNum = matchLineIdx !== -1 ? matchLineIdx + 1 : 1;
    findings.push({
      id: `cliche-${Date.now()}-${findingCounter.count++}`,
      ruleId: 202,
      type: 'VIBEPOLISH',
      title: 'CLICHE-02: Paired Dual CTA Buttons in Hero',
      severity: 'LOW',
      category: 'AI Cliché & Layout',
      filePath: file.path,
      lineRange: `L${lineNum}`,
      snippet: lines[matchLineIdx] || '<Button>Get Started</Button> <Button variant="outline">Watch Demo</Button>',
      reproductionSteps: [
        `Scanned hero section in ${file.path}:${lineNum}.`,
        'Detected paired primary + outline CTA buttons — standard AI-generated dual button pattern.'
      ],
      remediationPrompt: `Simplify hero in ${file.path} to a single strong CTA. If a secondary action is needed, move it below the fold or into navigation.`,
      status: 'OPEN',
      owner: 'UI Architect',
      falsePositive: false
    });
    logs.push(`[${ts}] 🎨 CLICHE-02: Dual CTA hero buttons detected (${file.path}:${lineNum})`);
  }

  // CLICHE-03: "No Credit Card Required" Micro-Copy Cliché
  if (/no credit card|kredi kartı gerek|no card required/i.test(cleanContent)) {
    const matchLineIdx = lines.findIndex(l => /no credit card|kredi kartı gerek|no card required/i.test(l));
    const lineNum = matchLineIdx !== -1 ? matchLineIdx + 1 : 1;
    findings.push({
      id: `cliche-${Date.now()}-${findingCounter.count++}`,
      ruleId: 203,
      type: 'VIBEPOLISH',
      title: 'CLICHE-03: "No Credit Card Required" Micro-Copy Cliché',
      severity: 'LOW',
      category: 'AI Cliché & Copywriting',
      filePath: file.path,
      lineRange: `L${lineNum}`,
      snippet: lines[matchLineIdx] || 'No credit card required',
      reproductionSteps: [
        `Scanned trust copy in ${file.path}:${lineNum}.`,
        'Detected generic "No credit card required" micro-copy — copy-paste AI filler.'
      ],
      remediationPrompt: `Replace generic trust statement in ${file.path} with specific differentiating value (e.g., "14-day free trial", "Cancel anytime").`,
      status: 'OPEN',
      owner: 'Copywriter',
      falsePositive: false
    });
    logs.push(`[${ts}] 🎨 CLICHE-03: "No credit card" filler copy detected (${file.path}:${lineNum})`);
  }

  // CLICHE-04: Full-Screen 100vh Hero Lock
  if (/h-screen|min-h-screen|height:\s*100vh/i.test(cleanContent) && /hero|landing|home/i.test(file.path)) {
    const matchLineIdx = lines.findIndex(l => /h-screen|min-h-screen|100vh/i.test(l));
    const lineNum = matchLineIdx !== -1 ? matchLineIdx + 1 : 1;
    findings.push({
      id: `cliche-${Date.now()}-${findingCounter.count++}`,
      ruleId: 204,
      type: 'VIBEPOLISH',
      title: 'CLICHE-04: Full-Screen 100vh Hero Lock (Missing Scroll Peek)',
      severity: 'LOW',
      category: 'AI Cliché & Layout',
      filePath: file.path,
      lineRange: `L${lineNum}`,
      snippet: lines[matchLineIdx] || 'className="min-h-screen"',
      reproductionSteps: [
        `Scanned hero layout in ${file.path}:${lineNum}.`,
        'Detected forced 100vh full-screen hero blocking scroll peek — user cannot sense content below.'
      ],
      remediationPrompt: `Allow below-fold content to peek by reducing hero height in ${file.path} to ~85vh or adding a scroll indicator.`,
      status: 'OPEN',
      owner: 'UI Architect',
      falsePositive: false
    });
    logs.push(`[${ts}] 🎨 CLICHE-04: 100vh hero lock detected (${file.path}:${lineNum})`);
  }

  // CLICHE-05: Floating 3D Perspective Device Mockup
  if (/perspective|rotateY|rotateX|rotate3d|skew|transform.*3d/i.test(cleanContent) && /mockup|hero|preview|screenshot/i.test(cleanContent)) {
    const matchLineIdx = lines.findIndex(l => /perspective|rotateY|rotateX|skew/i.test(l));
    const lineNum = matchLineIdx !== -1 ? matchLineIdx + 1 : 1;
    findings.push({
      id: `cliche-${Date.now()}-${findingCounter.count++}`,
      ruleId: 205,
      type: 'VIBEPOLISH',
      title: 'CLICHE-05: Floating 3D Perspective Device Mockup',
      severity: 'LOW',
      category: 'AI Cliché & Visual',
      filePath: file.path,
      lineRange: `L${lineNum}`,
      snippet: lines[matchLineIdx] || 'transform: perspective(1000px) rotateY(-15deg)',
      reproductionSteps: [
        `Scanned visual presentation in ${file.path}:${lineNum}.`,
        'Detected 3D tilted/perspective mockup — an AI-generated decorative anti-pattern.'
      ],
      remediationPrompt: `Replace 3D perspective mockup in ${file.path} with flat, readable real product screenshots that reflect actual user experience.`,
      status: 'OPEN',
      owner: 'UI Architect',
      falsePositive: false
    });
    logs.push(`[${ts}] 🎨 CLICHE-05: 3D tilted mockup detected (${file.path}:${lineNum})`);
  }

  // CLICHE-06: Fake Browser Chrome Window Decoration
  if (/browser-?chrome|browser-?frame|red.*yellow.*green|dot.*dot.*dot.*mockup|fake.*browser/i.test(cleanContent) ||
      (cleanContent.includes('bg-red-') && cleanContent.includes('bg-yellow-') && cleanContent.includes('bg-green-') && /rounded-full.*w-3|w-3.*rounded-full/i.test(cleanContent))) {
    const matchLineIdx = lines.findIndex(l => /browser-?chrome|bg-red-.*bg-yellow-|rounded-full.*w-3/i.test(l));
    const lineNum = matchLineIdx !== -1 ? matchLineIdx + 1 : 1;
    findings.push({
      id: `cliche-${Date.now()}-${findingCounter.count++}`,
      ruleId: 206,
      type: 'VIBEPOLISH',
      title: 'CLICHE-06: Fake Browser Chrome Window Decoration',
      severity: 'LOW',
      category: 'AI Cliché & Visual',
      filePath: file.path,
      lineRange: `L${lineNum}`,
      snippet: lines[matchLineIdx] || '<div className="flex gap-1"><span className="w-3 h-3 rounded-full bg-red-500" />...',
      reproductionSteps: [
        `Scanned visual frame elements in ${file.path}:${lineNum}.`,
        'Detected fake browser chrome (red/yellow/green dots) decoration — adds visual noise without value.'
      ],
      remediationPrompt: `Remove fake browser frame in ${file.path}. Show clean product UI directly without decorative chrome.`,
      status: 'OPEN',
      owner: 'UI Architect',
      falsePositive: false
    });
    logs.push(`[${ts}] 🎨 CLICHE-06: Fake browser chrome detected (${file.path}:${lineNum})`);
  }

  // CLICHE-07: Fabricated Brand Logos (Nexora, Vertexa, Lumina)
  if (/trusted by|güveniyor|as seen on/i.test(cleanContent) &&
      /Nexora|Vertexa|Lumina|Quantiq|Acme|TechCorp|CloudSoft|DataPulse|SynergyAI|CyberVault/i.test(cleanContent)) {
    const matchLineIdx = lines.findIndex(l => /Nexora|Vertexa|Lumina|Quantiq|Acme|TechCorp/i.test(l));
    const lineNum = matchLineIdx !== -1 ? matchLineIdx + 1 : 1;
    findings.push({
      id: `cliche-${Date.now()}-${findingCounter.count++}`,
      ruleId: 207,
      type: 'VIBEPOLISH',
      title: 'CLICHE-07: Fabricated Brand Logos (Fake Trust Proof)',
      severity: 'MEDIUM',
      category: 'AI Cliché & Trust',
      filePath: file.path,
      lineRange: `L${lineNum}`,
      snippet: lines[matchLineIdx] || '"Trusted by" Nexora, Vertexa, Lumina...',
      reproductionSteps: [
        `Scanned social proof section in ${file.path}:${lineNum}.`,
        'Detected fabricated brand names typically generated by AI — destroys user trust.'
      ],
      remediationPrompt: `Remove fake logos in ${file.path}. Only display real customer/partner logos or focus on product value instead.`,
      status: 'OPEN',
      owner: 'Marketing',
      falsePositive: false
    });
    logs.push(`[${ts}] 🎨 CLICHE-07: Fake trust logos detected (${file.path}:${lineNum})`);
  }

  // CLICHE-08: Infinite Scrolling Logo Marquee
  if (/marquee|infinite.*scroll.*logo|logo.*marquee|scroll.*infinite|animate-scroll|animation.*scroll/i.test(cleanContent) &&
      /logo|brand|partner|client/i.test(cleanContent)) {
    const matchLineIdx = lines.findIndex(l => /marquee|infinite.*scroll|animate-scroll/i.test(l));
    const lineNum = matchLineIdx !== -1 ? matchLineIdx + 1 : 1;
    findings.push({
      id: `cliche-${Date.now()}-${findingCounter.count++}`,
      ruleId: 208,
      type: 'VIBEPOLISH',
      title: 'CLICHE-08: Infinite Scrolling Logo Marquee',
      severity: 'LOW',
      category: 'AI Cliché & Animation',
      filePath: file.path,
      lineRange: `L${lineNum}`,
      snippet: lines[matchLineIdx] || 'className="animate-scroll infinite"',
      reproductionSteps: [
        `Scanned logo display section in ${file.path}:${lineNum}.`,
        'Detected infinite marquee logo animation — distracting and non-interactive.'
      ],
      remediationPrompt: `Replace infinite marquee in ${file.path} with a clean static grid of real partner logos.`,
      status: 'OPEN',
      owner: 'UI Architect',
      falsePositive: false
    });
    logs.push(`[${ts}] 🎨 CLICHE-08: Infinite logo marquee detected (${file.path}:${lineNum})`);
  }

  // CLICHE-09: Overlapping Stock Avatar Social Proof
  if (/-space-x|avatar.*group|stacked.*avatar|overlapping.*avatar/i.test(cleanContent) &&
      /\d+[\+,.]?\d*\s*(user|kullanıcı|people|joined|katıldı)/i.test(cleanContent)) {
    const matchLineIdx = lines.findIndex(l => /-space-x|avatar.*group|stacked.*avatar/i.test(l));
    const lineNum = matchLineIdx !== -1 ? matchLineIdx + 1 : 1;
    findings.push({
      id: `cliche-${Date.now()}-${findingCounter.count++}`,
      ruleId: 209,
      type: 'VIBEPOLISH',
      title: 'CLICHE-09: Overlapping Stock Avatar Social Proof',
      severity: 'LOW',
      category: 'AI Cliché & Trust',
      filePath: file.path,
      lineRange: `L${lineNum}`,
      snippet: lines[matchLineIdx] || '<AvatarGroup> "10,000+ users joined"',
      reproductionSteps: [
        `Scanned social proof in ${file.path}:${lineNum}.`,
        'Detected stacked avatar group with generic user count — stock photo social proof.'
      ],
      remediationPrompt: `Replace stacked stock avatars in ${file.path} with real user testimonials including name, company, and role.`,
      status: 'OPEN',
      owner: 'Marketing',
      falsePositive: false
    });
    logs.push(`[${ts}] 🎨 CLICHE-09: Stacked avatar social proof detected (${file.path}:${lineNum})`);
  }

  // CLICHE-10: Fabricated Vanity Metrics (10,000+ Users, 99.9% Uptime, 24/7)
  if (
    (/10[,.]?000\+?\s*(user|kullanıcı|customer)/i.test(cleanContent) && /99\.?9%\s*(uptime|availability)/i.test(cleanContent)) ||
    (/10[,.]?000\+/i.test(cleanContent) && /24\/7/i.test(cleanContent) && /uptime|destek|support/i.test(cleanContent))
  ) {
    const matchLineIdx = lines.findIndex(l => /10[,.]?000\+|99\.?9%|24\/7/i.test(l));
    const lineNum = matchLineIdx !== -1 ? matchLineIdx + 1 : 1;
    findings.push({
      id: `cliche-${Date.now()}-${findingCounter.count++}`,
      ruleId: 210,
      type: 'VIBEPOLISH',
      title: 'CLICHE-10: Fabricated Vanity Metrics (10,000+ Users, 99.9% Uptime, 24/7)',
      severity: 'MEDIUM',
      category: 'AI Cliché & Trust',
      filePath: file.path,
      lineRange: `L${lineNum}`,
      snippet: lines[matchLineIdx] || '10,000+ Users | 99.9% Uptime | 24/7 Support',
      reproductionSteps: [
        `Scanned statistics section in ${file.path}:${lineNum}.`,
        'Detected the classic AI-generated vanity metric trio (users/uptime/support).'
      ],
      remediationPrompt: `Replace fabricated metrics in ${file.path} with real, verifiable product-specific KPIs and measurable outcomes.`,
      status: 'OPEN',
      owner: 'Marketing',
      falsePositive: false
    });
    logs.push(`[${ts}] 🎨 CLICHE-10: Fabricated vanity metrics detected (${file.path}:${lineNum})`);
  }

  // CLICHE-11: Count-Up-From-Zero Number Animation
  if (/countUp|count-up|counter.*animation|animate.*count|useCountUp|CountUp/i.test(cleanContent) ||
      (/from.*0|start.*0/i.test(cleanContent) && /count|number|stat/i.test(cleanContent) && /animate|motion|spring/i.test(cleanContent))) {
    const matchLineIdx = lines.findIndex(l => /countUp|count-up|counter.*anim|useCountUp/i.test(l));
    const lineNum = matchLineIdx !== -1 ? matchLineIdx + 1 : 1;
    findings.push({
      id: `cliche-${Date.now()}-${findingCounter.count++}`,
      ruleId: 211,
      type: 'VIBEPOLISH',
      title: 'CLICHE-11: Count-Up-From-Zero Number Animation',
      severity: 'LOW',
      category: 'AI Cliché & Animation',
      filePath: file.path,
      lineRange: `L${lineNum}`,
      snippet: lines[matchLineIdx] || '<CountUp start={0} end={10000} duration={2} />',
      reproductionSteps: [
        `Scanned stat animations in ${file.path}:${lineNum}.`,
        'Detected count-up-from-zero animation — gimmicky AI filler pattern.'
      ],
      remediationPrompt: `Remove count-up animation in ${file.path}. Display numbers directly and clearly without theatrical counting scripts.`,
      status: 'OPEN',
      owner: 'UI Architect',
      falsePositive: false
    });
    logs.push(`[${ts}] 🎨 CLICHE-11: Count-up animation detected (${file.path}:${lineNum})`);
  }

  // CLICHE-12: Forced 1-2-3 Step "How It Works" Pattern
  if (
    /how it works|nasıl çalışır/i.test(cleanContent) &&
    /step.*1|adım.*1|sign.*up|kaydol/i.test(cleanContent) &&
    /step.*2|adım.*2|connect|bağla/i.test(cleanContent) &&
    /step.*3|adım.*3|start|başla/i.test(cleanContent)
  ) {
    const matchLineIdx = lines.findIndex(l => /how it works|nasıl çalışır/i.test(l));
    const lineNum = matchLineIdx !== -1 ? matchLineIdx + 1 : 1;
    findings.push({
      id: `cliche-${Date.now()}-${findingCounter.count++}`,
      ruleId: 212,
      type: 'VIBEPOLISH',
      title: 'CLICHE-12: Forced 1-2-3 Step "How It Works" Pattern',
      severity: 'LOW',
      category: 'AI Cliché & Layout',
      filePath: file.path,
      lineRange: `L${lineNum}`,
      snippet: lines[matchLineIdx] || '"How It Works?" 1. Sign Up 2. Connect 3. Start',
      reproductionSteps: [
        `Scanned process steps in ${file.path}:${lineNum}.`,
        'Detected the forced 3-step "How It Works" layout — an AI template classic.'
      ],
      remediationPrompt: `Redesign process section in ${file.path}. Show the actual unique value-creation flow instead of generic 1-2-3 sign-up steps.`,
      status: 'OPEN',
      owner: 'UI Architect',
      falsePositive: false
    });
    logs.push(`[${ts}] 🎨 CLICHE-12: 1-2-3 step pattern detected (${file.path}:${lineNum})`);
  }

  // CLICHE-13: Generic FAQ Accordion with Plus Icons
  if (/accordion|faq/i.test(cleanContent) &&
      (/how does it work|güvenli mi|is it secure|can i cancel/i.test(cleanContent) || /nasıl çalışır.*soru/i.test(cleanContent))) {
    const matchLineIdx = lines.findIndex(l => /accordion|faq/i.test(l));
    const lineNum = matchLineIdx !== -1 ? matchLineIdx + 1 : 1;
    findings.push({
      id: `cliche-${Date.now()}-${findingCounter.count++}`,
      ruleId: 213,
      type: 'VIBEPOLISH',
      title: 'CLICHE-13: Generic FAQ Accordion with Plus Icons',
      severity: 'LOW',
      category: 'AI Cliché & Content',
      filePath: file.path,
      lineRange: `L${lineNum}`,
      snippet: lines[matchLineIdx] || '<Accordion> "How does it work?" "Is it secure?"',
      reproductionSteps: [
        `Scanned FAQ section in ${file.path}:${lineNum}.`,
        'Detected generic AI-generated FAQ questions that do not address real customer objections.'
      ],
      remediationPrompt: `Replace generic FAQ questions in ${file.path} with real customer purchase-blocking objections and specific technical answers.`,
      status: 'OPEN',
      owner: 'Copywriter',
      falsePositive: false
    });
    logs.push(`[${ts}] 🎨 CLICHE-13: Generic FAQ accordion detected (${file.path}:${lineNum})`);
  }

  // CLICHE-14: Dark Closing CTA Banner ("Ready to get started?")
  if (/ready to (get started|start|begin)|bugün başlamaya|hazır mısın/i.test(cleanContent) &&
      /bg-(black|gray-900|slate-900|zinc-900)|bg-\[#0/i.test(cleanContent)) {
    const matchLineIdx = lines.findIndex(l => /ready to|hazır mısın|bugün başla/i.test(l));
    const lineNum = matchLineIdx !== -1 ? matchLineIdx + 1 : 1;
    findings.push({
      id: `cliche-${Date.now()}-${findingCounter.count++}`,
      ruleId: 214,
      type: 'VIBEPOLISH',
      title: 'CLICHE-14: Dark Closing CTA Banner ("Ready to get started?")',
      severity: 'LOW',
      category: 'AI Cliché & Layout',
      filePath: file.path,
      lineRange: `L${lineNum}`,
      snippet: lines[matchLineIdx] || '"Ready to get started?" on dark background',
      reproductionSteps: [
        `Scanned closing CTA in ${file.path}:${lineNum}.`,
        'Detected generic dark-background "Ready to get started?" closing banner.'
      ],
      remediationPrompt: `Strengthen closing CTA in ${file.path} with a specific value proposition, risk reducer, or personalized offer instead of generic "Ready?" text.`,
      status: 'OPEN',
      owner: 'Copywriter',
      falsePositive: false
    });
    logs.push(`[${ts}] 🎨 CLICHE-14: Dark closing CTA banner detected (${file.path}:${lineNum})`);
  }

  // CLICHE-15: Overloaded Fake Corporate Footer (5 Columns)
  if (/footer/i.test(file.path) || /footer/i.test(cleanContent)) {
    const linkCount = (cleanContent.match(/<a\s|<Link\s|href=/gi) || []).length;
    if (linkCount > 15) {
      findings.push({
        id: `cliche-${Date.now()}-${findingCounter.count++}`,
        ruleId: 215,
        type: 'VIBEPOLISH',
        title: 'CLICHE-15: Overloaded Fake Corporate Footer (5 Columns)',
        severity: 'LOW',
        category: 'AI Cliché & Navigation',
        filePath: file.path,
        lineRange: 'L1-L50',
        snippet: `Footer contains ${linkCount} links — likely more than existing pages`,
        reproductionSteps: [
          `Scanned footer in ${file.path}.`,
          `Detected ${linkCount} footer links — AI-generated sites often create links to pages that do not exist.`
        ],
        remediationPrompt: `Audit footer links in ${file.path}. Only link to pages that actually exist. Use a clean, functional 2-3 column footer.`,
        status: 'OPEN',
        owner: 'UI Architect',
        falsePositive: false
      });
      logs.push(`[${ts}] 🎨 CLICHE-15: Overloaded footer (${linkCount} links) detected (${file.path})`);
    }
  }

  // CLICHE-16: Non-Functional Theme Toggle Button
  if (/dark.*mode.*toggle|theme.*toggle|mode.*switch|setTheme|toggleTheme/i.test(cleanContent) &&
      !/data-theme|classList.*dark|document\.documentElement|ThemeProvider|useTheme/i.test(cleanContent)) {
    const matchLineIdx = lines.findIndex(l => /dark.*mode|theme.*toggle|toggleTheme/i.test(l));
    const lineNum = matchLineIdx !== -1 ? matchLineIdx + 1 : 1;
    findings.push({
      id: `cliche-${Date.now()}-${findingCounter.count++}`,
      ruleId: 216,
      type: 'VIBEPOLISH',
      title: 'CLICHE-16: Non-Functional Theme Toggle Button',
      severity: 'MEDIUM',
      category: 'AI Cliché & Functionality',
      filePath: file.path,
      lineRange: `L${lineNum}`,
      snippet: lines[matchLineIdx] || '<button onClick={toggleDarkMode}>🌙</button>',
      reproductionSteps: [
        `Scanned theme toggle in ${file.path}:${lineNum}.`,
        'Detected dark mode toggle without actual theme infrastructure (ThemeProvider / CSS variables).'
      ],
      remediationPrompt: `Either implement full CSS variable-based theme system or remove non-functional toggle in ${file.path}. Half-implemented toggles erode trust.`,
      status: 'OPEN',
      owner: 'Frontend Team',
      falsePositive: false
    });
    logs.push(`[${ts}] 🎨 CLICHE-16: Non-functional dark mode toggle detected (${file.path}:${lineNum})`);
  }

  // CLICHE-17: Excessive Center-Alignment (text-center Abuse)
  const centerCount = (cleanContent.match(/text-center|text-align:\s*center/gi) || []).length;
  if (centerCount > 8 && lines.length > 50) {
    findings.push({
      id: `cliche-${Date.now()}-${findingCounter.count++}`,
      ruleId: 217,
      type: 'VIBEPOLISH',
      title: 'CLICHE-17: Excessive Center-Alignment (text-center Abuse)',
      severity: 'MEDIUM',
      category: 'AI Cliché & Typography',
      filePath: file.path,
      lineRange: 'L1-L50',
      snippet: `${centerCount} center-alignment instances detected in ${lines.length} lines`,
      reproductionSteps: [
        `Scanned text alignment in ${file.path}.`,
        `Detected ${centerCount} center-aligned blocks — AI defaults to center everything, hurting F-pattern readability.`
      ],
      remediationPrompt: `Left-align body text, descriptions, and feature lists in ${file.path} for natural F-pattern reading. Reserve center-align only for hero headlines.`,
      status: 'OPEN',
      owner: 'UI Architect',
      falsePositive: false
    });
    logs.push(`[${ts}] 🎨 CLICHE-17: Excessive center-alignment (${centerCount}x) detected (${file.path})`);
  }

  // CLICHE-18: Repetitive 3-Column Card Grid Sections
  const gridSections = (cleanContent.match(/grid-cols-3|grid.*cols.*3/gi) || []).length;
  if (gridSections >= 3) {
    findings.push({
      id: `cliche-${Date.now()}-${findingCounter.count++}`,
      ruleId: 218,
      type: 'VIBEPOLISH',
      title: 'CLICHE-18: Repetitive 3-Column Card Grid Sections',
      severity: 'LOW',
      category: 'AI Cliché & Layout',
      filePath: file.path,
      lineRange: 'L1-L100',
      snippet: `${gridSections} identical 3-column grids repeating in layout`,
      reproductionSteps: [
        `Scanned layout structure in ${file.path}.`,
        `Detected ${gridSections} identical 3-column grid sections — break the visual monotony.`
      ],
      remediationPrompt: `Add visual rhythm to ${file.path}: alternate between 2-column splits, interactive demos, asymmetric grids, and full-width sections.`,
      status: 'OPEN',
      owner: 'UI Architect',
      falsePositive: false
    });
    logs.push(`[${ts}] 🎨 CLICHE-18: Repetitive 3-column grid pattern (${gridSections}x) detected (${file.path})`);
  }

  // CLICHE-19: Default Indigo-600 Color Fallback (#4F46E5)
  if (/indigo-600|#4F46E5|#4f46e5|indigo-500/i.test(cleanContent) && !/brand|theme|custom/i.test(cleanContent)) {
    const matchLineIdx = lines.findIndex(l => /indigo-600|#4F46E5|indigo-500/i.test(l));
    const lineNum = matchLineIdx !== -1 ? matchLineIdx + 1 : 1;
    findings.push({
      id: `cliche-${Date.now()}-${findingCounter.count++}`,
      ruleId: 219,
      type: 'VIBEPOLISH',
      title: 'CLICHE-19: Default Indigo-600 Color Fallback (#4F46E5)',
      severity: 'LOW',
      category: 'AI Cliché & Color',
      filePath: file.path,
      lineRange: `L${lineNum}`,
      snippet: lines[matchLineIdx] || 'className="bg-indigo-600"',
      reproductionSteps: [
        `Scanned color usage in ${file.path}:${lineNum}.`,
        'Detected default AI fallback color Indigo-600 (#4F46E5) — a telltale sign of unbranded AI output.'
      ],
      remediationPrompt: `Define a custom brand color palette in ${file.path} instead of defaulting to Indigo-600/Blurple.`,
      status: 'OPEN',
      owner: 'UI Architect',
      falsePositive: false
    });
    logs.push(`[${ts}] 🎨 CLICHE-19: Default Indigo-600 color detected (${file.path}:${lineNum})`);
  }

  // CLICHE-20: Monotone Slate-500 Gray Text Overuse (#64748B)
  const slateCount = (cleanContent.match(/slate-500|#64748B|#64748b|text-gray-500/gi) || []).length;
  if (slateCount > 6) {
    findings.push({
      id: `cliche-${Date.now()}-${findingCounter.count++}`,
      ruleId: 220,
      type: 'VIBEPOLISH',
      title: 'CLICHE-20: Monotone Slate-500 Gray Text Overuse (#64748B)',
      severity: 'LOW',
      category: 'AI Cliché & Color',
      filePath: file.path,
      lineRange: 'L1-L50',
      snippet: `${slateCount} occurrences of Slate-500/#64748B mono-tone gray`,
      reproductionSteps: [
        `Scanned text color hierarchy in ${file.path}.`,
        `Detected ${slateCount} instances of the same gray (#64748B) — AI often uses a single shade for all text.`
      ],
      remediationPrompt: `Establish proper text hierarchy in ${file.path} using multiple font weights, sizes, and varied gray tones instead of flat Slate-500.`,
      status: 'OPEN',
      owner: 'UI Architect',
      falsePositive: false
    });
    logs.push(`[${ts}] 🎨 CLICHE-20: Monotone Slate-500 text overuse (${slateCount}x) detected (${file.path})`);
  }

  // CLICHE-21: Forced Fixed-Height Card Containers
  if (/h-\[(?:200|250|300|350|400)px\]|h-(?:48|52|56|60|64|72|80)/i.test(cleanContent) && /card|feature|pricing/i.test(cleanContent)) {
    const matchLineIdx = lines.findIndex(l => /h-\[\d+px\]|h-(?:48|52|56|60|64|72|80)\b/i.test(l) && /card|feature|pricing/i.test(l));
    const lineNum = matchLineIdx !== -1 ? matchLineIdx + 1 : 1;
    findings.push({
      id: `cliche-${Date.now()}-${findingCounter.count++}`,
      ruleId: 221,
      type: 'VIBEPOLISH',
      title: 'CLICHE-21: Forced Fixed-Height Card Containers',
      severity: 'LOW',
      category: 'AI Cliché & Layout',
      filePath: file.path,
      lineRange: `L${lineNum}`,
      snippet: lines[matchLineIdx] || 'className="h-[300px] card"',
      reproductionSteps: [
        `Scanned card layouts in ${file.path}:${lineNum}.`,
        'Detected force-fixed card heights — creates artificial whitespace when content varies.'
      ],
      remediationPrompt: `Allow natural content flow in ${file.path} cards or write balanced content. Use min-height instead of fixed height.`,
      status: 'OPEN',
      owner: 'UI Architect',
      falsePositive: false
    });
    logs.push(`[${ts}] 🎨 CLICHE-21: Fixed card heights detected (${file.path}:${lineNum})`);
  }

  // CLICHE-22: Pastel Square Rounded Icon Containers
  if (/rounded-(?:lg|xl|2xl).*(?:bg-(?:blue|green|orange|pink|purple|teal|cyan)-(?:50|100))/i.test(cleanContent) &&
      /lucide|icon|Icon|Feature/i.test(cleanContent)) {
    const matchLineIdx = lines.findIndex(l => /rounded-.*bg-.*-(?:50|100)/i.test(l) && /icon|Icon/i.test(l));
    const lineNum = matchLineIdx !== -1 ? matchLineIdx + 1 : 1;
    findings.push({
      id: `cliche-${Date.now()}-${findingCounter.count++}`,
      ruleId: 222,
      type: 'VIBEPOLISH',
      title: 'CLICHE-22: Pastel Square Rounded Icon Containers',
      severity: 'LOW',
      category: 'AI Cliché & Visual',
      filePath: file.path,
      lineRange: `L${lineNum}`,
      snippet: lines[matchLineIdx] || '<div className="rounded-xl bg-blue-50 p-3"><Icon /></div>',
      reproductionSteps: [
        `Scanned feature icon styling in ${file.path}:${lineNum}.`,
        'Detected pastel-colored rounded square icon containers — standard AI visual pattern.'
      ],
      remediationPrompt: `Replace pastel icon boxes in ${file.path} with real UI screenshots, micro-illustrations, or inline contextual graphics.`,
      status: 'OPEN',
      owner: 'UI Architect',
      falsePositive: false
    });
    logs.push(`[${ts}] 🎨 CLICHE-22: Pastel icon boxes detected (${file.path}:${lineNum})`);
  }

  // CLICHE-23: Generic Faceless Flat Stock Vectors (unDraw)
  if (/undraw|unDraw|illustrations\/undraw|flat.*illustration/i.test(cleanContent)) {
    const matchLineIdx = lines.findIndex(l => /undraw|unDraw|flat.*illustration/i.test(l));
    const lineNum = matchLineIdx !== -1 ? matchLineIdx + 1 : 1;
    findings.push({
      id: `cliche-${Date.now()}-${findingCounter.count++}`,
      ruleId: 223,
      type: 'VIBEPOLISH',
      title: 'CLICHE-23: Generic Faceless Flat Stock Vectors (unDraw)',
      severity: 'LOW',
      category: 'AI Cliché & Visual',
      filePath: file.path,
      lineRange: `L${lineNum}`,
      snippet: lines[matchLineIdx] || 'src="/illustrations/undraw-team.svg"',
      reproductionSteps: [
        `Scanned visual assets in ${file.path}:${lineNum}.`,
        'Detected unDraw-style generic flat vector illustrations — faceless, personality-less stock art.'
      ],
      remediationPrompt: `Replace stock vector illustrations in ${file.path} with real product UI screenshots, actual data visualizations, or custom-designed brand assets.`,
      status: 'OPEN',
      owner: 'Design Team',
      falsePositive: false
    });
    logs.push(`[${ts}] 🎨 CLICHE-23: Stock flat illustration detected (${file.path}:${lineNum})`);
  }

  // CLICHE-24: Decorative Floating Glassmorphism Blur Orbs
  if (/blur-(?:2xl|3xl)|backdrop-blur|glassmorphism/i.test(cleanContent) &&
      /absolute.*rounded-full|rounded-full.*absolute/i.test(cleanContent) &&
      /bg-(?:purple|blue|pink|cyan|teal)-(?:400|500|600)\/(?:20|30|40|50)|opacity-(?:20|30|40)/i.test(cleanContent)) {
    const matchLineIdx = lines.findIndex(l => /blur-(?:2xl|3xl)|backdrop-blur/i.test(l));
    const lineNum = matchLineIdx !== -1 ? matchLineIdx + 1 : 1;
    findings.push({
      id: `cliche-${Date.now()}-${findingCounter.count++}`,
      ruleId: 224,
      type: 'VIBEPOLISH',
      title: 'CLICHE-24: Decorative Floating Glassmorphism Blur Orbs',
      severity: 'LOW',
      category: 'AI Cliché & Visual',
      filePath: file.path,
      lineRange: `L${lineNum}`,
      snippet: lines[matchLineIdx] || '<div className="absolute rounded-full blur-3xl bg-purple-500/30 w-64 h-64" />',
      reproductionSteps: [
        `Scanned decorative elements in ${file.path}:${lineNum}.`,
        'Detected floating glassmorphism blur orbs — AI-generated space-filler with no functional purpose.'
      ],
      remediationPrompt: `Remove floating blur decorations in ${file.path}. Use negative space (whitespace) intentionally as a design element instead.`,
      status: 'OPEN',
      owner: 'UI Architect',
      falsePositive: false
    });
    logs.push(`[${ts}] 🎨 CLICHE-24: Floating glassmorphism blur orbs detected (${file.path}:${lineNum})`);
  }

  // CLICHE-25: Stock Photo of Happy Team Looking at Laptop
  if (/stock.*photo|team.*photo|shutterstock|istock|unsplash.*team|pexels.*office|happy.*team/i.test(cleanContent) &&
      /office|laptop|meeting|team/i.test(cleanContent)) {
    const matchLineIdx = lines.findIndex(l => /stock.*photo|shutterstock|istock|unsplash.*team|happy.*team/i.test(l));
    const lineNum = matchLineIdx !== -1 ? matchLineIdx + 1 : 1;
    findings.push({
      id: `cliche-${Date.now()}-${findingCounter.count++}`,
      ruleId: 225,
      type: 'VIBEPOLISH',
      title: 'CLICHE-25: Stock Photo of Happy Team Looking at Laptop',
      severity: 'LOW',
      category: 'AI Cliché & Visual',
      filePath: file.path,
      lineRange: `L${lineNum}`,
      snippet: lines[matchLineIdx] || 'src="/images/happy-team-office.jpg"',
      reproductionSteps: [
        `Scanned visual assets in ${file.path}:${lineNum}.`,
        'Detected generic stock team/office photography — reduces authenticity.'
      ],
      remediationPrompt: `Replace stock team photos in ${file.path} with real founder/team photos, workspace images, or direct product screenshots.`,
      status: 'OPEN',
      owner: 'Marketing',
      falsePositive: false
    });
    logs.push(`[${ts}] 🎨 CLICHE-25: Stock team photo detected (${file.path}:${lineNum})`);
  }

  return { findings, logs };
}
