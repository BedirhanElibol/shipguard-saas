# Zelsis Self-Scan Dogfooding Baseline Report

**Generated At:** 2026-09-25T20:17:01.266Z  
**Target:** Zelsis Codebase (Internal Self-Scan)  
**Analyzed Files:** 382 source files  
**Duration:** 4532ms  
**Readiness Score:** 0/100  
**Gate Clearance:** FAILED  

## Executive Summary

| Metric | Count |
|---|---|
| **Critical Blockers** | 145 |
| **High Severity Issues** | 132 |
| **Medium Warnings** | 117 |
| **Low / Informational** | 26 |
| **Total Findings** | 420 |

## Detected Stacks & Architecture

- **Databases:** PostgreSQL, MongoDB, Redis
- **ORMs:** Supabase Client

## Detailed Findings Catalog

| ID | Severity | Pillar | Rule Code | File | Description |
|---|---|---|---|---|---|
| 1 | **LOW** | SECURITY | `7216` | `app/api/v1/badge/route.ts:L1` | API-16: Missing ETag Header on Cacheable Entity Endpoints |
| 2 | **HIGH** | INFRA_DATABASE | `11101` | `app/api/v1/badge/route.ts:L1` | CDN-01: Missing Stale-While-Revalidate and Immutable Directives on Static Bundles |
| 3 | **CRITICAL** | INFRA_DATABASE | `13201` | `app/api/v1/badge/route.ts:L1` | OPA-01: Rego Policy Infinite Recursion and Execution Timeout |
| 4 | **HIGH** | INFRA_DATABASE | `13505` | `app/api/v1/badge/route.ts:L1` | VECTOR-05: Missing Inverted Index on Vector Metadata Filter Fields |
| 5 | **HIGH** | INFRA_DATABASE | `7001` | `app/api/v1/gate-check/route.ts:L1` | CLOUD-01: Synchronous Serverless Function Timeout Exceeding 30s |
| 6 | **MEDIUM** | INFRA_DATABASE | `10705` | `app/api/v1/gate-check/route.ts:L1` | CACHE-05: Unpartitioned Large Cache Key Degradation (>1MB Payload Blob) |
| 7 | **LOW** | SECURITY | `11405` | `app/api/v1/gate-check/route.ts:L1` | GW-05: Missing API Deprecation and Sunset Announcement Headers |
| 8 | **CRITICAL** | SECURITY | `12101` | `app/api/v1/gate-check/route.ts:L1` | AUDIT-01: Plaintext Credentials or PII Leaked in Application Logs |
| 9 | **HIGH** | INFRA_DATABASE | `13505` | `app/api/v1/gate-check/route.ts:L1` | VECTOR-05: Missing Inverted Index on Vector Metadata Filter Fields |
| 10 | **HIGH** | SECURITY | `14805` | `app/api/v1/gate-check/route.ts:L1` | CSPM-05: Cloud Audit Trails (CloudTrail / Audit Logs) Disabled in Region |
| 11 | **LOW** | SECURITY | `7216` | `app/api/v1/geo/route.ts:L1` | API-16: Missing ETag Header on Cacheable Entity Endpoints |
| 12 | **HIGH** | INFRA_DATABASE | `11101` | `app/api/v1/geo/route.ts:L1` | CDN-01: Missing Stale-While-Revalidate and Immutable Directives on Static Bundles |
| 13 | **HIGH** | INFRA_DATABASE | `11105` | `app/api/v1/geo/route.ts:L1` | CDN-05: Uncached Dynamic API Responses Missing Cache-Control Revalidation Headers |
| 14 | **LOW** | SECURITY | `7216` | `app/api/v1/github-proxy/route.ts:L1` | API-16: Missing ETag Header on Cacheable Entity Endpoints |
| 15 | **MEDIUM** | INFRA_DATABASE | `8604` | `app/api/v1/github-proxy/route.ts:L1` | NEXT15-04: Uncached Dynamic Route Render Explosion (force-dynamic) |
| 16 | **HIGH** | INFRA_DATABASE | `11105` | `app/api/v1/github-proxy/route.ts:L1` | CDN-05: Uncached Dynamic API Responses Missing Cache-Control Revalidation Headers |
| 17 | **CRITICAL** | SECURITY | `12101` | `app/api/v1/github-proxy/route.ts:L1` | AUDIT-01: Plaintext Credentials or PII Leaked in Application Logs |
| 18 | **HIGH** | INFRA_DATABASE | `13505` | `app/api/v1/github-proxy/route.ts:L1` | VECTOR-05: Missing Inverted Index on Vector Metadata Filter Fields |
| 19 | **CRITICAL** | SECURITY | `12101` | `app/api/v1/polar-webhook/route.ts:L2` | AUDIT-01: Plaintext Credentials or PII Leaked in Application Logs |
| 20 | **CRITICAL** | SECURITY | `13301` | `app/api/v1/polar-webhook/route.ts:L2` | CRYPTO-01: Hardcoded Cryptographic Keys and Static Salts in Source Code |
| 21 | **LOW** | SECURITY | `7216` | `app/api/v1/proxy/route.ts:L1` | API-16: Missing ETag Header on Cacheable Entity Endpoints |
| 22 | **HIGH** | INFRA_DATABASE | `11105` | `app/api/v1/proxy/route.ts:L1` | CDN-05: Uncached Dynamic API Responses Missing Cache-Control Revalidation Headers |
| 23 | **CRITICAL** | SECURITY | `12101` | `app/api/v1/proxy/route.ts:L1` | AUDIT-01: Plaintext Credentials or PII Leaked in Application Logs |
| 24 | **HIGH** | INFRA_DATABASE | `13505` | `app/api/v1/proxy/route.ts:L1` | VECTOR-05: Missing Inverted Index on Vector Metadata Filter Fields |
| 25 | **CRITICAL** | SECURITY | `13802` | `app/api/v1/proxy/route.ts:L1` | ASVS-02: ASVS V3.2 Session Management: Permitting Session Fixation or Insecure Cookie Flags |
| 26 | **MEDIUM** | SECURITY | `7211` | `app/api/v1/quota/route.ts:L1` | API-11: Missing Content-Type Validation on POST/PUT Endpoints |
| 27 | **LOW** | SECURITY | `7216` | `app/api/v1/quota/route.ts:L1` | API-16: Missing ETag Header on Cacheable Entity Endpoints |
| 28 | **HIGH** | INFRA_DATABASE | `11105` | `app/api/v1/quota/route.ts:L1` | CDN-05: Uncached Dynamic API Responses Missing Cache-Control Revalidation Headers |
| 29 | **CRITICAL** | SECURITY | `12101` | `app/api/v1/quota/route.ts:L1` | AUDIT-01: Plaintext Credentials or PII Leaked in Application Logs |
| 30 | **HIGH** | SECURITY | `14805` | `app/api/v1/quota/route.ts:L1` | CSPM-05: Cloud Audit Trails (CloudTrail / Audit Logs) Disabled in Region |
| 31 | **LOW** | SECURITY | `7216` | `app/api/v1/scans/jobs/[id]/route.ts:L1` | API-16: Missing ETag Header on Cacheable Entity Endpoints |
| 32 | **MEDIUM** | INFRA_DATABASE | `8604` | `app/api/v1/scans/jobs/[id]/route.ts:L1` | NEXT15-04: Uncached Dynamic Route Render Explosion (force-dynamic) |
| 33 | **HIGH** | INFRA_DATABASE | `11105` | `app/api/v1/scans/jobs/[id]/route.ts:L1` | CDN-05: Uncached Dynamic API Responses Missing Cache-Control Revalidation Headers |
| 34 | **HIGH** | INFRA_DATABASE | `7001` | `app/api/v1/scans/process-job/route.ts:L1` | CLOUD-01: Synchronous Serverless Function Timeout Exceeding 30s |
| 35 | **MEDIUM** | SECURITY | `7208` | `app/api/v1/scans/process-job/route.ts:L1` | API-08: Missing 'Retry-After' Header on Rate Limit Throttling (429) |
| 36 | **MEDIUM** | SECURITY | `7211` | `app/api/v1/scans/process-job/route.ts:L1` | API-11: Missing Content-Type Validation on POST/PUT Endpoints |
| 37 | **MEDIUM** | INFRA_DATABASE | `8604` | `app/api/v1/scans/process-job/route.ts:L1` | NEXT15-04: Uncached Dynamic Route Render Explosion (force-dynamic) |
| 38 | **HIGH** | SECURITY | `10402` | `app/api/v1/scans/process-job/route.ts:L1` | WAF-02: Missing Edge Rate Limiting on High-Cost AI Inference Endpoints |
| 39 | **CRITICAL** | SECURITY | `12101` | `app/api/v1/scans/process-job/route.ts:L1` | AUDIT-01: Plaintext Credentials or PII Leaked in Application Logs |
| 40 | **MEDIUM** | INFRA_DATABASE | `10705` | `app/api/v1/scans/queue/route.ts:L1` | CACHE-05: Unpartitioned Large Cache Key Degradation (>1MB Payload Blob) |
| 41 | **LOW** | SECURITY | `11405` | `app/api/v1/scans/queue/route.ts:L1` | GW-05: Missing API Deprecation and Sunset Announcement Headers |
| 42 | **CRITICAL** | SECURITY | `12101` | `app/api/v1/scans/queue/route.ts:L1` | AUDIT-01: Plaintext Credentials or PII Leaked in Application Logs |
| 43 | **CRITICAL** | SECURITY | `12101` | `app/api/v1/subscription/sync/route.ts:L1` | AUDIT-01: Plaintext Credentials or PII Leaked in Application Logs |
| 44 | **HIGH** | INFRA_DATABASE | `13505` | `app/api/v1/subscription/sync/route.ts:L1` | VECTOR-05: Missing Inverted Index on Vector Metadata Filter Fields |
| 45 | **MEDIUM** | SECURITY | `7211` | `app/api/v1/test-webhook/route.ts:L1` | API-11: Missing Content-Type Validation on POST/PUT Endpoints |
| 46 | **CRITICAL** | SECURITY | `8143` | `app/api/v1/test-webhook/route.ts:L1` | ZERO-AUTH-43: Missing Identity Verification on Webhook Receiver Endpoints |
| 47 | **CRITICAL** | SECURITY | `12101` | `app/api/v1/test-webhook/route.ts:L1` | AUDIT-01: Plaintext Credentials or PII Leaked in Application Logs |
| 48 | **CRITICAL** | SECURITY | `12101` | `app/api/v1/user/delete/route.ts:L1` | AUDIT-01: Plaintext Credentials or PII Leaked in Application Logs |
| 49 | **LOW** | SECURITY | `7216` | `app/api/v1/user/export/route.ts:L1` | API-16: Missing ETag Header on Cacheable Entity Endpoints |
| 50 | **MEDIUM** | INFRA_DATABASE | `10705` | `app/api/v1/user/export/route.ts:L1` | CACHE-05: Unpartitioned Large Cache Key Degradation (>1MB Payload Blob) |
| 51 | **HIGH** | INFRA_DATABASE | `11105` | `app/api/v1/user/export/route.ts:L1` | CDN-05: Uncached Dynamic API Responses Missing Cache-Control Revalidation Headers |
| 52 | **CRITICAL** | SECURITY | `12101` | `app/api/v1/user/export/route.ts:L1` | AUDIT-01: Plaintext Credentials or PII Leaked in Application Logs |
| 53 | **MEDIUM** | INFRA_DATABASE | `8604` | `app/api/v1/verify-checkout/route.ts:L1` | NEXT15-04: Uncached Dynamic Route Render Explosion (force-dynamic) |
| 54 | **CRITICAL** | SECURITY | `12101` | `app/api/v1/verify-checkout/route.ts:L1` | AUDIT-01: Plaintext Credentials or PII Leaked in Application Logs |
| 55 | **CRITICAL** | LEGAL_COMPLIANCE | `12902` | `app/api/v1/verify-checkout/route.ts:L1` | PCI4-02: PCI-DSS Req 6.4.3 Insecure Third-Party Scripts on Payment Pages |
| 56 | **MEDIUM** | INFRA_DATABASE | `10705` | `app/auth/callback/page.tsx:L1` | CACHE-05: Unpartitioned Large Cache Key Degradation (>1MB Payload Blob) |
| 57 | **HIGH** | INFRA_DATABASE | `13505` | `app/auth/callback/page.tsx:L1` | VECTOR-05: Missing Inverted Index on Vector Metadata Filter Fields |
| 58 | **CRITICAL** | INFRA_DATABASE | `13701` | `app/auth/callback/page.tsx:L1` | FED-01: Unbounded Subgraph Query Depth in Federated Gateway |
| 59 | **CRITICAL** | SECURITY | `14301` | `app/auth/callback/page.tsx:L1` | APIDEF-01: API1:2023 Broken Object Level Authorization (BOLA): Insecure Record Lookup |
| 60 | **MEDIUM** | INFRA_DATABASE | `10705` | `app/checkout/page.tsx:L1` | CACHE-05: Unpartitioned Large Cache Key Degradation (>1MB Payload Blob) |
| 61 | **CRITICAL** | SECURITY | `11402` | `app/checkout/page.tsx:L1` | GW-02: Missing Token Bucket Rate Limiting on Credential Authentication Routes |
| 62 | **CRITICAL** | LEGAL_COMPLIANCE | `12902` | `app/checkout/page.tsx:L1` | PCI4-02: PCI-DSS Req 6.4.3 Insecure Third-Party Scripts on Payment Pages |
| 63 | **HIGH** | INFRA_DATABASE | `13505` | `app/checkout/page.tsx:L1` | VECTOR-05: Missing Inverted Index on Vector Metadata Filter Fields |
| 64 | **CRITICAL** | INFRA_DATABASE | `13701` | `app/checkout/page.tsx:L1` | FED-01: Unbounded Subgraph Query Depth in Federated Gateway |
| 65 | **CRITICAL** | SECURITY | `14301` | `app/checkout/page.tsx:L1` | APIDEF-01: API1:2023 Broken Object Level Authorization (BOLA): Insecure Record Lookup |
| 66 | **CRITICAL** | INFRA_DATABASE | `13201` | `app/cookies/page.tsx:L1` | OPA-01: Rego Policy Infinite Recursion and Execution Timeout |
| 67 | **MEDIUM** | VIBEPOLISH | `111` | `app/dashboard/page.tsx:L110` | UI-111: TypeScript "any" Type Escape |
| 68 | **MEDIUM** | INFRA_DATABASE | `10705` | `app/dashboard/page.tsx:L1` | CACHE-05: Unpartitioned Large Cache Key Degradation (>1MB Payload Blob) |
| 69 | **CRITICAL** | SECURITY | `11402` | `app/dashboard/page.tsx:L1` | GW-02: Missing Token Bucket Rate Limiting on Credential Authentication Routes |
| 70 | **HIGH** | INFRA_DATABASE | `13505` | `app/dashboard/page.tsx:L1` | VECTOR-05: Missing Inverted Index on Vector Metadata Filter Fields |
| 71 | **CRITICAL** | INFRA_DATABASE | `13701` | `app/dashboard/page.tsx:L1` | FED-01: Unbounded Subgraph Query Depth in Federated Gateway |
| 72 | **CRITICAL** | SECURITY | `14301` | `app/dashboard/page.tsx:L1` | APIDEF-01: API1:2023 Broken Object Level Authorization (BOLA): Insecure Record Lookup |
| 73 | **CRITICAL** | LEGAL_COMPLIANCE | `10804` | `app/error.tsx:L1` | ISO-04: Missing Segregation in Production and Development Environments (A.8.31) |
| 74 | **CRITICAL** | LEGAL_COMPLIANCE | `10804` | `app/global-error.tsx:L1` | ISO-04: Missing Segregation in Production and Development Environments (A.8.31) |
| 75 | **CRITICAL** | INFRA_DATABASE | `13204` | `app/page.tsx:L1` | OPA-04: Unrestricted Container Linux Capabilities (SYS_ADMIN) Admission |
| 76 | **CRITICAL** | INFRA_DATABASE | `13701` | `app/page.tsx:L1` | FED-01: Unbounded Subgraph Query Depth in Federated Gateway |
| 77 | **CRITICAL** | SECURITY | `15701` | `app/page.tsx:L1` | KERN-SEC-01: Unrestricted Linux Root Capabilities (CAP_SYS_ADMIN) Retained in Container Workloads |
| 78 | **CRITICAL** | INFRA_DATABASE | `13201` | `app/privacy/page.tsx:L1` | OPA-01: Rego Policy Infinite Recursion and Execution Timeout |
| 79 | **CRITICAL** | INFRA_DATABASE | `13201` | `app/refund/page.tsx:L1` | OPA-01: Rego Policy Infinite Recursion and Execution Timeout |
| 80 | **CRITICAL** | INFRA_DATABASE | `13201` | `app/terms/page.tsx:L1` | OPA-01: Rego Policy Infinite Recursion and Execution Timeout |
| 81 | **CRITICAL** | LEGAL_COMPLIANCE | `9804` | `components/analytics/AnalyticsScripts.tsx:L1` | HIPAA-04: Third-Party Analytics Tracking Pixels on Health Portal |
| 82 | **MEDIUM** | INFRA_DATABASE | `8609` | `components/auth/AuthModal.tsx:L1` | NEXT15-09: React 19 useActionState Missing Double-Submit Guard |
| 83 | **CRITICAL** | INFRA_DATABASE | `13201` | `components/auth/AuthModal.tsx:L1` | OPA-01: Rego Policy Infinite Recursion and Execution Timeout |
| 84 | **MEDIUM** | INFRA_DATABASE | `10705` | `components/checkout/CheckoutView.tsx:L1` | CACHE-05: Unpartitioned Large Cache Key Degradation (>1MB Payload Blob) |
| 85 | **CRITICAL** | SECURITY | `11402` | `components/checkout/CheckoutView.tsx:L1` | GW-02: Missing Token Bucket Rate Limiting on Credential Authentication Routes |
| 86 | **LOW** | SECURITY | `11405` | `components/checkout/CheckoutView.tsx:L1` | GW-05: Missing API Deprecation and Sunset Announcement Headers |
| 87 | **CRITICAL** | LEGAL_COMPLIANCE | `12901` | `components/checkout/CheckoutView.tsx:L1` | PCI4-01: PCI-DSS Req 3.4 Unencrypted Primary Account Numbers (PAN) at Rest |
| 88 | **CRITICAL** | LEGAL_COMPLIANCE | `12902` | `components/checkout/CheckoutView.tsx:L1` | PCI4-02: PCI-DSS Req 6.4.3 Insecure Third-Party Scripts on Payment Pages |
| 89 | **CRITICAL** | INFRA_DATABASE | `13201` | `components/checkout/CheckoutView.tsx:L1` | OPA-01: Rego Policy Infinite Recursion and Execution Timeout |
| 90 | **HIGH** | INFRA_DATABASE | `13505` | `components/checkout/CheckoutView.tsx:L1` | VECTOR-05: Missing Inverted Index on Vector Metadata Filter Fields |
| 91 | **CRITICAL** | INFRA_DATABASE | `13701` | `components/checkout/CheckoutView.tsx:L1` | FED-01: Unbounded Subgraph Query Depth in Federated Gateway |
| 92 | **CRITICAL** | SECURITY | `14301` | `components/checkout/CheckoutView.tsx:L1` | APIDEF-01: API1:2023 Broken Object Level Authorization (BOLA): Insecure Record Lookup |
| 93 | **MEDIUM** | INFRA_DATABASE | `10705` | `components/CicdAutomationView.tsx:L1` | CACHE-05: Unpartitioned Large Cache Key Degradation (>1MB Payload Blob) |
| 94 | **HIGH** | SECURITY | `12605` | `components/CicdAutomationView.tsx:L1` | SBOM-05: Unvetted Third-Party GitHub Actions in Production CI/CD Workflows |
| 95 | **CRITICAL** | INFRA_DATABASE | `13201` | `components/CicdAutomationView.tsx:L1` | OPA-01: Rego Policy Infinite Recursion and Execution Timeout |
| 96 | **HIGH** | SECURITY | `14104` | `components/CicdAutomationView.tsx:L1` | SLSA-04: Mutable Git Tags Used in Release Pipeline Rather Than Commit SHAs |
| 97 | **HIGH** | LEGAL_COMPLIANCE | `8212` | `components/CookieBanner.tsx:L1` | PRIVACY-12: Missing Cookie Consent Revocation / Preferences Manager |
| 98 | **CRITICAL** | INFRA_DATABASE | `13201` | `components/CookieBanner.tsx:L1` | OPA-01: Rego Policy Infinite Recursion and Execution Timeout |
| 99 | **CRITICAL** | SECURITY | `14301` | `components/CookieBanner.tsx:L1` | APIDEF-01: API1:2023 Broken Object Level Authorization (BOLA): Insecure Record Lookup |
| 100 | **LOW** | SECURITY | `11405` | `components/dashboard/BadgeGeneratorModal.tsx:L1` | GW-05: Missing API Deprecation and Sunset Announcement Headers |
| 101 | **LOW** | SECURITY | `11405` | `components/dashboard/CiCdIntegrationModal.tsx:L1` | GW-05: Missing API Deprecation and Sunset Announcement Headers |
| 102 | **HIGH** | SECURITY | `12605` | `components/dashboard/CiCdIntegrationModal.tsx:L1` | SBOM-05: Unvetted Third-Party GitHub Actions in Production CI/CD Workflows |
| 103 | **HIGH** | SECURITY | `14104` | `components/dashboard/CiCdIntegrationModal.tsx:L1` | SLSA-04: Mutable Git Tags Used in Release Pipeline Rather Than Commit SHAs |
| 104 | **LOW** | SECURITY | `11405` | `components/dashboard/DeploymentManifestModal.tsx:L1` | GW-05: Missing API Deprecation and Sunset Announcement Headers |
| 105 | **HIGH** | SECURITY | `12605` | `components/dashboard/DeploymentManifestModal.tsx:L1` | SBOM-05: Unvetted Third-Party GitHub Actions in Production CI/CD Workflows |
| 106 | **HIGH** | SECURITY | `14104` | `components/dashboard/DeploymentManifestModal.tsx:L1` | SLSA-04: Mutable Git Tags Used in Release Pipeline Rather Than Commit SHAs |
| 107 | **LOW** | SECURITY | `11405` | `components/dashboard/GeoIpTracker.tsx:L1` | GW-05: Missing API Deprecation and Sunset Announcement Headers |
| 108 | **CRITICAL** | SECURITY | `11402` | `components/dashboard/LifecycleBanner.tsx:L1` | GW-02: Missing Token Bucket Rate Limiting on Credential Authentication Routes |
| 109 | **MEDIUM** | INFRA_DATABASE | `10705` | `components/dashboard/NotificationSettingsModal.tsx:L1` | CACHE-05: Unpartitioned Large Cache Key Degradation (>1MB Payload Blob) |
| 110 | **LOW** | SECURITY | `11405` | `components/dashboard/NotificationSettingsModal.tsx:L1` | GW-05: Missing API Deprecation and Sunset Announcement Headers |
| 111 | **CRITICAL** | SECURITY | `14301` | `components/dashboard/NotificationSettingsModal.tsx:L1` | APIDEF-01: API1:2023 Broken Object Level Authorization (BOLA): Insecure Record Lookup |
| 112 | **MEDIUM** | INFRA_DATABASE | `8609` | `components/dashboard/PrivateRepoTokenModal.tsx:L1` | NEXT15-09: React 19 useActionState Missing Double-Submit Guard |
| 113 | **CRITICAL** | SECURITY | `14301` | `components/dashboard/PrivateRepoTokenModal.tsx:L1` | APIDEF-01: API1:2023 Broken Object Level Authorization (BOLA): Insecure Record Lookup |
| 114 | **MEDIUM** | INFRA_DATABASE | `10705` | `components/dashboard/QuickChartWidget.tsx:L1` | CACHE-05: Unpartitioned Large Cache Key Degradation (>1MB Payload Blob) |
| 115 | **CRITICAL** | INFRA_DATABASE | `13701` | `components/dashboard/QuotaLimitModal.tsx:L1` | FED-01: Unbounded Subgraph Query Depth in Federated Gateway |
| 116 | **CRITICAL** | INFRA_DATABASE | `13201` | `components/dashboard/RuleConfiguratorModal.tsx:L1` | OPA-01: Rego Policy Infinite Recursion and Execution Timeout |
| 117 | **CRITICAL** | INFRA_DATABASE | `13201` | `components/dashboard/ScaLicenseRiskCard.tsx:L1` | OPA-01: Rego Policy Infinite Recursion and Execution Timeout |
| 118 | **CRITICAL** | SECURITY | `11402` | `components/findings/FindingDetailModal.tsx:L1` | GW-02: Missing Token Bucket Rate Limiting on Credential Authentication Routes |
| 119 | **CRITICAL** | SECURITY | `11402` | `components/findings/RemediationDrawer.tsx:L1` | GW-02: Missing Token Bucket Rate Limiting on Credential Authentication Routes |
| 120 | **HIGH** | LEGAL_COMPLIANCE | `8226` | `components/Footer.tsx:L1` | PRIVACY-26: Missing Opt-Out Mechanism for Sale / Sharing of Personal Info |
| 121 | **CRITICAL** | INFRA_DATABASE | `13201` | `components/Footer.tsx:L1` | OPA-01: Rego Policy Infinite Recursion and Execution Timeout |
| 122 | **HIGH** | INFRA_DATABASE | `12202` | `components/Hero.tsx:L1` | CONTAINER-02: Root User Execution in Container Runtime Image |
| 123 | **HIGH** | INFRA_DATABASE | `13002` | `components/Hero.tsx:L1` | SEARCH-02: Unindexed Leading Wildcard Search Triggering Full Cluster Scans |
| 124 | **CRITICAL** | INFRA_DATABASE | `13201` | `components/Hero.tsx:L1` | OPA-01: Rego Policy Infinite Recursion and Execution Timeout |
| 125 | **CRITICAL** | SECURITY | `13301` | `components/Hero.tsx:L1` | CRYPTO-01: Hardcoded Cryptographic Keys and Static Salts in Source Code |
| 126 | **CRITICAL** | SECURITY | `11402` | `components/layout/AppShell.tsx:L1` | GW-02: Missing Token Bucket Rate Limiting on Credential Authentication Routes |
| 127 | **MEDIUM** | INFRA_DATABASE | `8609` | `components/layout/ConnectTargetModal.tsx:L1` | NEXT15-09: React 19 useActionState Missing Double-Submit Guard |
| 128 | **CRITICAL** | SECURITY | `14301` | `components/layout/ConnectTargetModal.tsx:L1` | APIDEF-01: API1:2023 Broken Object Level Authorization (BOLA): Insecure Record Lookup |
| 129 | **MEDIUM** | INFRA_DATABASE | `8609` | `components/layout/Header.tsx:L1` | NEXT15-09: React 19 useActionState Missing Double-Submit Guard |
| 130 | **CRITICAL** | SECURITY | `11402` | `components/layout/Header.tsx:L1` | GW-02: Missing Token Bucket Rate Limiting on Credential Authentication Routes |
| 131 | **CRITICAL** | SECURITY | `14301` | `components/layout/Header.tsx:L1` | APIDEF-01: API1:2023 Broken Object Level Authorization (BOLA): Insecure Record Lookup |
| 132 | **CRITICAL** | SECURITY | `11402` | `components/layout/Sidebar.tsx:L1` | GW-02: Missing Token Bucket Rate Limiting on Credential Authentication Routes |
| 133 | **CRITICAL** | LEGAL_COMPLIANCE | `12901` | `components/layout/Sidebar.tsx:L1` | PCI4-01: PCI-DSS Req 3.4 Unencrypted Primary Account Numbers (PAN) at Rest |
| 134 | **CRITICAL** | SECURITY | `11402` | `components/Navbar.tsx:L1` | GW-02: Missing Token Bucket Rate Limiting on Credential Authentication Routes |
| 135 | **CRITICAL** | SECURITY | `14301` | `components/Navbar.tsx:L1` | APIDEF-01: API1:2023 Broken Object Level Authorization (BOLA): Insecure Record Lookup |
| 136 | **CRITICAL** | INFRA_DATABASE | `13701` | `components/PricingView.tsx:L1` | FED-01: Unbounded Subgraph Query Depth in Federated Gateway |
| 137 | **MEDIUM** | INFRA_DATABASE | `8609` | `components/projects/NewProjectModal.tsx:L1` | NEXT15-09: React 19 useActionState Missing Double-Submit Guard |
| 138 | **CRITICAL** | INFRA_DATABASE | `13701` | `components/projects/NewProjectModal.tsx:L1` | FED-01: Unbounded Subgraph Query Depth in Federated Gateway |
| 139 | **CRITICAL** | SECURITY | `11402` | `components/ProjectSettingsView.tsx:L1` | GW-02: Missing Token Bucket Rate Limiting on Credential Authentication Routes |
| 140 | **CRITICAL** | SECURITY | `14301` | `components/ProjectSettingsView.tsx:L1` | APIDEF-01: API1:2023 Broken Object Level Authorization (BOLA): Insecure Record Lookup |
| 141 | **CRITICAL** | SECURITY | `11402` | `components/ProjectsView.tsx:L1` | GW-02: Missing Token Bucket Rate Limiting on Credential Authentication Routes |
| 142 | **MEDIUM** | VIBEPOLISH | `1004` | `components/saas/BenchmarkSection.tsx:L1-L50` | UI-04: Absence of Empty State Component Fallback |
| 143 | **CRITICAL** | INFRA_DATABASE | `13201` | `components/saas/BenchmarkSection.tsx:L1` | OPA-01: Rego Policy Infinite Recursion and Execution Timeout |
| 144 | **CRITICAL** | SECURITY | `13602` | `components/saas/BenchmarkSection.tsx:L1` | THREAT-02: MITRE T1059 Command Execution: Unmonitored Interactive Shell Spawning in Web Pods |
| 145 | **CRITICAL** | INFRA_DATABASE | `13701` | `components/saas/BenchmarkSection.tsx:L1` | FED-01: Unbounded Subgraph Query Depth in Federated Gateway |
| 146 | **HIGH** | SECURITY | `8109` | `components/saas/ComparisonTable.tsx:L1` | ZERO-AUTH-09: Session Fixation Vulnerability on Login State Transition |
| 147 | **CRITICAL** | SECURITY | `11402` | `components/saas/ComparisonTable.tsx:L1` | GW-02: Missing Token Bucket Rate Limiting on Credential Authentication Routes |
| 148 | **CRITICAL** | INFRA_DATABASE | `13201` | `components/saas/ComparisonTable.tsx:L1` | OPA-01: Rego Policy Infinite Recursion and Execution Timeout |
| 149 | **CRITICAL** | INFRA_DATABASE | `13701` | `components/saas/ComparisonTable.tsx:L1` | FED-01: Unbounded Subgraph Query Depth in Federated Gateway |
| 150 | **CRITICAL** | SECURITY | `14301` | `components/saas/ComparisonTable.tsx:L1` | APIDEF-01: API1:2023 Broken Object Level Authorization (BOLA): Insecure Record Lookup |
| 151 | **CRITICAL** | INFRA_DATABASE | `13201` | `components/saas/FaqSection.tsx:L1` | OPA-01: Rego Policy Infinite Recursion and Execution Timeout |
| 152 | **CRITICAL** | INFRA_DATABASE | `13701` | `components/saas/FaqSection.tsx:L1` | FED-01: Unbounded Subgraph Query Depth in Federated Gateway |
| 153 | **LOW** | VIBEPOLISH | `221` | `components/saas/FinalCta.tsx:L1` | CLICHE-21: Forced Fixed-Height Card Containers |
| 154 | **CRITICAL** | INFRA_DATABASE | `13701` | `components/saas/FinalCta.tsx:L1` | FED-01: Unbounded Subgraph Query Depth in Federated Gateway |
| 155 | **CRITICAL** | INFRA_DATABASE | `13201` | `components/saas/ProductCapabilities.tsx:L1` | OPA-01: Rego Policy Infinite Recursion and Execution Timeout |
| 156 | **CRITICAL** | INFRA_DATABASE | `13204` | `components/saas/ProductCapabilities.tsx:L1` | OPA-04: Unrestricted Container Linux Capabilities (SYS_ADMIN) Admission |
| 157 | **CRITICAL** | SECURITY | `15701` | `components/saas/ProductCapabilities.tsx:L1` | KERN-SEC-01: Unrestricted Linux Root Capabilities (CAP_SYS_ADMIN) Retained in Container Workloads |
| 158 | **CRITICAL** | SECURITY | `11402` | `components/saas/SaasCheckout.tsx:L1` | GW-02: Missing Token Bucket Rate Limiting on Credential Authentication Routes |
| 159 | **CRITICAL** | LEGAL_COMPLIANCE | `12902` | `components/saas/SaasCheckout.tsx:L1` | PCI4-02: PCI-DSS Req 6.4.3 Insecure Third-Party Scripts on Payment Pages |
| 160 | **MEDIUM** | INFRA_DATABASE | `8609` | `components/saas/SaasHero.tsx:L1` | NEXT15-09: React 19 useActionState Missing Double-Submit Guard |
| 161 | **CRITICAL** | INFRA_DATABASE | `13701` | `components/saas/SaasHero.tsx:L1` | FED-01: Unbounded Subgraph Query Depth in Federated Gateway |
| 162 | **HIGH** | VIBEPOLISH | `106` | `components/ScanRunnerView.tsx:L217` | UI-106: Empty Silent Catch Block |
| 163 | **MEDIUM** | VIBEPOLISH | `111` | `components/ScanRunnerView.tsx:L69` | UI-111: TypeScript "any" Type Escape |
| 164 | **MEDIUM** | VIBEPOLISH | `115` | `components/ScanRunnerView.tsx:L1-L1208` | UI-115: Monolithic Overly Long Source File (>500 Lines) |
| 165 | **MEDIUM** | INFRA_DATABASE | `10705` | `components/ScanRunnerView.tsx:L1` | CACHE-05: Unpartitioned Large Cache Key Degradation (>1MB Payload Blob) |
| 166 | **CRITICAL** | SECURITY | `11402` | `components/ScanRunnerView.tsx:L1` | GW-02: Missing Token Bucket Rate Limiting on Credential Authentication Routes |
| 167 | **LOW** | SECURITY | `11405` | `components/ScanRunnerView.tsx:L1` | GW-05: Missing API Deprecation and Sunset Announcement Headers |
| 168 | **HIGH** | INFRA_DATABASE | `11701` | `components/ScanRunnerView.tsx:L1` | CRON-01: Distributed Mutex Lock Missing on Periodic Worker |
| 169 | **CRITICAL** | SECURITY | `14301` | `components/ScanRunnerView.tsx:L1` | APIDEF-01: API1:2023 Broken Object Level Authorization (BOLA): Insecure Record Lookup |
| 170 | **MEDIUM** | INFRA_DATABASE | `10705` | `components/settings/DangerZoneCard.tsx:L1` | CACHE-05: Unpartitioned Large Cache Key Degradation (>1MB Payload Blob) |
| 171 | **CRITICAL** | SECURITY | `11402` | `components/settings/DangerZoneCard.tsx:L1` | GW-02: Missing Token Bucket Rate Limiting on Credential Authentication Routes |
| 172 | **LOW** | SECURITY | `11405` | `components/settings/DangerZoneCard.tsx:L1` | GW-05: Missing API Deprecation and Sunset Announcement Headers |
| 173 | **CRITICAL** | INFRA_DATABASE | `13701` | `components/settings/DangerZoneCard.tsx:L1` | FED-01: Unbounded Subgraph Query Depth in Federated Gateway |
| 174 | **HIGH** | SECURITY | `14304` | `components/settings/DangerZoneCard.tsx:L1` | APIDEF-04: API4:2023 Unrestricted Resource Consumption: Missing Client Rate Limits |
| 175 | **MEDIUM** | INFRA_DATABASE | `8609` | `components/settings/EnterpriseOrgCard.tsx:L1` | NEXT15-09: React 19 useActionState Missing Double-Submit Guard |
| 176 | **CRITICAL** | SECURITY | `11402` | `components/settings/EnterpriseOrgCard.tsx:L1` | GW-02: Missing Token Bucket Rate Limiting on Credential Authentication Routes |
| 177 | **CRITICAL** | INFRA_DATABASE | `13201` | `components/settings/EnterpriseOrgCard.tsx:L1` | OPA-01: Rego Policy Infinite Recursion and Execution Timeout |
| 178 | **CRITICAL** | SECURITY | `14301` | `components/settings/EnterpriseOrgCard.tsx:L1` | APIDEF-01: API1:2023 Broken Object Level Authorization (BOLA): Insecure Record Lookup |
| 179 | **MEDIUM** | INFRA_DATABASE | `8609` | `components/settings/RepoConfigCard.tsx:L1` | NEXT15-09: React 19 useActionState Missing Double-Submit Guard |
| 180 | **MEDIUM** | VIBEPOLISH | `115` | `components/settings/SubscriptionCard.tsx:L1-L604` | UI-115: Monolithic Overly Long Source File (>500 Lines) |
| 181 | **MEDIUM** | LEGAL_COMPLIANCE | `2004` | `components/settings/SubscriptionCard.tsx:L413` | User Data Collection Form Missing Mandatory Privacy Consent Disclosure |
| 182 | **MEDIUM** | INFRA_DATABASE | `8609` | `components/settings/SubscriptionCard.tsx:L1` | NEXT15-09: React 19 useActionState Missing Double-Submit Guard |
| 183 | **MEDIUM** | INFRA_DATABASE | `10705` | `components/settings/SubscriptionCard.tsx:L1` | CACHE-05: Unpartitioned Large Cache Key Degradation (>1MB Payload Blob) |
| 184 | **CRITICAL** | SECURITY | `11402` | `components/settings/SubscriptionCard.tsx:L1` | GW-02: Missing Token Bucket Rate Limiting on Credential Authentication Routes |
| 185 | **LOW** | SECURITY | `11405` | `components/settings/SubscriptionCard.tsx:L1` | GW-05: Missing API Deprecation and Sunset Announcement Headers |
| 186 | **CRITICAL** | LEGAL_COMPLIANCE | `12901` | `components/settings/SubscriptionCard.tsx:L1` | PCI4-01: PCI-DSS Req 3.4 Unencrypted Primary Account Numbers (PAN) at Rest |
| 187 | **CRITICAL** | INFRA_DATABASE | `13701` | `components/settings/SubscriptionCard.tsx:L1` | FED-01: Unbounded Subgraph Query Depth in Federated Gateway |
| 188 | **CRITICAL** | SECURITY | `14301` | `components/settings/SubscriptionCard.tsx:L1` | APIDEF-01: API1:2023 Broken Object Level Authorization (BOLA): Insecure Record Lookup |
| 189 | **LOW** | SECURITY | `11405` | `components/ui/OfflineBanner.tsx:L1` | GW-05: Missing API Deprecation and Sunset Announcement Headers |
| 190 | **CRITICAL** | INFRA_DATABASE | `13701` | `components/ui/UpgradePaywallModal.tsx:L1` | FED-01: Unbounded Subgraph Query Depth in Federated Gateway |
| 191 | **CRITICAL** | SECURITY | `14301` | `components/ui/UpgradePaywallModal.tsx:L1` | APIDEF-01: API1:2023 Broken Object Level Authorization (BOLA): Insecure Record Lookup |
| 192 | **CRITICAL** | SECURITY | `11402` | `components/VibeCareView.tsx:L1` | GW-02: Missing Token Bucket Rate Limiting on Credential Authentication Routes |
| 193 | **LOW** | SECURITY | `11405` | `components/VibeCareView.tsx:L1` | GW-05: Missing API Deprecation and Sunset Announcement Headers |
| 194 | **HIGH** | INFRA_DATABASE | `10305` | `data/supabase-migration.sql:L3` | PG-05: Deadlock Risk from Non-Deterministic Lock Acquisition Order |
| 195 | **CRITICAL** | INFRA_DATABASE | `13201` | `data/supabase-migration.sql:L3` | OPA-01: Rego Policy Infinite Recursion and Execution Timeout |
| 196 | **CRITICAL** | INFRA_DATABASE | `15001` | `data/supabase-migration.sql:L3` | GEODIST-01: Unpartitioned Multi-Region Tables Triggering Cross-WAN Latency Spikes |
| 197 | **MEDIUM** | VIBEPOLISH | `111` | `hooks/useDashboardState.ts:L322` | UI-111: TypeScript "any" Type Escape |
| 198 | **MEDIUM** | INFRA_DATABASE | `10705` | `hooks/useDashboardState.ts:L1` | CACHE-05: Unpartitioned Large Cache Key Degradation (>1MB Payload Blob) |
| 199 | **CRITICAL** | SECURITY | `11402` | `hooks/useDashboardState.ts:L1` | GW-02: Missing Token Bucket Rate Limiting on Credential Authentication Routes |
| 200 | **LOW** | SECURITY | `11405` | `hooks/useDashboardState.ts:L1` | GW-05: Missing API Deprecation and Sunset Announcement Headers |
| 201 | **HIGH** | INFRA_DATABASE | `13505` | `hooks/useDashboardState.ts:L1` | VECTOR-05: Missing Inverted Index on Vector Metadata Filter Fields |
| 202 | **CRITICAL** | SECURITY | `14301` | `hooks/useDashboardState.ts:L1` | APIDEF-01: API1:2023 Broken Object Level Authorization (BOLA): Insecure Record Lookup |
| 203 | **CRITICAL** | SECURITY | `14303` | `hooks/useDashboardState.ts:L1` | APIDEF-03: API3:2023 Broken Object Property Level Authorization: Mass Assignment |
| 204 | **MEDIUM** | INFRA_DATABASE | `10705` | `lib/attribution.ts:L1` | CACHE-05: Unpartitioned Large Cache Key Degradation (>1MB Payload Blob) |
| 205 | **HIGH** | INFRA_DATABASE | `13505` | `lib/attribution.ts:L1` | VECTOR-05: Missing Inverted Index on Vector Metadata Filter Fields |
| 206 | **CRITICAL** | SECURITY | `14301` | `lib/attribution.ts:L1` | APIDEF-01: API1:2023 Broken Object Level Authorization (BOLA): Insecure Record Lookup |
| 207 | **CRITICAL** | SECURITY | `14301` | `lib/chunk-reload.ts:L1` | APIDEF-01: API1:2023 Broken Object Level Authorization (BOLA): Insecure Record Lookup |
| 208 | **MEDIUM** | SECURITY | `8512` | `lib/db-schema.sql:L7` | GQL-12: Rate Limiting by HTTP Endpoint Only Instead of Operation |
| 209 | **HIGH** | SECURITY | `8513` | `lib/db-schema.sql:L7` | GQL-13: Persisted Queries Allowlist Missing |
| 210 | **HIGH** | SECURITY | `8521` | `lib/db-schema.sql:L7` | GQL-21: GQL-21: Enterprise GraphQL Resilience & Security Check |
| 211 | **MEDIUM** | SECURITY | `8522` | `lib/db-schema.sql:L7` | GQL-22: GQL-22: Enterprise GraphQL Resilience & Security Check |
| 212 | **HIGH** | SECURITY | `8523` | `lib/db-schema.sql:L7` | GQL-23: GQL-23: Enterprise GraphQL Resilience & Security Check |
| 213 | **MEDIUM** | SECURITY | `8524` | `lib/db-schema.sql:L7` | GQL-24: GQL-24: Enterprise GraphQL Resilience & Security Check |
| 214 | **HIGH** | SECURITY | `8525` | `lib/db-schema.sql:L7` | GQL-25: GQL-25: Enterprise GraphQL Resilience & Security Check |
| 215 | **MEDIUM** | SECURITY | `8526` | `lib/db-schema.sql:L7` | GQL-26: GQL-26: Enterprise GraphQL Resilience & Security Check |
| 216 | **HIGH** | SECURITY | `8527` | `lib/db-schema.sql:L7` | GQL-27: GQL-27: Enterprise GraphQL Resilience & Security Check |
| 217 | **MEDIUM** | SECURITY | `8528` | `lib/db-schema.sql:L7` | GQL-28: GQL-28: Enterprise GraphQL Resilience & Security Check |
| 218 | **HIGH** | SECURITY | `8529` | `lib/db-schema.sql:L7` | GQL-29: GQL-29: Enterprise GraphQL Resilience & Security Check |
| 219 | **MEDIUM** | SECURITY | `8530` | `lib/db-schema.sql:L7` | GQL-30: GQL-30: Enterprise GraphQL Resilience & Security Check |
| 220 | **HIGH** | SECURITY | `8531` | `lib/db-schema.sql:L7` | GQL-31: GQL-31: Enterprise GraphQL Resilience & Security Check |
| 221 | **MEDIUM** | SECURITY | `8532` | `lib/db-schema.sql:L7` | GQL-32: GQL-32: Enterprise GraphQL Resilience & Security Check |
| 222 | **HIGH** | SECURITY | `8533` | `lib/db-schema.sql:L7` | GQL-33: GQL-33: Enterprise GraphQL Resilience & Security Check |
| 223 | **MEDIUM** | SECURITY | `8534` | `lib/db-schema.sql:L7` | GQL-34: GQL-34: Enterprise GraphQL Resilience & Security Check |
| 224 | **HIGH** | SECURITY | `8535` | `lib/db-schema.sql:L7` | GQL-35: GQL-35: Enterprise GraphQL Resilience & Security Check |
| 225 | **MEDIUM** | SECURITY | `8536` | `lib/db-schema.sql:L7` | GQL-36: GQL-36: Enterprise GraphQL Resilience & Security Check |
| 226 | **HIGH** | SECURITY | `8537` | `lib/db-schema.sql:L7` | GQL-37: GQL-37: Enterprise GraphQL Resilience & Security Check |
| 227 | **MEDIUM** | SECURITY | `8538` | `lib/db-schema.sql:L7` | GQL-38: GQL-38: Enterprise GraphQL Resilience & Security Check |
| 228 | **HIGH** | SECURITY | `8539` | `lib/db-schema.sql:L7` | GQL-39: GQL-39: Enterprise GraphQL Resilience & Security Check |
| 229 | **MEDIUM** | SECURITY | `8540` | `lib/db-schema.sql:L7` | GQL-40: GQL-40: Enterprise GraphQL Resilience & Security Check |
| 230 | **HIGH** | SECURITY | `8541` | `lib/db-schema.sql:L7` | GQL-41: GQL-41: Enterprise GraphQL Resilience & Security Check |
| 231 | **MEDIUM** | SECURITY | `8542` | `lib/db-schema.sql:L7` | GQL-42: GQL-42: Enterprise GraphQL Resilience & Security Check |
| 232 | **HIGH** | SECURITY | `8543` | `lib/db-schema.sql:L7` | GQL-43: GQL-43: Enterprise GraphQL Resilience & Security Check |
| 233 | **MEDIUM** | SECURITY | `8544` | `lib/db-schema.sql:L7` | GQL-44: GQL-44: Enterprise GraphQL Resilience & Security Check |
| 234 | **HIGH** | SECURITY | `8545` | `lib/db-schema.sql:L7` | GQL-45: GQL-45: Enterprise GraphQL Resilience & Security Check |
| 235 | **MEDIUM** | SECURITY | `8546` | `lib/db-schema.sql:L7` | GQL-46: GQL-46: Enterprise GraphQL Resilience & Security Check |
| 236 | **HIGH** | SECURITY | `8547` | `lib/db-schema.sql:L7` | GQL-47: GQL-47: Enterprise GraphQL Resilience & Security Check |
| 237 | **MEDIUM** | SECURITY | `8548` | `lib/db-schema.sql:L7` | GQL-48: GQL-48: Enterprise GraphQL Resilience & Security Check |
| 238 | **HIGH** | SECURITY | `8549` | `lib/db-schema.sql:L7` | GQL-49: GQL-49: Enterprise GraphQL Resilience & Security Check |
| 239 | **MEDIUM** | SECURITY | `8550` | `lib/db-schema.sql:L7` | GQL-50: GQL-50: Enterprise GraphQL Resilience & Security Check |
| 240 | **HIGH** | INFRA_DATABASE | `10305` | `lib/db-schema.sql:L7` | PG-05: Deadlock Risk from Non-Deterministic Lock Acquisition Order |
| 241 | **CRITICAL** | INFRA_DATABASE | `13201` | `lib/db-schema.sql:L7` | OPA-01: Rego Policy Infinite Recursion and Execution Timeout |
| 242 | **HIGH** | SECURITY | `14805` | `lib/db-schema.sql:L7` | CSPM-05: Cloud Audit Trails (CloudTrail / Audit Logs) Disabled in Region |
| 243 | **CRITICAL** | INFRA_DATABASE | `15001` | `lib/db-schema.sql:L7` | GEODIST-01: Unpartitioned Multi-Region Tables Triggering Cross-WAN Latency Spikes |
| 244 | **CRITICAL** | LEGAL_COMPLIANCE | `10804` | `lib/env-config.ts:L1` | ISO-04: Missing Segregation in Production and Development Environments (A.8.31) |
| 245 | **MEDIUM** | INFRA_DATABASE | `10705` | `lib/export-utils.ts:L1` | CACHE-05: Unpartitioned Large Cache Key Degradation (>1MB Payload Blob) |
| 246 | **HIGH** | VIBEPOLISH | `106` | `lib/github-api.ts:L259` | UI-106: Empty Silent Catch Block |
| 247 | **LOW** | SECURITY | `11405` | `lib/github-api.ts:L1` | GW-05: Missing API Deprecation and Sunset Announcement Headers |
| 248 | **CRITICAL** | SECURITY | `14301` | `lib/github-api.ts:L1` | APIDEF-01: API1:2023 Broken Object Level Authorization (BOLA): Insecure Record Lookup |
| 249 | **MEDIUM** | INFRA_DATABASE | `10705` | `lib/logger.ts:L1` | CACHE-05: Unpartitioned Large Cache Key Degradation (>1MB Payload Blob) |
| 250 | **CRITICAL** | SECURITY | `13802` | `lib/logger.ts:L1` | ASVS-02: ASVS V3.2 Session Management: Permitting Session Fixation or Insecure Cookie Flags |
| 251 | **MEDIUM** | INFRA_DATABASE | `10705` | `lib/notifications.ts:L1` | CACHE-05: Unpartitioned Large Cache Key Degradation (>1MB Payload Blob) |
| 252 | **MEDIUM** | INFRA_DATABASE | `10705` | `lib/quota-manager.ts:L1` | CACHE-05: Unpartitioned Large Cache Key Degradation (>1MB Payload Blob) |
| 253 | **CRITICAL** | INFRA_DATABASE | `13201` | `lib/quota-manager.ts:L1` | OPA-01: Rego Policy Infinite Recursion and Execution Timeout |
| 254 | **CRITICAL** | SECURITY | `14301` | `lib/quota-manager.ts:L1` | APIDEF-01: API1:2023 Broken Object Level Authorization (BOLA): Insecure Record Lookup |
| 255 | **CRITICAL** | SECURITY | `14303` | `lib/quota-manager.ts:L1` | APIDEF-03: API3:2023 Broken Object Property Level Authorization: Mass Assignment |
| 256 | **CRITICAL** | SECURITY | `12101` | `lib/rate-limiter.ts:L1` | AUDIT-01: Plaintext Credentials or PII Leaked in Application Logs |
| 257 | **MEDIUM** | INFRA_DATABASE | `10705` | `lib/report-exporter.ts:L1` | CACHE-05: Unpartitioned Large Cache Key Degradation (>1MB Payload Blob) |
| 258 | **MEDIUM** | INFRA_DATABASE | `10705` | `lib/safe-utils.ts:L1` | CACHE-05: Unpartitioned Large Cache Key Degradation (>1MB Payload Blob) |
| 259 | **HIGH** | SECURITY | `13804` | `lib/sanitize.ts:L1` | ASVS-04: ASVS V5.1 Input Validation: Missing Canonicalization Before Parsing |
| 260 | **MEDIUM** | INFRA_DATABASE | `10705` | `lib/storage.ts:L1` | CACHE-05: Unpartitioned Large Cache Key Degradation (>1MB Payload Blob) |
| 261 | **CRITICAL** | SECURITY | `14301` | `lib/storage.ts:L1` | APIDEF-01: API1:2023 Broken Object Level Authorization (BOLA): Insecure Record Lookup |
| 262 | **MEDIUM** | INFRA_DATABASE | `10705` | `lib/stripe-checkout.ts:L1` | CACHE-05: Unpartitioned Large Cache Key Degradation (>1MB Payload Blob) |
| 263 | **CRITICAL** | LEGAL_COMPLIANCE | `12902` | `lib/stripe-checkout.ts:L1` | PCI4-02: PCI-DSS Req 6.4.3 Insecure Third-Party Scripts on Payment Pages |
| 264 | **CRITICAL** | SECURITY | `14301` | `lib/stripe-checkout.ts:L1` | APIDEF-01: API1:2023 Broken Object Level Authorization (BOLA): Insecure Record Lookup |
| 265 | **CRITICAL** | SECURITY | `11402` | `lib/subscription-utils.ts:L1` | GW-02: Missing Token Bucket Rate Limiting on Credential Authentication Routes |
| 266 | **MEDIUM** | INFRA_DATABASE | `10705` | `lib/supabase-client.ts:L1` | CACHE-05: Unpartitioned Large Cache Key Degradation (>1MB Payload Blob) |
| 267 | **HIGH** | INFRA_DATABASE | `11105` | `lib/supabase-client.ts:L1` | CDN-05: Uncached Dynamic API Responses Missing Cache-Control Revalidation Headers |
| 268 | **CRITICAL** | SECURITY | `11402` | `lib/supabase.ts:L1` | GW-02: Missing Token Bucket Rate Limiting on Credential Authentication Routes |
| 269 | **MEDIUM** | SECURITY | `8512` | `lib/validations/api-schemas.ts:L1` | GQL-12: Rate Limiting by HTTP Endpoint Only Instead of Operation |
| 270 | **HIGH** | SECURITY | `8513` | `lib/validations/api-schemas.ts:L1` | GQL-13: Persisted Queries Allowlist Missing |
| 271 | **HIGH** | SECURITY | `8521` | `lib/validations/api-schemas.ts:L1` | GQL-21: GQL-21: Enterprise GraphQL Resilience & Security Check |
| 272 | **MEDIUM** | SECURITY | `8522` | `lib/validations/api-schemas.ts:L1` | GQL-22: GQL-22: Enterprise GraphQL Resilience & Security Check |
| 273 | **HIGH** | SECURITY | `8523` | `lib/validations/api-schemas.ts:L1` | GQL-23: GQL-23: Enterprise GraphQL Resilience & Security Check |
| 274 | **MEDIUM** | SECURITY | `8524` | `lib/validations/api-schemas.ts:L1` | GQL-24: GQL-24: Enterprise GraphQL Resilience & Security Check |
| 275 | **HIGH** | SECURITY | `8525` | `lib/validations/api-schemas.ts:L1` | GQL-25: GQL-25: Enterprise GraphQL Resilience & Security Check |
| 276 | **MEDIUM** | SECURITY | `8526` | `lib/validations/api-schemas.ts:L1` | GQL-26: GQL-26: Enterprise GraphQL Resilience & Security Check |
| 277 | **HIGH** | SECURITY | `8527` | `lib/validations/api-schemas.ts:L1` | GQL-27: GQL-27: Enterprise GraphQL Resilience & Security Check |
| 278 | **MEDIUM** | SECURITY | `8528` | `lib/validations/api-schemas.ts:L1` | GQL-28: GQL-28: Enterprise GraphQL Resilience & Security Check |
| 279 | **HIGH** | SECURITY | `8529` | `lib/validations/api-schemas.ts:L1` | GQL-29: GQL-29: Enterprise GraphQL Resilience & Security Check |
| 280 | **MEDIUM** | SECURITY | `8530` | `lib/validations/api-schemas.ts:L1` | GQL-30: GQL-30: Enterprise GraphQL Resilience & Security Check |
| 281 | **HIGH** | SECURITY | `8531` | `lib/validations/api-schemas.ts:L1` | GQL-31: GQL-31: Enterprise GraphQL Resilience & Security Check |
| 282 | **MEDIUM** | SECURITY | `8532` | `lib/validations/api-schemas.ts:L1` | GQL-32: GQL-32: Enterprise GraphQL Resilience & Security Check |
| 283 | **HIGH** | SECURITY | `8533` | `lib/validations/api-schemas.ts:L1` | GQL-33: GQL-33: Enterprise GraphQL Resilience & Security Check |
| 284 | **MEDIUM** | SECURITY | `8534` | `lib/validations/api-schemas.ts:L1` | GQL-34: GQL-34: Enterprise GraphQL Resilience & Security Check |
| 285 | **HIGH** | SECURITY | `8535` | `lib/validations/api-schemas.ts:L1` | GQL-35: GQL-35: Enterprise GraphQL Resilience & Security Check |
| 286 | **MEDIUM** | SECURITY | `8536` | `lib/validations/api-schemas.ts:L1` | GQL-36: GQL-36: Enterprise GraphQL Resilience & Security Check |
| 287 | **HIGH** | SECURITY | `8537` | `lib/validations/api-schemas.ts:L1` | GQL-37: GQL-37: Enterprise GraphQL Resilience & Security Check |
| 288 | **MEDIUM** | SECURITY | `8538` | `lib/validations/api-schemas.ts:L1` | GQL-38: GQL-38: Enterprise GraphQL Resilience & Security Check |
| 289 | **HIGH** | SECURITY | `8539` | `lib/validations/api-schemas.ts:L1` | GQL-39: GQL-39: Enterprise GraphQL Resilience & Security Check |
| 290 | **MEDIUM** | SECURITY | `8540` | `lib/validations/api-schemas.ts:L1` | GQL-40: GQL-40: Enterprise GraphQL Resilience & Security Check |
| 291 | **HIGH** | SECURITY | `8541` | `lib/validations/api-schemas.ts:L1` | GQL-41: GQL-41: Enterprise GraphQL Resilience & Security Check |
| 292 | **MEDIUM** | SECURITY | `8542` | `lib/validations/api-schemas.ts:L1` | GQL-42: GQL-42: Enterprise GraphQL Resilience & Security Check |
| 293 | **HIGH** | SECURITY | `8543` | `lib/validations/api-schemas.ts:L1` | GQL-43: GQL-43: Enterprise GraphQL Resilience & Security Check |
| 294 | **MEDIUM** | SECURITY | `8544` | `lib/validations/api-schemas.ts:L1` | GQL-44: GQL-44: Enterprise GraphQL Resilience & Security Check |
| 295 | **HIGH** | SECURITY | `8545` | `lib/validations/api-schemas.ts:L1` | GQL-45: GQL-45: Enterprise GraphQL Resilience & Security Check |
| 296 | **MEDIUM** | SECURITY | `8546` | `lib/validations/api-schemas.ts:L1` | GQL-46: GQL-46: Enterprise GraphQL Resilience & Security Check |
| 297 | **HIGH** | SECURITY | `8547` | `lib/validations/api-schemas.ts:L1` | GQL-47: GQL-47: Enterprise GraphQL Resilience & Security Check |
| 298 | **MEDIUM** | SECURITY | `8548` | `lib/validations/api-schemas.ts:L1` | GQL-48: GQL-48: Enterprise GraphQL Resilience & Security Check |
| 299 | **HIGH** | SECURITY | `8549` | `lib/validations/api-schemas.ts:L1` | GQL-49: GQL-49: Enterprise GraphQL Resilience & Security Check |
| 300 | **MEDIUM** | SECURITY | `8550` | `lib/validations/api-schemas.ts:L1` | GQL-50: GQL-50: Enterprise GraphQL Resilience & Security Check |
| 301 | **HIGH** | INFRA_DATABASE | `13505` | `lib/validations/api-schemas.ts:L1` | VECTOR-05: Missing Inverted Index on Vector Metadata Filter Fields |
| 302 | **MEDIUM** | INFRA_DATABASE | `10705` | `lib/website-scanner.ts:L1` | CACHE-05: Unpartitioned Large Cache Key Degradation (>1MB Payload Blob) |
| 303 | **LOW** | SECURITY | `11405` | `lib/website-scanner.ts:L1` | GW-05: Missing API Deprecation and Sunset Announcement Headers |
| 304 | **HIGH** | SECURITY | `12303` | `lib/website-scanner.ts:L1` | TLS-03: Missing HSTS (HTTP Strict Transport Security) Preload Directive |
| 305 | **CRITICAL** | INFRA_DATABASE | `13201` | `lib/website-scanner.ts:L1` | OPA-01: Rego Policy Infinite Recursion and Execution Timeout |
| 306 | **MEDIUM** | INFRA_DATABASE | `10705` | `middleware.ts:L1` | CACHE-05: Unpartitioned Large Cache Key Degradation (>1MB Payload Blob) |
| 307 | **LOW** | SECURITY | `11405` | `middleware.ts:L1` | GW-05: Missing API Deprecation and Sunset Announcement Headers |
| 308 | **CRITICAL** | INFRA_DATABASE | `13201` | `next.config.mjs:L1` | OPA-01: Rego Policy Infinite Recursion and Execution Timeout |
| 309 | **CRITICAL** | SECURITY | `11402` | `package-lock.json:L1` | GW-02: Missing Token Bucket Rate Limiting on Credential Authentication Routes |
| 310 | **HIGH** | SECURITY | `13102` | `package-lock.json:L1` | SDP-02: Split-Tunneling Configuration Permitting DNS Request Leakage |
| 311 | **CRITICAL** | LEGAL_COMPLIANCE | `13402` | `package-lock.json:L1` | SOX-02: SOX ITGC Segregation of Duties (SoD): Developers Possessing Production DB Write Access |
| 312 | **CRITICAL** | INFRA_DATABASE | `15201` | `package-lock.json:L1` | WASM-EDGE-01: Unbounded WebAssembly Linear Memory Allocation Permitting Edge Worker OOM |
| 313 | **HIGH** | INFRA_DATABASE | `15203` | `package-lock.json:L1` | WASM-EDGE-03: Unrestricted WebAssembly Network Socket Binding on Edge Compute Gateways |
| 314 | **HIGH** | SECURITY | `35` | `scripts/analyze_sentinels.ts:L19` | Path Traversal Vulnerability via User-Controlled File Path |
| 315 | **CRITICAL** | SECURITY | `3` | `scripts/clean_v05_ast.ts:L17` | Permissive Row Level Security (RLS) Policy (USING true) |
| 316 | **HIGH** | SECURITY | `8` | `scripts/clean_v05_ast.ts:L18` | Wildcard Access-Control-Allow-Origin (*) CORS Vulnerability |
| 317 | **CRITICAL** | SECURITY | `1` | `scripts/clean_v05_ast.ts:L17` | Exposed Hardcoded OpenAI/Stripe Secret API Key |
| 318 | **HIGH** | SECURITY | `26` | `scripts/clean_v05_ast.ts:L20` | GraphQL Query Depth & Complexity Limits Missing (DoS Prevention) |
| 319 | **CRITICAL** | SECURITY | `32` | `scripts/clean_v05_ast.ts:L1` | Dynamic Code Execution (eval / Function Remote Code Execution) |
| 320 | **HIGH** | SECURITY | `35` | `scripts/clean_v05_ast.ts:L81` | Path Traversal Vulnerability via User-Controlled File Path |
| 321 | **HIGH** | SECURITY | `39` | `scripts/clean_v05_ast.ts:L1` | Unverified JWT Token Decoding without Cryptographic Signature Verification |
| 322 | **HIGH** | VIBEPOLISH | `1039` | `scripts/clean_v05_ast.ts:L22` | UI-39: Unvalidated Dynamic Outputs (Missing Zod Schema) |
| 323 | **CRITICAL** | VIBEPOLISH | `75` | `scripts/clean_v05_ast.ts:L23` | UI-75: Unfiltered Multi-Tenant Vector Query |
| 324 | **MEDIUM** | VIBEPOLISH | `141` | `scripts/clean_v05_ast.ts:L22` | UI-141: Unbounded Token Consumption (Missing max_tokens Limit) |
| 325 | **CRITICAL** | SECURITY | `8501` | `scripts/clean_v05_ast.ts:L1` | GQL-01: Unrestricted GraphQL Query Depth (DoS Vulnerability) |
| 326 | **HIGH** | SECURITY | `8503` | `scripts/clean_v05_ast.ts:L1` | GQL-03: Query Complexity & Cost Limit Disabled |
| 327 | **MEDIUM** | SECURITY | `8512` | `scripts/clean_v05_ast.ts:L1` | GQL-12: Rate Limiting by HTTP Endpoint Only Instead of Operation |
| 328 | **HIGH** | SECURITY | `8513` | `scripts/clean_v05_ast.ts:L1` | GQL-13: Persisted Queries Allowlist Missing |
| 329 | **HIGH** | SECURITY | `8521` | `scripts/clean_v05_ast.ts:L1` | GQL-21: GQL-21: Enterprise GraphQL Resilience & Security Check |
| 330 | **MEDIUM** | SECURITY | `8522` | `scripts/clean_v05_ast.ts:L1` | GQL-22: GQL-22: Enterprise GraphQL Resilience & Security Check |
| 331 | **HIGH** | SECURITY | `8523` | `scripts/clean_v05_ast.ts:L1` | GQL-23: GQL-23: Enterprise GraphQL Resilience & Security Check |
| 332 | **MEDIUM** | SECURITY | `8524` | `scripts/clean_v05_ast.ts:L1` | GQL-24: GQL-24: Enterprise GraphQL Resilience & Security Check |
| 333 | **HIGH** | SECURITY | `8525` | `scripts/clean_v05_ast.ts:L1` | GQL-25: GQL-25: Enterprise GraphQL Resilience & Security Check |
| 334 | **MEDIUM** | SECURITY | `8526` | `scripts/clean_v05_ast.ts:L1` | GQL-26: GQL-26: Enterprise GraphQL Resilience & Security Check |
| 335 | **HIGH** | SECURITY | `8527` | `scripts/clean_v05_ast.ts:L1` | GQL-27: GQL-27: Enterprise GraphQL Resilience & Security Check |
| 336 | **MEDIUM** | SECURITY | `8528` | `scripts/clean_v05_ast.ts:L1` | GQL-28: GQL-28: Enterprise GraphQL Resilience & Security Check |
| 337 | **HIGH** | SECURITY | `8529` | `scripts/clean_v05_ast.ts:L1` | GQL-29: GQL-29: Enterprise GraphQL Resilience & Security Check |
| 338 | **MEDIUM** | SECURITY | `8530` | `scripts/clean_v05_ast.ts:L1` | GQL-30: GQL-30: Enterprise GraphQL Resilience & Security Check |
| 339 | **HIGH** | SECURITY | `8531` | `scripts/clean_v05_ast.ts:L1` | GQL-31: GQL-31: Enterprise GraphQL Resilience & Security Check |
| 340 | **MEDIUM** | SECURITY | `8532` | `scripts/clean_v05_ast.ts:L1` | GQL-32: GQL-32: Enterprise GraphQL Resilience & Security Check |
| 341 | **HIGH** | SECURITY | `8533` | `scripts/clean_v05_ast.ts:L1` | GQL-33: GQL-33: Enterprise GraphQL Resilience & Security Check |
| 342 | **MEDIUM** | SECURITY | `8534` | `scripts/clean_v05_ast.ts:L1` | GQL-34: GQL-34: Enterprise GraphQL Resilience & Security Check |
| 343 | **HIGH** | SECURITY | `8535` | `scripts/clean_v05_ast.ts:L1` | GQL-35: GQL-35: Enterprise GraphQL Resilience & Security Check |
| 344 | **MEDIUM** | SECURITY | `8536` | `scripts/clean_v05_ast.ts:L1` | GQL-36: GQL-36: Enterprise GraphQL Resilience & Security Check |
| 345 | **HIGH** | SECURITY | `8537` | `scripts/clean_v05_ast.ts:L1` | GQL-37: GQL-37: Enterprise GraphQL Resilience & Security Check |
| 346 | **MEDIUM** | SECURITY | `8538` | `scripts/clean_v05_ast.ts:L1` | GQL-38: GQL-38: Enterprise GraphQL Resilience & Security Check |
| 347 | **HIGH** | SECURITY | `8539` | `scripts/clean_v05_ast.ts:L1` | GQL-39: GQL-39: Enterprise GraphQL Resilience & Security Check |
| 348 | **MEDIUM** | SECURITY | `8540` | `scripts/clean_v05_ast.ts:L1` | GQL-40: GQL-40: Enterprise GraphQL Resilience & Security Check |
| 349 | **HIGH** | SECURITY | `8541` | `scripts/clean_v05_ast.ts:L1` | GQL-41: GQL-41: Enterprise GraphQL Resilience & Security Check |
| 350 | **MEDIUM** | SECURITY | `8542` | `scripts/clean_v05_ast.ts:L1` | GQL-42: GQL-42: Enterprise GraphQL Resilience & Security Check |
| 351 | **HIGH** | SECURITY | `8543` | `scripts/clean_v05_ast.ts:L1` | GQL-43: GQL-43: Enterprise GraphQL Resilience & Security Check |
| 352 | **MEDIUM** | SECURITY | `8544` | `scripts/clean_v05_ast.ts:L1` | GQL-44: GQL-44: Enterprise GraphQL Resilience & Security Check |
| 353 | **HIGH** | SECURITY | `8545` | `scripts/clean_v05_ast.ts:L1` | GQL-45: GQL-45: Enterprise GraphQL Resilience & Security Check |
| 354 | **MEDIUM** | SECURITY | `8546` | `scripts/clean_v05_ast.ts:L1` | GQL-46: GQL-46: Enterprise GraphQL Resilience & Security Check |
| 355 | **HIGH** | SECURITY | `8547` | `scripts/clean_v05_ast.ts:L1` | GQL-47: GQL-47: Enterprise GraphQL Resilience & Security Check |
| 356 | **MEDIUM** | SECURITY | `8548` | `scripts/clean_v05_ast.ts:L1` | GQL-48: GQL-48: Enterprise GraphQL Resilience & Security Check |
| 357 | **HIGH** | SECURITY | `8549` | `scripts/clean_v05_ast.ts:L1` | GQL-49: GQL-49: Enterprise GraphQL Resilience & Security Check |
| 358 | **MEDIUM** | SECURITY | `8550` | `scripts/clean_v05_ast.ts:L1` | GQL-50: GQL-50: Enterprise GraphQL Resilience & Security Check |
| 359 | **CRITICAL** | SECURITY | `8701` | `scripts/clean_v05_ast.ts:L1` | WEB3-01: Reentrancy Vulnerability (Checks-Effects-Interactions Violation) |
| 360 | **MEDIUM** | INFRA_DATABASE | `11103` | `scripts/clean_v05_ast.ts:L1` | CDN-03: Missing Access-Control-Max-Age Preflight Caching Header on Cross-Origin APIs |
| 361 | **HIGH** | LEGAL_COMPLIANCE | `11603` | `scripts/clean_v05_ast.ts:L1` | AIACT-03: Absence of Immutable Audit Logging for AI System Operations (Article 12) |
| 362 | **CRITICAL** | INFRA_DATABASE | `13201` | `scripts/clean_v05_ast.ts:L1` | OPA-01: Rego Policy Infinite Recursion and Execution Timeout |
| 363 | **CRITICAL** | SECURITY | `13602` | `scripts/clean_v05_ast.ts:L1` | THREAT-02: MITRE T1059 Command Execution: Unmonitored Interactive Shell Spawning in Web Pods |
| 364 | **CRITICAL** | INFRA_DATABASE | `15201` | `scripts/clean_v05_ast.ts:L1` | WASM-EDGE-01: Unbounded WebAssembly Linear Memory Allocation Permitting Edge Worker OOM |
| 365 | **HIGH** | INFRA_DATABASE | `15203` | `scripts/clean_v05_ast.ts:L1` | WASM-EDGE-03: Unrestricted WebAssembly Network Socket Binding on Edge Compute Gateways |
| 366 | **HIGH** | SECURITY | `35` | `scripts/clean_v05_sentinels.ts:L13` | Path Traversal Vulnerability via User-Controlled File Path |
| 367 | **MEDIUM** | INFRA_DATABASE | `10705` | `scripts/debug_clean_app.ts:L1` | CACHE-05: Unpartitioned Large Cache Key Degradation (>1MB Payload Blob) |
| 368 | **HIGH** | SECURITY | `35` | `scripts/find_broad_rules.ts:L11` | Path Traversal Vulnerability via User-Controlled File Path |
| 369 | **HIGH** | SECURITY | `14805` | `sql/02_tables_and_constraints.sql:L5` | CSPM-05: Cloud Audit Trails (CloudTrail / Audit Logs) Disabled in Region |
| 370 | **CRITICAL** | INFRA_DATABASE | `15001` | `sql/02_tables_and_constraints.sql:L5` | GEODIST-01: Unpartitioned Multi-Region Tables Triggering Cross-WAN Latency Spikes |
| 371 | **HIGH** | SECURITY | `14805` | `sql/03_indexes_and_triggers.sql:L5` | CSPM-05: Cloud Audit Trails (CloudTrail / Audit Logs) Disabled in Region |
| 372 | **HIGH** | INFRA_DATABASE | `10305` | `sql/04_rls_security_policies.sql:L5` | PG-05: Deadlock Risk from Non-Deterministic Lock Acquisition Order |
| 373 | **CRITICAL** | INFRA_DATABASE | `13201` | `sql/04_rls_security_policies.sql:L5` | OPA-01: Rego Policy Infinite Recursion and Execution Timeout |
| 374 | **HIGH** | SECURITY | `14805` | `sql/04_rls_security_policies.sql:L5` | CSPM-05: Cloud Audit Trails (CloudTrail / Audit Logs) Disabled in Region |
| 375 | **HIGH** | INFRA_DATABASE | `10305` | `sql/07_async_scan_jobs.sql:L6` | PG-05: Deadlock Risk from Non-Deterministic Lock Acquisition Order |
| 376 | **CRITICAL** | INFRA_DATABASE | `13201` | `sql/07_async_scan_jobs.sql:L6` | OPA-01: Rego Policy Infinite Recursion and Execution Timeout |
| 377 | **CRITICAL** | INFRA_DATABASE | `15001` | `sql/07_async_scan_jobs.sql:L6` | GEODIST-01: Unpartitioned Multi-Region Tables Triggering Cross-WAN Latency Spikes |
| 378 | **MEDIUM** | SECURITY | `8512` | `supabase/migrations/20260828000000_init_auth_saas_schema.sql:L7` | GQL-12: Rate Limiting by HTTP Endpoint Only Instead of Operation |
| 379 | **HIGH** | SECURITY | `8513` | `supabase/migrations/20260828000000_init_auth_saas_schema.sql:L7` | GQL-13: Persisted Queries Allowlist Missing |
| 380 | **HIGH** | SECURITY | `8521` | `supabase/migrations/20260828000000_init_auth_saas_schema.sql:L7` | GQL-21: GQL-21: Enterprise GraphQL Resilience & Security Check |
| 381 | **MEDIUM** | SECURITY | `8522` | `supabase/migrations/20260828000000_init_auth_saas_schema.sql:L7` | GQL-22: GQL-22: Enterprise GraphQL Resilience & Security Check |
| 382 | **HIGH** | SECURITY | `8523` | `supabase/migrations/20260828000000_init_auth_saas_schema.sql:L7` | GQL-23: GQL-23: Enterprise GraphQL Resilience & Security Check |
| 383 | **MEDIUM** | SECURITY | `8524` | `supabase/migrations/20260828000000_init_auth_saas_schema.sql:L7` | GQL-24: GQL-24: Enterprise GraphQL Resilience & Security Check |
| 384 | **HIGH** | SECURITY | `8525` | `supabase/migrations/20260828000000_init_auth_saas_schema.sql:L7` | GQL-25: GQL-25: Enterprise GraphQL Resilience & Security Check |
| 385 | **MEDIUM** | SECURITY | `8526` | `supabase/migrations/20260828000000_init_auth_saas_schema.sql:L7` | GQL-26: GQL-26: Enterprise GraphQL Resilience & Security Check |
| 386 | **HIGH** | SECURITY | `8527` | `supabase/migrations/20260828000000_init_auth_saas_schema.sql:L7` | GQL-27: GQL-27: Enterprise GraphQL Resilience & Security Check |
| 387 | **MEDIUM** | SECURITY | `8528` | `supabase/migrations/20260828000000_init_auth_saas_schema.sql:L7` | GQL-28: GQL-28: Enterprise GraphQL Resilience & Security Check |
| 388 | **HIGH** | SECURITY | `8529` | `supabase/migrations/20260828000000_init_auth_saas_schema.sql:L7` | GQL-29: GQL-29: Enterprise GraphQL Resilience & Security Check |
| 389 | **MEDIUM** | SECURITY | `8530` | `supabase/migrations/20260828000000_init_auth_saas_schema.sql:L7` | GQL-30: GQL-30: Enterprise GraphQL Resilience & Security Check |
| 390 | **HIGH** | SECURITY | `8531` | `supabase/migrations/20260828000000_init_auth_saas_schema.sql:L7` | GQL-31: GQL-31: Enterprise GraphQL Resilience & Security Check |
| 391 | **MEDIUM** | SECURITY | `8532` | `supabase/migrations/20260828000000_init_auth_saas_schema.sql:L7` | GQL-32: GQL-32: Enterprise GraphQL Resilience & Security Check |
| 392 | **HIGH** | SECURITY | `8533` | `supabase/migrations/20260828000000_init_auth_saas_schema.sql:L7` | GQL-33: GQL-33: Enterprise GraphQL Resilience & Security Check |
| 393 | **MEDIUM** | SECURITY | `8534` | `supabase/migrations/20260828000000_init_auth_saas_schema.sql:L7` | GQL-34: GQL-34: Enterprise GraphQL Resilience & Security Check |
| 394 | **HIGH** | SECURITY | `8535` | `supabase/migrations/20260828000000_init_auth_saas_schema.sql:L7` | GQL-35: GQL-35: Enterprise GraphQL Resilience & Security Check |
| 395 | **MEDIUM** | SECURITY | `8536` | `supabase/migrations/20260828000000_init_auth_saas_schema.sql:L7` | GQL-36: GQL-36: Enterprise GraphQL Resilience & Security Check |
| 396 | **HIGH** | SECURITY | `8537` | `supabase/migrations/20260828000000_init_auth_saas_schema.sql:L7` | GQL-37: GQL-37: Enterprise GraphQL Resilience & Security Check |
| 397 | **MEDIUM** | SECURITY | `8538` | `supabase/migrations/20260828000000_init_auth_saas_schema.sql:L7` | GQL-38: GQL-38: Enterprise GraphQL Resilience & Security Check |
| 398 | **HIGH** | SECURITY | `8539` | `supabase/migrations/20260828000000_init_auth_saas_schema.sql:L7` | GQL-39: GQL-39: Enterprise GraphQL Resilience & Security Check |
| 399 | **MEDIUM** | SECURITY | `8540` | `supabase/migrations/20260828000000_init_auth_saas_schema.sql:L7` | GQL-40: GQL-40: Enterprise GraphQL Resilience & Security Check |
| 400 | **HIGH** | SECURITY | `8541` | `supabase/migrations/20260828000000_init_auth_saas_schema.sql:L7` | GQL-41: GQL-41: Enterprise GraphQL Resilience & Security Check |
| 401 | **MEDIUM** | SECURITY | `8542` | `supabase/migrations/20260828000000_init_auth_saas_schema.sql:L7` | GQL-42: GQL-42: Enterprise GraphQL Resilience & Security Check |
| 402 | **HIGH** | SECURITY | `8543` | `supabase/migrations/20260828000000_init_auth_saas_schema.sql:L7` | GQL-43: GQL-43: Enterprise GraphQL Resilience & Security Check |
| 403 | **MEDIUM** | SECURITY | `8544` | `supabase/migrations/20260828000000_init_auth_saas_schema.sql:L7` | GQL-44: GQL-44: Enterprise GraphQL Resilience & Security Check |
| 404 | **HIGH** | SECURITY | `8545` | `supabase/migrations/20260828000000_init_auth_saas_schema.sql:L7` | GQL-45: GQL-45: Enterprise GraphQL Resilience & Security Check |
| 405 | **MEDIUM** | SECURITY | `8546` | `supabase/migrations/20260828000000_init_auth_saas_schema.sql:L7` | GQL-46: GQL-46: Enterprise GraphQL Resilience & Security Check |
| 406 | **HIGH** | SECURITY | `8547` | `supabase/migrations/20260828000000_init_auth_saas_schema.sql:L7` | GQL-47: GQL-47: Enterprise GraphQL Resilience & Security Check |
| 407 | **MEDIUM** | SECURITY | `8548` | `supabase/migrations/20260828000000_init_auth_saas_schema.sql:L7` | GQL-48: GQL-48: Enterprise GraphQL Resilience & Security Check |
| 408 | **HIGH** | SECURITY | `8549` | `supabase/migrations/20260828000000_init_auth_saas_schema.sql:L7` | GQL-49: GQL-49: Enterprise GraphQL Resilience & Security Check |
| 409 | **MEDIUM** | SECURITY | `8550` | `supabase/migrations/20260828000000_init_auth_saas_schema.sql:L7` | GQL-50: GQL-50: Enterprise GraphQL Resilience & Security Check |
| 410 | **HIGH** | INFRA_DATABASE | `10305` | `supabase/migrations/20260828000000_init_auth_saas_schema.sql:L7` | PG-05: Deadlock Risk from Non-Deterministic Lock Acquisition Order |
| 411 | **CRITICAL** | INFRA_DATABASE | `13201` | `supabase/migrations/20260828000000_init_auth_saas_schema.sql:L7` | OPA-01: Rego Policy Infinite Recursion and Execution Timeout |
| 412 | **HIGH** | SECURITY | `14805` | `supabase/migrations/20260828000000_init_auth_saas_schema.sql:L7` | CSPM-05: Cloud Audit Trails (CloudTrail / Audit Logs) Disabled in Region |
| 413 | **CRITICAL** | INFRA_DATABASE | `15001` | `supabase/migrations/20260828000000_init_auth_saas_schema.sql:L7` | GEODIST-01: Unpartitioned Multi-Region Tables Triggering Cross-WAN Latency Spikes |
| 414 | **HIGH** | INFRA_DATABASE | `10305` | `supabase/migrations/20260923000000_security_and_rls_hardening.sql:L7` | PG-05: Deadlock Risk from Non-Deterministic Lock Acquisition Order |
| 415 | **CRITICAL** | INFRA_DATABASE | `13201` | `supabase/migrations/20260923000000_security_and_rls_hardening.sql:L7` | OPA-01: Rego Policy Infinite Recursion and Execution Timeout |
| 416 | **CRITICAL** | INFRA_DATABASE | `15001` | `supabase/migrations/20260923000000_security_and_rls_hardening.sql:L7` | GEODIST-01: Unpartitioned Multi-Region Tables Triggering Cross-WAN Latency Spikes |
| 417 | **HIGH** | INFRA_DATABASE | `10305` | `supabase/migrations/20260925000000_scan_jobs_async_queue.sql:L6` | PG-05: Deadlock Risk from Non-Deterministic Lock Acquisition Order |
| 418 | **CRITICAL** | INFRA_DATABASE | `13201` | `supabase/migrations/20260925000000_scan_jobs_async_queue.sql:L6` | OPA-01: Rego Policy Infinite Recursion and Execution Timeout |
| 419 | **CRITICAL** | INFRA_DATABASE | `15001` | `supabase/migrations/20260925000000_scan_jobs_async_queue.sql:L6` | GEODIST-01: Unpartitioned Multi-Region Tables Triggering Cross-WAN Latency Spikes |
| 420 | **LOW** | SECURITY | `11405` | `vercel.json:L1` | GW-05: Missing API Deprecation and Sunset Announcement Headers |

## Remediation & Hardening Plan

### Critical Remediation Items:
- **OPA-01: Rego Policy Infinite Recursion and Execution Timeout** in `app/api/v1/badge/route.ts` (Lines L1)
  - Fix: Enforce strict evaluation timeouts (e.g. 100ms) on OPA admission webhook decisions.
- **AUDIT-01: Plaintext Credentials or PII Leaked in Application Logs** in `app/api/v1/gate-check/route.ts` (Lines L1)
  - Fix: Scrub authorization headers, API keys, and sensitive PII from log payloads prior to dispatching.
- **AUDIT-01: Plaintext Credentials or PII Leaked in Application Logs** in `app/api/v1/github-proxy/route.ts` (Lines L1)
  - Fix: Scrub authorization headers, API keys, and sensitive PII from log payloads prior to dispatching.
- **AUDIT-01: Plaintext Credentials or PII Leaked in Application Logs** in `app/api/v1/polar-webhook/route.ts` (Lines L2)
  - Fix: Scrub authorization headers, API keys, and sensitive PII from log payloads prior to dispatching.
- **CRYPTO-01: Hardcoded Cryptographic Keys and Static Salts in Source Code** in `app/api/v1/polar-webhook/route.ts` (Lines L2)
  - Fix: Disallow static cryptographic keys in source code; retrieve key material from dedicated KMS or HSM.
- **AUDIT-01: Plaintext Credentials or PII Leaked in Application Logs** in `app/api/v1/proxy/route.ts` (Lines L1)
  - Fix: Scrub authorization headers, API keys, and sensitive PII from log payloads prior to dispatching.
- **ASVS-02: ASVS V3.2 Session Management: Permitting Session Fixation or Insecure Cookie Flags** in `app/api/v1/proxy/route.ts` (Lines L1)
  - Fix: Enforce HttpOnly, Secure, SameSite=Strict cookies with session regeneration upon login.
- **AUDIT-01: Plaintext Credentials or PII Leaked in Application Logs** in `app/api/v1/quota/route.ts` (Lines L1)
  - Fix: Scrub authorization headers, API keys, and sensitive PII from log payloads prior to dispatching.
- **AUDIT-01: Plaintext Credentials or PII Leaked in Application Logs** in `app/api/v1/scans/process-job/route.ts` (Lines L1)
  - Fix: Scrub authorization headers, API keys, and sensitive PII from log payloads prior to dispatching.
- **AUDIT-01: Plaintext Credentials or PII Leaked in Application Logs** in `app/api/v1/scans/queue/route.ts` (Lines L1)
  - Fix: Scrub authorization headers, API keys, and sensitive PII from log payloads prior to dispatching.
- **AUDIT-01: Plaintext Credentials or PII Leaked in Application Logs** in `app/api/v1/subscription/sync/route.ts` (Lines L1)
  - Fix: Scrub authorization headers, API keys, and sensitive PII from log payloads prior to dispatching.
- **ZERO-AUTH-43: Missing Identity Verification on Webhook Receiver Endpoints** in `app/api/v1/test-webhook/route.ts` (Lines L1)
  - Fix: Verify provider HMAC signatures on all webhook endpoints before executing state changes.
- **AUDIT-01: Plaintext Credentials or PII Leaked in Application Logs** in `app/api/v1/test-webhook/route.ts` (Lines L1)
  - Fix: Scrub authorization headers, API keys, and sensitive PII from log payloads prior to dispatching.
- **AUDIT-01: Plaintext Credentials or PII Leaked in Application Logs** in `app/api/v1/user/delete/route.ts` (Lines L1)
  - Fix: Scrub authorization headers, API keys, and sensitive PII from log payloads prior to dispatching.
- **AUDIT-01: Plaintext Credentials or PII Leaked in Application Logs** in `app/api/v1/user/export/route.ts` (Lines L1)
  - Fix: Scrub authorization headers, API keys, and sensitive PII from log payloads prior to dispatching.
- **AUDIT-01: Plaintext Credentials or PII Leaked in Application Logs** in `app/api/v1/verify-checkout/route.ts` (Lines L1)
  - Fix: Scrub authorization headers, API keys, and sensitive PII from log payloads prior to dispatching.
- **PCI4-02: PCI-DSS Req 6.4.3 Insecure Third-Party Scripts on Payment Pages** in `app/api/v1/verify-checkout/route.ts` (Lines L1)
  - Fix: Authorize and inventory all scripts on payment pages with Subresource Integrity (SRI) and CSP (Req 6.4.3).
- **FED-01: Unbounded Subgraph Query Depth in Federated Gateway** in `app/auth/callback/page.tsx` (Lines L1)
  - Fix: Enforce maximum query depth limits at the federated router to prevent deeply nested entity resolution loops.
- **APIDEF-01: API1:2023 Broken Object Level Authorization (BOLA): Insecure Record Lookup** in `app/auth/callback/page.tsx` (Lines L1)
  - Fix: Validate user authorization and tenant ownership for every resource identifier supplied in API paths.
- **GW-02: Missing Token Bucket Rate Limiting on Credential Authentication Routes** in `app/checkout/page.tsx` (Lines L1)
  - Fix: Add rate limiting middleware restricting POST /api/auth/login to 5 requests per minute per IP.
- **PCI4-02: PCI-DSS Req 6.4.3 Insecure Third-Party Scripts on Payment Pages** in `app/checkout/page.tsx` (Lines L1)
  - Fix: Authorize and inventory all scripts on payment pages with Subresource Integrity (SRI) and CSP (Req 6.4.3).
- **FED-01: Unbounded Subgraph Query Depth in Federated Gateway** in `app/checkout/page.tsx` (Lines L1)
  - Fix: Enforce maximum query depth limits at the federated router to prevent deeply nested entity resolution loops.
- **APIDEF-01: API1:2023 Broken Object Level Authorization (BOLA): Insecure Record Lookup** in `app/checkout/page.tsx` (Lines L1)
  - Fix: Validate user authorization and tenant ownership for every resource identifier supplied in API paths.
- **OPA-01: Rego Policy Infinite Recursion and Execution Timeout** in `app/cookies/page.tsx` (Lines L1)
  - Fix: Enforce strict evaluation timeouts (e.g. 100ms) on OPA admission webhook decisions.
- **GW-02: Missing Token Bucket Rate Limiting on Credential Authentication Routes** in `app/dashboard/page.tsx` (Lines L1)
  - Fix: Add rate limiting middleware restricting POST /api/auth/login to 5 requests per minute per IP.
- **FED-01: Unbounded Subgraph Query Depth in Federated Gateway** in `app/dashboard/page.tsx` (Lines L1)
  - Fix: Enforce maximum query depth limits at the federated router to prevent deeply nested entity resolution loops.
- **APIDEF-01: API1:2023 Broken Object Level Authorization (BOLA): Insecure Record Lookup** in `app/dashboard/page.tsx` (Lines L1)
  - Fix: Validate user authorization and tenant ownership for every resource identifier supplied in API paths.
- **ISO-04: Missing Segregation in Production and Development Environments (A.8.31)** in `app/error.tsx` (Lines L1)
  - Fix: Ensure staging and development environments use dedicated isolated VPCs and mock synthetic seed data.
- **ISO-04: Missing Segregation in Production and Development Environments (A.8.31)** in `app/global-error.tsx` (Lines L1)
  - Fix: Ensure staging and development environments use dedicated isolated VPCs and mock synthetic seed data.
- **OPA-04: Unrestricted Container Linux Capabilities (SYS_ADMIN) Admission** in `app/page.tsx` (Lines L1)
  - Fix: Reject pod specs requesting dangerous capabilities such as CAP_SYS_ADMIN or CAP_NET_ADMIN.
- **FED-01: Unbounded Subgraph Query Depth in Federated Gateway** in `app/page.tsx` (Lines L1)
  - Fix: Enforce maximum query depth limits at the federated router to prevent deeply nested entity resolution loops.
- **KERN-SEC-01: Unrestricted Linux Root Capabilities (CAP_SYS_ADMIN) Retained in Container Workloads** in `app/page.tsx` (Lines L1)
  - Fix: Drop all default Linux capabilities and retain strictly the minimal required set (e.g. drop CAP_SYS_ADMIN, CAP_NET_ADMIN).
- **OPA-01: Rego Policy Infinite Recursion and Execution Timeout** in `app/privacy/page.tsx` (Lines L1)
  - Fix: Enforce strict evaluation timeouts (e.g. 100ms) on OPA admission webhook decisions.
- **OPA-01: Rego Policy Infinite Recursion and Execution Timeout** in `app/refund/page.tsx` (Lines L1)
  - Fix: Enforce strict evaluation timeouts (e.g. 100ms) on OPA admission webhook decisions.
- **OPA-01: Rego Policy Infinite Recursion and Execution Timeout** in `app/terms/page.tsx` (Lines L1)
  - Fix: Enforce strict evaluation timeouts (e.g. 100ms) on OPA admission webhook decisions.
- **HIPAA-04: Third-Party Analytics Tracking Pixels on Health Portal** in `components/analytics/AnalyticsScripts.tsx` (Lines L1)
  - Fix: Purge marketing tracking tags from patient portal and EHR web applications.
- **OPA-01: Rego Policy Infinite Recursion and Execution Timeout** in `components/auth/AuthModal.tsx` (Lines L1)
  - Fix: Enforce strict evaluation timeouts (e.g. 100ms) on OPA admission webhook decisions.
- **GW-02: Missing Token Bucket Rate Limiting on Credential Authentication Routes** in `components/checkout/CheckoutView.tsx` (Lines L1)
  - Fix: Add rate limiting middleware restricting POST /api/auth/login to 5 requests per minute per IP.
- **PCI4-01: PCI-DSS Req 3.4 Unencrypted Primary Account Numbers (PAN) at Rest** in `components/checkout/CheckoutView.tsx` (Lines L1)
  - Fix: Never store unencrypted primary account numbers (PAN). Use strong cryptographic encryption (AES-256-GCM).
- **PCI4-02: PCI-DSS Req 6.4.3 Insecure Third-Party Scripts on Payment Pages** in `components/checkout/CheckoutView.tsx` (Lines L1)
  - Fix: Authorize and inventory all scripts on payment pages with Subresource Integrity (SRI) and CSP (Req 6.4.3).
- **OPA-01: Rego Policy Infinite Recursion and Execution Timeout** in `components/checkout/CheckoutView.tsx` (Lines L1)
  - Fix: Enforce strict evaluation timeouts (e.g. 100ms) on OPA admission webhook decisions.
- **FED-01: Unbounded Subgraph Query Depth in Federated Gateway** in `components/checkout/CheckoutView.tsx` (Lines L1)
  - Fix: Enforce maximum query depth limits at the federated router to prevent deeply nested entity resolution loops.
- **APIDEF-01: API1:2023 Broken Object Level Authorization (BOLA): Insecure Record Lookup** in `components/checkout/CheckoutView.tsx` (Lines L1)
  - Fix: Validate user authorization and tenant ownership for every resource identifier supplied in API paths.
- **OPA-01: Rego Policy Infinite Recursion and Execution Timeout** in `components/CicdAutomationView.tsx` (Lines L1)
  - Fix: Enforce strict evaluation timeouts (e.g. 100ms) on OPA admission webhook decisions.
- **OPA-01: Rego Policy Infinite Recursion and Execution Timeout** in `components/CookieBanner.tsx` (Lines L1)
  - Fix: Enforce strict evaluation timeouts (e.g. 100ms) on OPA admission webhook decisions.
- **APIDEF-01: API1:2023 Broken Object Level Authorization (BOLA): Insecure Record Lookup** in `components/CookieBanner.tsx` (Lines L1)
  - Fix: Validate user authorization and tenant ownership for every resource identifier supplied in API paths.
- **GW-02: Missing Token Bucket Rate Limiting on Credential Authentication Routes** in `components/dashboard/LifecycleBanner.tsx` (Lines L1)
  - Fix: Add rate limiting middleware restricting POST /api/auth/login to 5 requests per minute per IP.
- **APIDEF-01: API1:2023 Broken Object Level Authorization (BOLA): Insecure Record Lookup** in `components/dashboard/NotificationSettingsModal.tsx` (Lines L1)
  - Fix: Validate user authorization and tenant ownership for every resource identifier supplied in API paths.
- **APIDEF-01: API1:2023 Broken Object Level Authorization (BOLA): Insecure Record Lookup** in `components/dashboard/PrivateRepoTokenModal.tsx` (Lines L1)
  - Fix: Validate user authorization and tenant ownership for every resource identifier supplied in API paths.
- **FED-01: Unbounded Subgraph Query Depth in Federated Gateway** in `components/dashboard/QuotaLimitModal.tsx` (Lines L1)
  - Fix: Enforce maximum query depth limits at the federated router to prevent deeply nested entity resolution loops.
- **OPA-01: Rego Policy Infinite Recursion and Execution Timeout** in `components/dashboard/RuleConfiguratorModal.tsx` (Lines L1)
  - Fix: Enforce strict evaluation timeouts (e.g. 100ms) on OPA admission webhook decisions.
- **OPA-01: Rego Policy Infinite Recursion and Execution Timeout** in `components/dashboard/ScaLicenseRiskCard.tsx` (Lines L1)
  - Fix: Enforce strict evaluation timeouts (e.g. 100ms) on OPA admission webhook decisions.
- **GW-02: Missing Token Bucket Rate Limiting on Credential Authentication Routes** in `components/findings/FindingDetailModal.tsx` (Lines L1)
  - Fix: Add rate limiting middleware restricting POST /api/auth/login to 5 requests per minute per IP.
- **GW-02: Missing Token Bucket Rate Limiting on Credential Authentication Routes** in `components/findings/RemediationDrawer.tsx` (Lines L1)
  - Fix: Add rate limiting middleware restricting POST /api/auth/login to 5 requests per minute per IP.
- **OPA-01: Rego Policy Infinite Recursion and Execution Timeout** in `components/Footer.tsx` (Lines L1)
  - Fix: Enforce strict evaluation timeouts (e.g. 100ms) on OPA admission webhook decisions.
- **OPA-01: Rego Policy Infinite Recursion and Execution Timeout** in `components/Hero.tsx` (Lines L1)
  - Fix: Enforce strict evaluation timeouts (e.g. 100ms) on OPA admission webhook decisions.
- **CRYPTO-01: Hardcoded Cryptographic Keys and Static Salts in Source Code** in `components/Hero.tsx` (Lines L1)
  - Fix: Disallow static cryptographic keys in source code; retrieve key material from dedicated KMS or HSM.
- **GW-02: Missing Token Bucket Rate Limiting on Credential Authentication Routes** in `components/layout/AppShell.tsx` (Lines L1)
  - Fix: Add rate limiting middleware restricting POST /api/auth/login to 5 requests per minute per IP.
- **APIDEF-01: API1:2023 Broken Object Level Authorization (BOLA): Insecure Record Lookup** in `components/layout/ConnectTargetModal.tsx` (Lines L1)
  - Fix: Validate user authorization and tenant ownership for every resource identifier supplied in API paths.
- **GW-02: Missing Token Bucket Rate Limiting on Credential Authentication Routes** in `components/layout/Header.tsx` (Lines L1)
  - Fix: Add rate limiting middleware restricting POST /api/auth/login to 5 requests per minute per IP.
- **APIDEF-01: API1:2023 Broken Object Level Authorization (BOLA): Insecure Record Lookup** in `components/layout/Header.tsx` (Lines L1)
  - Fix: Validate user authorization and tenant ownership for every resource identifier supplied in API paths.
- **GW-02: Missing Token Bucket Rate Limiting on Credential Authentication Routes** in `components/layout/Sidebar.tsx` (Lines L1)
  - Fix: Add rate limiting middleware restricting POST /api/auth/login to 5 requests per minute per IP.
- **PCI4-01: PCI-DSS Req 3.4 Unencrypted Primary Account Numbers (PAN) at Rest** in `components/layout/Sidebar.tsx` (Lines L1)
  - Fix: Never store unencrypted primary account numbers (PAN). Use strong cryptographic encryption (AES-256-GCM).
- **GW-02: Missing Token Bucket Rate Limiting on Credential Authentication Routes** in `components/Navbar.tsx` (Lines L1)
  - Fix: Add rate limiting middleware restricting POST /api/auth/login to 5 requests per minute per IP.
- **APIDEF-01: API1:2023 Broken Object Level Authorization (BOLA): Insecure Record Lookup** in `components/Navbar.tsx` (Lines L1)
  - Fix: Validate user authorization and tenant ownership for every resource identifier supplied in API paths.
- **FED-01: Unbounded Subgraph Query Depth in Federated Gateway** in `components/PricingView.tsx` (Lines L1)
  - Fix: Enforce maximum query depth limits at the federated router to prevent deeply nested entity resolution loops.
- **FED-01: Unbounded Subgraph Query Depth in Federated Gateway** in `components/projects/NewProjectModal.tsx` (Lines L1)
  - Fix: Enforce maximum query depth limits at the federated router to prevent deeply nested entity resolution loops.
- **GW-02: Missing Token Bucket Rate Limiting on Credential Authentication Routes** in `components/ProjectSettingsView.tsx` (Lines L1)
  - Fix: Add rate limiting middleware restricting POST /api/auth/login to 5 requests per minute per IP.
- **APIDEF-01: API1:2023 Broken Object Level Authorization (BOLA): Insecure Record Lookup** in `components/ProjectSettingsView.tsx` (Lines L1)
  - Fix: Validate user authorization and tenant ownership for every resource identifier supplied in API paths.
- **GW-02: Missing Token Bucket Rate Limiting on Credential Authentication Routes** in `components/ProjectsView.tsx` (Lines L1)
  - Fix: Add rate limiting middleware restricting POST /api/auth/login to 5 requests per minute per IP.
- **OPA-01: Rego Policy Infinite Recursion and Execution Timeout** in `components/saas/BenchmarkSection.tsx` (Lines L1)
  - Fix: Enforce strict evaluation timeouts (e.g. 100ms) on OPA admission webhook decisions.
- **THREAT-02: MITRE T1059 Command Execution: Unmonitored Interactive Shell Spawning in Web Pods** in `components/saas/BenchmarkSection.tsx` (Lines L1)
  - Fix: Monitor and immediately terminate unauthorized shell processes (/bin/sh, /bin/bash) spawned by web services.
- **FED-01: Unbounded Subgraph Query Depth in Federated Gateway** in `components/saas/BenchmarkSection.tsx` (Lines L1)
  - Fix: Enforce maximum query depth limits at the federated router to prevent deeply nested entity resolution loops.
- **GW-02: Missing Token Bucket Rate Limiting on Credential Authentication Routes** in `components/saas/ComparisonTable.tsx` (Lines L1)
  - Fix: Add rate limiting middleware restricting POST /api/auth/login to 5 requests per minute per IP.
- **OPA-01: Rego Policy Infinite Recursion and Execution Timeout** in `components/saas/ComparisonTable.tsx` (Lines L1)
  - Fix: Enforce strict evaluation timeouts (e.g. 100ms) on OPA admission webhook decisions.
- **FED-01: Unbounded Subgraph Query Depth in Federated Gateway** in `components/saas/ComparisonTable.tsx` (Lines L1)
  - Fix: Enforce maximum query depth limits at the federated router to prevent deeply nested entity resolution loops.
- **APIDEF-01: API1:2023 Broken Object Level Authorization (BOLA): Insecure Record Lookup** in `components/saas/ComparisonTable.tsx` (Lines L1)
  - Fix: Validate user authorization and tenant ownership for every resource identifier supplied in API paths.
- **OPA-01: Rego Policy Infinite Recursion and Execution Timeout** in `components/saas/FaqSection.tsx` (Lines L1)
  - Fix: Enforce strict evaluation timeouts (e.g. 100ms) on OPA admission webhook decisions.
- **FED-01: Unbounded Subgraph Query Depth in Federated Gateway** in `components/saas/FaqSection.tsx` (Lines L1)
  - Fix: Enforce maximum query depth limits at the federated router to prevent deeply nested entity resolution loops.
- **FED-01: Unbounded Subgraph Query Depth in Federated Gateway** in `components/saas/FinalCta.tsx` (Lines L1)
  - Fix: Enforce maximum query depth limits at the federated router to prevent deeply nested entity resolution loops.
- **OPA-01: Rego Policy Infinite Recursion and Execution Timeout** in `components/saas/ProductCapabilities.tsx` (Lines L1)
  - Fix: Enforce strict evaluation timeouts (e.g. 100ms) on OPA admission webhook decisions.
- **OPA-04: Unrestricted Container Linux Capabilities (SYS_ADMIN) Admission** in `components/saas/ProductCapabilities.tsx` (Lines L1)
  - Fix: Reject pod specs requesting dangerous capabilities such as CAP_SYS_ADMIN or CAP_NET_ADMIN.
- **KERN-SEC-01: Unrestricted Linux Root Capabilities (CAP_SYS_ADMIN) Retained in Container Workloads** in `components/saas/ProductCapabilities.tsx` (Lines L1)
  - Fix: Drop all default Linux capabilities and retain strictly the minimal required set (e.g. drop CAP_SYS_ADMIN, CAP_NET_ADMIN).
- **GW-02: Missing Token Bucket Rate Limiting on Credential Authentication Routes** in `components/saas/SaasCheckout.tsx` (Lines L1)
  - Fix: Add rate limiting middleware restricting POST /api/auth/login to 5 requests per minute per IP.
- **PCI4-02: PCI-DSS Req 6.4.3 Insecure Third-Party Scripts on Payment Pages** in `components/saas/SaasCheckout.tsx` (Lines L1)
  - Fix: Authorize and inventory all scripts on payment pages with Subresource Integrity (SRI) and CSP (Req 6.4.3).
- **FED-01: Unbounded Subgraph Query Depth in Federated Gateway** in `components/saas/SaasHero.tsx` (Lines L1)
  - Fix: Enforce maximum query depth limits at the federated router to prevent deeply nested entity resolution loops.
- **GW-02: Missing Token Bucket Rate Limiting on Credential Authentication Routes** in `components/ScanRunnerView.tsx` (Lines L1)
  - Fix: Add rate limiting middleware restricting POST /api/auth/login to 5 requests per minute per IP.
- **APIDEF-01: API1:2023 Broken Object Level Authorization (BOLA): Insecure Record Lookup** in `components/ScanRunnerView.tsx` (Lines L1)
  - Fix: Validate user authorization and tenant ownership for every resource identifier supplied in API paths.
- **GW-02: Missing Token Bucket Rate Limiting on Credential Authentication Routes** in `components/settings/DangerZoneCard.tsx` (Lines L1)
  - Fix: Add rate limiting middleware restricting POST /api/auth/login to 5 requests per minute per IP.
- **FED-01: Unbounded Subgraph Query Depth in Federated Gateway** in `components/settings/DangerZoneCard.tsx` (Lines L1)
  - Fix: Enforce maximum query depth limits at the federated router to prevent deeply nested entity resolution loops.
- **GW-02: Missing Token Bucket Rate Limiting on Credential Authentication Routes** in `components/settings/EnterpriseOrgCard.tsx` (Lines L1)
  - Fix: Add rate limiting middleware restricting POST /api/auth/login to 5 requests per minute per IP.
- **OPA-01: Rego Policy Infinite Recursion and Execution Timeout** in `components/settings/EnterpriseOrgCard.tsx` (Lines L1)
  - Fix: Enforce strict evaluation timeouts (e.g. 100ms) on OPA admission webhook decisions.
- **APIDEF-01: API1:2023 Broken Object Level Authorization (BOLA): Insecure Record Lookup** in `components/settings/EnterpriseOrgCard.tsx` (Lines L1)
  - Fix: Validate user authorization and tenant ownership for every resource identifier supplied in API paths.
- **GW-02: Missing Token Bucket Rate Limiting on Credential Authentication Routes** in `components/settings/SubscriptionCard.tsx` (Lines L1)
  - Fix: Add rate limiting middleware restricting POST /api/auth/login to 5 requests per minute per IP.
- **PCI4-01: PCI-DSS Req 3.4 Unencrypted Primary Account Numbers (PAN) at Rest** in `components/settings/SubscriptionCard.tsx` (Lines L1)
  - Fix: Never store unencrypted primary account numbers (PAN). Use strong cryptographic encryption (AES-256-GCM).
- **FED-01: Unbounded Subgraph Query Depth in Federated Gateway** in `components/settings/SubscriptionCard.tsx` (Lines L1)
  - Fix: Enforce maximum query depth limits at the federated router to prevent deeply nested entity resolution loops.
- **APIDEF-01: API1:2023 Broken Object Level Authorization (BOLA): Insecure Record Lookup** in `components/settings/SubscriptionCard.tsx` (Lines L1)
  - Fix: Validate user authorization and tenant ownership for every resource identifier supplied in API paths.
- **FED-01: Unbounded Subgraph Query Depth in Federated Gateway** in `components/ui/UpgradePaywallModal.tsx` (Lines L1)
  - Fix: Enforce maximum query depth limits at the federated router to prevent deeply nested entity resolution loops.
- **APIDEF-01: API1:2023 Broken Object Level Authorization (BOLA): Insecure Record Lookup** in `components/ui/UpgradePaywallModal.tsx` (Lines L1)
  - Fix: Validate user authorization and tenant ownership for every resource identifier supplied in API paths.
- **GW-02: Missing Token Bucket Rate Limiting on Credential Authentication Routes** in `components/VibeCareView.tsx` (Lines L1)
  - Fix: Add rate limiting middleware restricting POST /api/auth/login to 5 requests per minute per IP.
- **OPA-01: Rego Policy Infinite Recursion and Execution Timeout** in `data/supabase-migration.sql` (Lines L3)
  - Fix: Enforce strict evaluation timeouts (e.g. 100ms) on OPA admission webhook decisions.
- **GEODIST-01: Unpartitioned Multi-Region Tables Triggering Cross-WAN Latency Spikes** in `data/supabase-migration.sql` (Lines L3)
  - Fix: Apply regional table locality (e.g. REGIONAL BY ROW) to anchor data partitions close to user geographies.
- **GW-02: Missing Token Bucket Rate Limiting on Credential Authentication Routes** in `hooks/useDashboardState.ts` (Lines L1)
  - Fix: Add rate limiting middleware restricting POST /api/auth/login to 5 requests per minute per IP.
- **APIDEF-01: API1:2023 Broken Object Level Authorization (BOLA): Insecure Record Lookup** in `hooks/useDashboardState.ts` (Lines L1)
  - Fix: Validate user authorization and tenant ownership for every resource identifier supplied in API paths.
- **APIDEF-03: API3:2023 Broken Object Property Level Authorization: Mass Assignment** in `hooks/useDashboardState.ts` (Lines L1)
  - Fix: Disallow bulk assignment on sensitive object properties (isAdmin, role, verified, balance) in API handlers.
- **APIDEF-01: API1:2023 Broken Object Level Authorization (BOLA): Insecure Record Lookup** in `lib/attribution.ts` (Lines L1)
  - Fix: Validate user authorization and tenant ownership for every resource identifier supplied in API paths.
- **APIDEF-01: API1:2023 Broken Object Level Authorization (BOLA): Insecure Record Lookup** in `lib/chunk-reload.ts` (Lines L1)
  - Fix: Validate user authorization and tenant ownership for every resource identifier supplied in API paths.
- **OPA-01: Rego Policy Infinite Recursion and Execution Timeout** in `lib/db-schema.sql` (Lines L7)
  - Fix: Enforce strict evaluation timeouts (e.g. 100ms) on OPA admission webhook decisions.
- **GEODIST-01: Unpartitioned Multi-Region Tables Triggering Cross-WAN Latency Spikes** in `lib/db-schema.sql` (Lines L7)
  - Fix: Apply regional table locality (e.g. REGIONAL BY ROW) to anchor data partitions close to user geographies.
- **ISO-04: Missing Segregation in Production and Development Environments (A.8.31)** in `lib/env-config.ts` (Lines L1)
  - Fix: Ensure staging and development environments use dedicated isolated VPCs and mock synthetic seed data.
- **APIDEF-01: API1:2023 Broken Object Level Authorization (BOLA): Insecure Record Lookup** in `lib/github-api.ts` (Lines L1)
  - Fix: Validate user authorization and tenant ownership for every resource identifier supplied in API paths.
- **ASVS-02: ASVS V3.2 Session Management: Permitting Session Fixation or Insecure Cookie Flags** in `lib/logger.ts` (Lines L1)
  - Fix: Enforce HttpOnly, Secure, SameSite=Strict cookies with session regeneration upon login.
- **OPA-01: Rego Policy Infinite Recursion and Execution Timeout** in `lib/quota-manager.ts` (Lines L1)
  - Fix: Enforce strict evaluation timeouts (e.g. 100ms) on OPA admission webhook decisions.
- **APIDEF-01: API1:2023 Broken Object Level Authorization (BOLA): Insecure Record Lookup** in `lib/quota-manager.ts` (Lines L1)
  - Fix: Validate user authorization and tenant ownership for every resource identifier supplied in API paths.
- **APIDEF-03: API3:2023 Broken Object Property Level Authorization: Mass Assignment** in `lib/quota-manager.ts` (Lines L1)
  - Fix: Disallow bulk assignment on sensitive object properties (isAdmin, role, verified, balance) in API handlers.
- **AUDIT-01: Plaintext Credentials or PII Leaked in Application Logs** in `lib/rate-limiter.ts` (Lines L1)
  - Fix: Scrub authorization headers, API keys, and sensitive PII from log payloads prior to dispatching.
- **APIDEF-01: API1:2023 Broken Object Level Authorization (BOLA): Insecure Record Lookup** in `lib/storage.ts` (Lines L1)
  - Fix: Validate user authorization and tenant ownership for every resource identifier supplied in API paths.
- **PCI4-02: PCI-DSS Req 6.4.3 Insecure Third-Party Scripts on Payment Pages** in `lib/stripe-checkout.ts` (Lines L1)
  - Fix: Authorize and inventory all scripts on payment pages with Subresource Integrity (SRI) and CSP (Req 6.4.3).
- **APIDEF-01: API1:2023 Broken Object Level Authorization (BOLA): Insecure Record Lookup** in `lib/stripe-checkout.ts` (Lines L1)
  - Fix: Validate user authorization and tenant ownership for every resource identifier supplied in API paths.
- **GW-02: Missing Token Bucket Rate Limiting on Credential Authentication Routes** in `lib/subscription-utils.ts` (Lines L1)
  - Fix: Add rate limiting middleware restricting POST /api/auth/login to 5 requests per minute per IP.
- **GW-02: Missing Token Bucket Rate Limiting on Credential Authentication Routes** in `lib/supabase.ts` (Lines L1)
  - Fix: Add rate limiting middleware restricting POST /api/auth/login to 5 requests per minute per IP.
- **OPA-01: Rego Policy Infinite Recursion and Execution Timeout** in `lib/website-scanner.ts` (Lines L1)
  - Fix: Enforce strict evaluation timeouts (e.g. 100ms) on OPA admission webhook decisions.
- **OPA-01: Rego Policy Infinite Recursion and Execution Timeout** in `next.config.mjs` (Lines L1)
  - Fix: Enforce strict evaluation timeouts (e.g. 100ms) on OPA admission webhook decisions.
- **GW-02: Missing Token Bucket Rate Limiting on Credential Authentication Routes** in `package-lock.json` (Lines L1)
  - Fix: Add rate limiting middleware restricting POST /api/auth/login to 5 requests per minute per IP.
- **SOX-02: SOX ITGC Segregation of Duties (SoD): Developers Possessing Production DB Write Access** in `package-lock.json` (Lines L1)
  - Fix: Revoke direct production write and DDL permissions from development and engineering staff.
- **WASM-EDGE-01: Unbounded WebAssembly Linear Memory Allocation Permitting Edge Worker OOM** in `package-lock.json` (Lines L1)
  - Fix: Define strict memory limits in Wasm runtime flags (e.g. maximum linear memory pages 128MB) to prevent edge node exhaustion.
- **Permissive Row Level Security (RLS) Policy (USING true)** in `scripts/clean_v05_ast.ts` (Lines L17)
  - Fix: Replace permissive RLS policy in scripts/clean_v05_ast.ts. Write strict auth.uid() = user_id checks.
- **Exposed Hardcoded OpenAI/Stripe Secret API Key** in `scripts/clean_v05_ast.ts` (Lines L17)
  - Fix: Extract secret API key in scripts/clean_v05_ast.ts to process.env.OPENAI_API_KEY. Never commit secret tokens to version control.
- **Dynamic Code Execution (eval / Function Remote Code Execution)** in `scripts/clean_v05_ast.ts` (Lines L1)
  - Fix: Eliminate eval() and dynamic Function invocation in scripts/clean_v05_ast.ts:1. Use structured JSON parsing or safe domain-specific interpreters.
- **UI-75: Unfiltered Multi-Tenant Vector Query** in `scripts/clean_v05_ast.ts` (Lines L23)
  - Fix: Enforce mandatory tenant_id and user_id metadata filtering in scripts/clean_v05_ast.ts for vector database queries: vectorStore.similaritySearch(query, 5, { tenant_id: user.tenantId }).
- **GQL-01: Unrestricted GraphQL Query Depth (DoS Vulnerability)** in `scripts/clean_v05_ast.ts` (Lines L1)
  - Fix: Configure query depth limiter (e.g. depthLimit(6)) to prevent recursive DoS queries.
- **WEB3-01: Reentrancy Vulnerability (Checks-Effects-Interactions Violation)** in `scripts/clean_v05_ast.ts` (Lines L1)
  - Fix: Apply OpenZeppelin ReentrancyGuard nonReentrant modifier and strictly follow Checks-Effects-Interactions.
- **OPA-01: Rego Policy Infinite Recursion and Execution Timeout** in `scripts/clean_v05_ast.ts` (Lines L1)
  - Fix: Enforce strict evaluation timeouts (e.g. 100ms) on OPA admission webhook decisions.
- **THREAT-02: MITRE T1059 Command Execution: Unmonitored Interactive Shell Spawning in Web Pods** in `scripts/clean_v05_ast.ts` (Lines L1)
  - Fix: Monitor and immediately terminate unauthorized shell processes (/bin/sh, /bin/bash) spawned by web services.
- **WASM-EDGE-01: Unbounded WebAssembly Linear Memory Allocation Permitting Edge Worker OOM** in `scripts/clean_v05_ast.ts` (Lines L1)
  - Fix: Define strict memory limits in Wasm runtime flags (e.g. maximum linear memory pages 128MB) to prevent edge node exhaustion.
- **GEODIST-01: Unpartitioned Multi-Region Tables Triggering Cross-WAN Latency Spikes** in `sql/02_tables_and_constraints.sql` (Lines L5)
  - Fix: Apply regional table locality (e.g. REGIONAL BY ROW) to anchor data partitions close to user geographies.
- **OPA-01: Rego Policy Infinite Recursion and Execution Timeout** in `sql/04_rls_security_policies.sql` (Lines L5)
  - Fix: Enforce strict evaluation timeouts (e.g. 100ms) on OPA admission webhook decisions.
- **OPA-01: Rego Policy Infinite Recursion and Execution Timeout** in `sql/07_async_scan_jobs.sql` (Lines L6)
  - Fix: Enforce strict evaluation timeouts (e.g. 100ms) on OPA admission webhook decisions.
- **GEODIST-01: Unpartitioned Multi-Region Tables Triggering Cross-WAN Latency Spikes** in `sql/07_async_scan_jobs.sql` (Lines L6)
  - Fix: Apply regional table locality (e.g. REGIONAL BY ROW) to anchor data partitions close to user geographies.
- **OPA-01: Rego Policy Infinite Recursion and Execution Timeout** in `supabase/migrations/20260828000000_init_auth_saas_schema.sql` (Lines L7)
  - Fix: Enforce strict evaluation timeouts (e.g. 100ms) on OPA admission webhook decisions.
- **GEODIST-01: Unpartitioned Multi-Region Tables Triggering Cross-WAN Latency Spikes** in `supabase/migrations/20260828000000_init_auth_saas_schema.sql` (Lines L7)
  - Fix: Apply regional table locality (e.g. REGIONAL BY ROW) to anchor data partitions close to user geographies.
- **OPA-01: Rego Policy Infinite Recursion and Execution Timeout** in `supabase/migrations/20260923000000_security_and_rls_hardening.sql` (Lines L7)
  - Fix: Enforce strict evaluation timeouts (e.g. 100ms) on OPA admission webhook decisions.
- **GEODIST-01: Unpartitioned Multi-Region Tables Triggering Cross-WAN Latency Spikes** in `supabase/migrations/20260923000000_security_and_rls_hardening.sql` (Lines L7)
  - Fix: Apply regional table locality (e.g. REGIONAL BY ROW) to anchor data partitions close to user geographies.
- **OPA-01: Rego Policy Infinite Recursion and Execution Timeout** in `supabase/migrations/20260925000000_scan_jobs_async_queue.sql` (Lines L6)
  - Fix: Enforce strict evaluation timeouts (e.g. 100ms) on OPA admission webhook decisions.
- **GEODIST-01: Unpartitioned Multi-Region Tables Triggering Cross-WAN Latency Spikes** in `supabase/migrations/20260925000000_scan_jobs_async_queue.sql` (Lines L6)
  - Fix: Apply regional table locality (e.g. REGIONAL BY ROW) to anchor data partitions close to user geographies.
