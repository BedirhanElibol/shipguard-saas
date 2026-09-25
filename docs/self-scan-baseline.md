# Zelsis Self-Scan Dogfooding Baseline Report

**Generated At:** 2026-09-25T19:10:51.655Z  
**Target:** Zelsis Codebase (Internal Self-Scan)  
**Analyzed Files:** 376 source files  
**Duration:** 13373ms  
**Readiness Score:** 83/100  
**Gate Clearance:** FAILED  

## Executive Summary

| Metric | Count |
|---|---|
| **Critical Blockers** | 0 |
| **High Severity Issues** | 1 |
| **Medium Warnings** | 8 |
| **Low / Informational** | 1 |
| **Total Findings** | 10 |

## Detected Stacks & Architecture

- **Databases:** PostgreSQL, MongoDB, Redis
- **ORMs:** Supabase Client

## Detailed Findings Catalog

| ID | Severity | Pillar | Rule Code | File | Description |
|---|---|---|---|---|---|
| 1 | **HIGH** | INFRA_DATABASE | `7001` | `app/api/v1/scans/process-job/route.ts:L1` | CLOUD-01: Synchronous Serverless Function Timeout Exceeding 30s |
| 2 | **MEDIUM** | SECURITY | `7208` | `app/api/v1/scans/process-job/route.ts:L1` | API-08: Missing 'Retry-After' Header on Rate Limit Throttling (429) |
| 3 | **MEDIUM** | VIBEPOLISH | `111` | `app/dashboard/page.tsx:L110` | UI-111: TypeScript "any" Type Escape |
| 4 | **MEDIUM** | VIBEPOLISH | `1004` | `components/saas/BenchmarkSection.tsx:L1-L50` | UI-04: Absence of Empty State Component Fallback |
| 5 | **LOW** | VIBEPOLISH | `221` | `components/saas/FinalCta.tsx:L1` | CLICHE-21: Forced Fixed-Height Card Containers |
| 6 | **MEDIUM** | VIBEPOLISH | `111` | `components/ScanRunnerView.tsx:L69` | UI-111: TypeScript "any" Type Escape |
| 7 | **MEDIUM** | VIBEPOLISH | `115` | `components/ScanRunnerView.tsx:L1-L1206` | UI-115: Monolithic Overly Long Source File (>500 Lines) |
| 8 | **MEDIUM** | VIBEPOLISH | `115` | `components/settings/SubscriptionCard.tsx:L1-L604` | UI-115: Monolithic Overly Long Source File (>500 Lines) |
| 9 | **MEDIUM** | LEGAL_COMPLIANCE | `2004` | `components/settings/SubscriptionCard.tsx:L413` | User Data Collection Form Missing Mandatory Privacy Consent Disclosure |
| 10 | **MEDIUM** | VIBEPOLISH | `111` | `hooks/useDashboardState.ts:L322` | UI-111: TypeScript "any" Type Escape |

## Remediation & Hardening Plan

✅ Zero critical deployment blockers exist in the Zelsis core architecture.
