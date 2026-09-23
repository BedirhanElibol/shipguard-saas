# Zelsis SQL Database Schema & Migration Suite

This directory contains the production-grade PostgreSQL / Supabase SQL schema definitions for the **Zelsis AI Release Gate SaaS** platform.

> **Single Source of Truth:** The authoritative schema migrations are maintained under `supabase/migrations/` (`20260828000000_init_auth_saas_schema.sql` and `20260923000000_security_and_rls_hardening.sql`). The scripts in this directory (`sql/`) are modular standalone mirrors kept in strict synchronization.

## 📁 File Directory Structure

| File Name | Purpose & Contents |
| :--- | :--- |
| `01_extensions_and_enums.sql` | Postgres Extensions (`uuid-ossp`, `pgcrypto`) & Enum Types (`user_role`, `plan_tier`, `gate_status`, `finding_severity`, `finding_status`, `pillar_type`) |
| `02_tables_and_constraints.sql` | Core DDL tables (`profiles`, `subscriptions`, `projects`, `scans`, `findings`, `api_keys`, `audit_logs`) and foreign keys |
| `03_indexes_and_triggers.sql` | Query performance indexes & hardened triggers with `SET search_path = ''` |
| `04_rls_security_policies.sql` | Multi-Tenant Row Level Security (RLS) policies with strict `WITH CHECK` controls |
| `05_rls_tier_protection.sql` | CWE-285 defense-in-depth trigger preventing client-side `profiles.tier` escalation |
| `05_seed_data.sql` | OWASP rule catalog table with enforced RLS and seed entries |
| `06_production_patch.sql` | Production live patch for adding denormalized columns idempotently |

---

## 🚀 Execution Guide (Supabase CLI or Dashboard)

### Option A: Supabase CLI (Recommended)
Run using Supabase CLI with automated migration tracking:
```bash
supabase db push
```

### Option B: Supabase Dashboard SQL Editor
Execute the unified migration:
`supabase/migrations/20260923000000_security_and_rls_hardening.sql`
