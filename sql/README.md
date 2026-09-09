# Zelsis SQL Database Schema & Migration Suite

This directory contains the production-grade PostgreSQL / Supabase SQL schema definitions for the **Zelsis AI Release Gate SaaS** platform.

## 📁 File Directory Structure

| File Name | Purpose & Contents |
| :--- | :--- |
| `01_extensions_and_enums.sql` | Postgres Extensions (`uuid-ossp`, `pgcrypto`) & Enum Types (`user_role`, `plan_tier`, `gate_status`, `finding_severity`, `finding_status`, `pillar_type`) |
| `02_tables_and_constraints.sql` | Core DDL tables (`profiles`, `subscriptions`, `projects`, `scans`, `findings`, `api_keys`, `audit_logs`) and foreign keys |
| `03_indexes_and_triggers.sql` | Query performance indexes & automatic triggers (`handle_new_user_signup`, `update_timestamp_column`) |
| `04_rls_security_policies.sql` | Multi-Tenant Row Level Security (RLS) policies for user data isolation |
| `05_seed_data.sql` | System default catalog reference entries & OWASP rule seeds |

---

## 🚀 Execution Guide (Supabase CLI or Dashboard)

### Option A: Supabase Dashboard SQL Editor
Copy and execute files `01` through `05` sequentially in the **Supabase SQL Editor**.

### Option B: Supabase Local Migration
Run using Supabase CLI:
```bash
supabase db push
```
