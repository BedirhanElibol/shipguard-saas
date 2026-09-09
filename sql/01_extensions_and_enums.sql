-- ==============================================================================
-- ZELSIS B2B SAAS - POSTGRESQL EXTENSIONS & CUSTOM ENUM TYPES
-- File: sql/01_extensions_and_enums.sql
-- ==============================================================================

-- 1. EXTENSIONS
CREATE EXTENSION IF NOT EXISTS "uuid-ossp";
CREATE EXTENSION IF NOT EXISTS "pgcrypto";

-- 2. ENUM TYPES
DO $$ BEGIN
    CREATE TYPE user_role AS ENUM ('user', 'admin', 'auditor');
EXCEPTION
    WHEN duplicate_object THEN null;
END $$;

DO $$ BEGIN
    CREATE TYPE plan_tier AS ENUM ('Free', 'Pro', 'Enterprise');
EXCEPTION
    WHEN duplicate_object THEN null;
END $$;

DO $$ BEGIN
    CREATE TYPE gate_status AS ENUM ('PASSED', 'WARNING', 'FAILED');
EXCEPTION
    WHEN duplicate_object THEN null;
END $$;

DO $$ BEGIN
    CREATE TYPE finding_severity AS ENUM ('CRITICAL', 'HIGH', 'MEDIUM', 'LOW', 'PASSED');
EXCEPTION
    WHEN duplicate_object THEN null;
END $$;

DO $$ BEGIN
    CREATE TYPE finding_status AS ENUM ('OPEN', 'ACCEPTED_RISK', 'RESOLVED');
EXCEPTION
    WHEN duplicate_object THEN null;
END $$;

DO $$ BEGIN
    CREATE TYPE pillar_type AS ENUM ('SECURITY', 'VIBEPOLISH', 'AICLICHE', 'AIMASTER', 'VIBECARE', 'LEGAL_COMPLIANCE', 'INFRA_DATABASE');
EXCEPTION
    WHEN duplicate_object THEN null;
END $$;
