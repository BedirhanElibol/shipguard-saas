-- ==============================================================================
-- SHIPGUARD B2B SAAS - CORE TABLES & CONSTRAINTS
-- File: sql/02_tables_and_constraints.sql
-- ==============================================================================

-- 1. PROFILES / USERS TABLE
CREATE TABLE IF NOT EXISTS public.profiles (
    id UUID PRIMARY KEY REFERENCES auth.users(id) ON DELETE CASCADE,
    email TEXT UNIQUE NOT NULL,
    full_name TEXT,
    avatar_url TEXT,
    role user_role DEFAULT 'user'::user_role NOT NULL,
    github_username TEXT,
    company_name TEXT,
    created_at TIMESTAMPTZ DEFAULT NOW() NOT NULL,
    updated_at TIMESTAMPTZ DEFAULT NOW() NOT NULL
);

-- 2. SUBSCRIPTIONS TABLE
CREATE TABLE IF NOT EXISTS public.subscriptions (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    user_id UUID REFERENCES public.profiles(id) ON DELETE CASCADE NOT NULL UNIQUE,
    plan_tier plan_tier DEFAULT 'Free'::plan_tier NOT NULL,
    status TEXT DEFAULT 'active' NOT NULL,
    monthly_scan_quota INTEGER DEFAULT 3 NOT NULL,
    scans_used_this_month INTEGER DEFAULT 0 NOT NULL,
    stripe_customer_id TEXT,
    stripe_subscription_id TEXT,
    current_period_start TIMESTAMPTZ DEFAULT NOW() NOT NULL,
    current_period_end TIMESTAMPTZ DEFAULT (NOW() + INTERVAL '30 days') NOT NULL,
    cancel_at_period_end BOOLEAN DEFAULT FALSE NOT NULL,
    created_at TIMESTAMPTZ DEFAULT NOW() NOT NULL,
    updated_at TIMESTAMPTZ DEFAULT NOW() NOT NULL
);

-- 3. PROJECTS TABLE
CREATE TABLE IF NOT EXISTS public.projects (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    user_id UUID REFERENCES public.profiles(id) ON DELETE CASCADE NOT NULL,
    name TEXT NOT NULL,
    repo_url TEXT NOT NULL,
    preview_url TEXT,
    github_token TEXT,
    framework TEXT DEFAULT 'Auto-Detect' NOT NULL,
    providers TEXT[] DEFAULT ARRAY['GitHub Action', 'Vercel']::TEXT[] NOT NULL,
    last_scan_at TIMESTAMPTZ,
    readiness_score INTEGER DEFAULT 100 NOT NULL CHECK (readiness_score >= 0 AND readiness_score <= 100),
    gate_status gate_status DEFAULT 'PASSED'::gate_status NOT NULL,
    critical_count INTEGER DEFAULT 0 NOT NULL,
    high_count INTEGER DEFAULT 0 NOT NULL,
    medium_count INTEGER DEFAULT 0 NOT NULL,
    low_count INTEGER DEFAULT 0 NOT NULL,
    ui_cliche_count INTEGER DEFAULT 0 NOT NULL,
    created_at TIMESTAMPTZ DEFAULT NOW() NOT NULL,
    updated_at TIMESTAMPTZ DEFAULT NOW() NOT NULL
);

-- 4. SCANS HISTORY TABLE
CREATE TABLE IF NOT EXISTS public.scans (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    project_id UUID REFERENCES public.projects(id) ON DELETE CASCADE NOT NULL,
    user_id UUID REFERENCES public.profiles(id) ON DELETE CASCADE NOT NULL,
    trigger_type TEXT DEFAULT 'MANUAL' NOT NULL,
    readiness_score INTEGER NOT NULL CHECK (readiness_score >= 0 AND readiness_score <= 100),
    gate_status gate_status NOT NULL,
    critical_count INTEGER DEFAULT 0 NOT NULL,
    high_count INTEGER DEFAULT 0 NOT NULL,
    medium_count INTEGER DEFAULT 0 NOT NULL,
    low_count INTEGER DEFAULT 0 NOT NULL,
    ui_cliche_count INTEGER DEFAULT 0 NOT NULL,
    scan_duration_ms INTEGER DEFAULT 0 NOT NULL,
    scanned_at TIMESTAMPTZ DEFAULT NOW() NOT NULL
);

-- 5. AUDIT FINDINGS TABLE
CREATE TABLE IF NOT EXISTS public.findings (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    scan_id UUID REFERENCES public.scans(id) ON DELETE CASCADE NOT NULL,
    project_id UUID REFERENCES public.projects(id) ON DELETE CASCADE NOT NULL,
    rule_id INTEGER NOT NULL,
    type pillar_type NOT NULL,
    title TEXT NOT NULL,
    severity finding_severity NOT NULL,
    category TEXT NOT NULL,
    file_path TEXT NOT NULL,
    line_range TEXT NOT NULL,
    snippet TEXT NOT NULL,
    reproduction_steps TEXT[] DEFAULT ARRAY[]::TEXT[] NOT NULL,
    remediation_prompt TEXT NOT NULL,
    status finding_status DEFAULT 'OPEN'::finding_status NOT NULL,
    false_positive BOOLEAN DEFAULT FALSE NOT NULL,
    resolved_by UUID REFERENCES public.profiles(id) ON DELETE SET NULL,
    resolved_at TIMESTAMPTZ,
    created_at TIMESTAMPTZ DEFAULT NOW() NOT NULL,
    updated_at TIMESTAMPTZ DEFAULT NOW() NOT NULL
);

-- 6. API KEYS TABLE
CREATE TABLE IF NOT EXISTS public.api_keys (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    user_id UUID REFERENCES public.profiles(id) ON DELETE CASCADE NOT NULL,
    key_name TEXT NOT NULL,
    key_hash TEXT UNIQUE NOT NULL,
    prefix TEXT NOT NULL,
    last_used_at TIMESTAMPTZ,
    expires_at TIMESTAMPTZ,
    created_at TIMESTAMPTZ DEFAULT NOW() NOT NULL
);

-- 7. AUDIT LOGS TABLE
CREATE TABLE IF NOT EXISTS public.audit_logs (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    user_id UUID REFERENCES public.profiles(id) ON DELETE SET NULL,
    action TEXT NOT NULL,
    entity_type TEXT NOT NULL,
    entity_id TEXT NOT NULL,
    metadata JSONB DEFAULT '{}'::jsonb NOT NULL,
    ip_address TEXT,
    created_at TIMESTAMPTZ DEFAULT NOW() NOT NULL
);
