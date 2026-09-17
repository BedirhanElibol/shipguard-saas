-- ==============================================================================
-- ZELSIS B2B SAAS - PRODUCTION LIVE SCHEMA PATCH
-- File: sql/06_production_patch.sql
-- Run this script once in Supabase SQL Editor:
-- https://supabase.com/dashboard/project/afzpaydfkmycrwuxmzkk/sql/new
-- ==============================================================================

-- 1. Safely add tier and status columns to profiles table for fast denormalized lookups
ALTER TABLE public.profiles ADD COLUMN IF NOT EXISTS tier TEXT DEFAULT 'Free';
ALTER TABLE public.profiles ADD COLUMN IF NOT EXISTS status TEXT DEFAULT 'active';
ALTER TABLE public.profiles ADD COLUMN IF NOT EXISTS grace_period_until TIMESTAMPTZ;

-- 2. Safely add grace_period_until and polar_subscription_id to subscriptions table
ALTER TABLE public.subscriptions ADD COLUMN IF NOT EXISTS grace_period_until TIMESTAMPTZ;
ALTER TABLE public.subscriptions ADD COLUMN IF NOT EXISTS polar_subscription_id TEXT;

-- 3. Extend category enum for Legal Compliance and Database Infrastructure
ALTER TYPE pillar_type ADD VALUE IF NOT EXISTS 'LEGAL_COMPLIANCE';
ALTER TYPE pillar_type ADD VALUE IF NOT EXISTS 'INFRA_DATABASE';

-- 4. Create index for fast subscriber lookups
CREATE INDEX IF NOT EXISTS idx_subscriptions_user_id ON public.subscriptions(user_id);
CREATE INDEX IF NOT EXISTS idx_subscriptions_status ON public.subscriptions(status);
CREATE INDEX IF NOT EXISTS idx_profiles_email ON public.profiles(email);

-- 5. Confirmation output
SELECT 'Production schema patch applied successfully.' AS result;
