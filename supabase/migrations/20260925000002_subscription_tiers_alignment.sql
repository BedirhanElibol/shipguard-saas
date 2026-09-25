-- ==============================================================================
-- ZELSIS B2B SAAS - PRODUCTION SUBSCRIPTION TIERS & QUOTA ALIGNMENT
-- Migration: 20260925000002_subscription_tiers_alignment.sql
-- ==============================================================================

-- 1. Ensure plan_tier ENUM includes all 3 canonical tiers
DO $$ BEGIN
    IF NOT EXISTS (SELECT 1 FROM pg_type WHERE typname = 'plan_tier') THEN
        CREATE TYPE plan_tier AS ENUM ('Free', 'Pro', 'Enterprise');
    END IF;
END $$;

-- 2. Align subscriptions table defaults and column constraints
DO $$ BEGIN
    IF NOT EXISTS (
        SELECT 1 FROM information_schema.columns 
        WHERE table_schema = 'public' AND table_name = 'subscriptions' AND column_name = 'monthly_scan_quota'
    ) THEN
        ALTER TABLE public.subscriptions ADD COLUMN monthly_scan_quota INTEGER DEFAULT 3 NOT NULL;
    END IF;

    IF NOT EXISTS (
        SELECT 1 FROM information_schema.columns 
        WHERE table_schema = 'public' AND table_name = 'subscriptions' AND column_name = 'scans_used_this_month'
    ) THEN
        ALTER TABLE public.subscriptions ADD COLUMN scans_used_this_month INTEGER DEFAULT 0 NOT NULL;
    END IF;
END $$;

-- 3. Trigger: Automatically synchronizes monthly_scan_quota with plan_tier
--    Free = 3, Pro = -1 (Unlimited), Enterprise = -1 (Unlimited)
CREATE OR REPLACE FUNCTION public.sync_subscription_quota_on_tier_change()
RETURNS TRIGGER
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = ''
AS $$
BEGIN
    IF NEW.plan_tier = 'Free' THEN
        NEW.monthly_scan_quota := 3;
    ELSIF NEW.plan_tier IN ('Pro', 'Enterprise') THEN
        NEW.monthly_scan_quota := -1; -- -1 represents Unlimited
        NEW.scans_used_this_month := 0;
    END IF;

    -- Check if billing cycle rolled over
    IF NEW.current_period_end < NOW() THEN
        NEW.current_period_start := NOW();
        NEW.current_period_end := NOW() + INTERVAL '30 days';
        NEW.scans_used_this_month := 0;
    END IF;

    RETURN NEW;
END;
$$;

DROP TRIGGER IF EXISTS tr_sync_subscription_quota ON public.subscriptions;
CREATE TRIGGER tr_sync_subscription_quota
BEFORE INSERT OR UPDATE ON public.subscriptions
FOR EACH ROW
EXECUTE FUNCTION public.sync_subscription_quota_on_tier_change();

-- 4. Trigger: Automatically mirror profile tier when subscription changes
CREATE OR REPLACE FUNCTION public.sync_profile_tier_from_subscription()
RETURNS TRIGGER
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = ''
AS $$
BEGIN
    UPDATE public.profiles
    SET 
        tier = NEW.plan_tier::text,
        status = NEW.status,
        updated_at = NOW()
    WHERE id = NEW.user_id;

    RETURN NEW;
END;
$$;

DROP TRIGGER IF EXISTS tr_sync_profile_tier ON public.subscriptions;
CREATE TRIGGER tr_sync_profile_tier
AFTER INSERT OR UPDATE OF plan_tier, status ON public.subscriptions
FOR EACH ROW
EXECUTE FUNCTION public.sync_profile_tier_from_subscription();

-- 5. Strict RLS on Subscriptions table
ALTER TABLE public.subscriptions ENABLE ROW LEVEL SECURITY;

DROP POLICY IF EXISTS "Users can view own subscription" ON public.subscriptions;
CREATE POLICY "Users can view own subscription"
    ON public.subscriptions
    FOR SELECT
    USING (auth.uid() = user_id);

DROP POLICY IF EXISTS "Service role has full access to subscriptions" ON public.subscriptions;
CREATE POLICY "Service role has full access to subscriptions"
    ON public.subscriptions
    FOR ALL
    USING ((auth.jwt() ->> 'role') = 'service_role');
