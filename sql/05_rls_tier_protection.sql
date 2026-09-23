-- ============================================================================
-- ZELSIS / SHIPGUARD SAAS - PRODUCTION RLS TIER PROTECTION
-- Migration: 05_rls_tier_protection.sql
-- Description: Restricts UPDATE on profiles.tier and profiles.role
--              Prevents client-side privilege escalation attacks (CWE-285).
-- ============================================================================

-- 1. Prevent standard authenticated users from changing their own tier or role
CREATE OR REPLACE FUNCTION public.check_profile_tier_modification()
RETURNS TRIGGER
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = ''
AS $$
BEGIN
  -- If tier or role is being changed
  IF (NEW.tier IS DISTINCT FROM OLD.tier) OR (NEW.role IS DISTINCT FROM OLD.role) THEN
    -- Only allow service_role (backend webhooks / admin API) to modify tier or role
    IF (auth.jwt() ->> 'role') IS DISTINCT FROM 'service_role' THEN
      -- Revert tier and role to old values silently or raise exception
      NEW.tier := OLD.tier;
      NEW.role := OLD.role;
    END IF;
  END IF;
  RETURN NEW;
END;
$$;

-- 2. Attach trigger to profiles table
DROP TRIGGER IF EXISTS tr_protect_profile_tier ON public.profiles;
CREATE TRIGGER tr_protect_profile_tier
BEFORE UPDATE ON public.profiles
FOR EACH ROW
EXECUTE FUNCTION public.check_profile_tier_modification();

-- 3. Ensure RLS is active on profiles
ALTER TABLE public.profiles ENABLE ROW LEVEL SECURITY;
