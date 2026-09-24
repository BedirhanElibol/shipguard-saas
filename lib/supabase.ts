import { createClient, SupabaseClient, Session } from '@supabase/supabase-js';
import { UserProfile } from '@/components/auth/AuthModal';
import { isPlatformAdminEmail } from '@/lib/subscription-utils';

export { isPlatformAdminEmail };

const DEFAULT_SUPABASE_URL = 'https://afzpaydfkmycrwuxmzkk.supabase.co';
const DEFAULT_SUPABASE_ANON_KEY = 'eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJpc3MiOiJzdXBhYmFzZSIsInJlZiI6ImFmenBheWRma215Y3J3dXhtemtrIiwicm9sZSI6ImFub24iLCJpYXQiOjE3ODc5MTc5NzEsImV4cCI6MjEwMzQ5Mzk3MX0.MNtKjLI3mNmGIRmcirzwnGknw0VJy58A2noAnEZZKZA';

const supabaseUrl = process.env.NEXT_PUBLIC_SUPABASE_URL || DEFAULT_SUPABASE_URL;
const supabaseAnonKey = process.env.NEXT_PUBLIC_SUPABASE_ANON_KEY || DEFAULT_SUPABASE_ANON_KEY;

let supabaseInstance: SupabaseClient | null = null;

export const isSupabaseConfigured = (): boolean => {
  return Boolean(
    supabaseUrl &&
    supabaseAnonKey &&
    !supabaseUrl.includes('sb-project.supabase.co') &&
    !supabaseUrl.includes('placeholder')
  );
};

export const getSupabase = (): SupabaseClient | null => {
  if (!isSupabaseConfigured()) return null;
  if (!supabaseInstance) {
    try {
      supabaseInstance = createClient(supabaseUrl, supabaseAnonKey);
    } catch (err) {
      console.warn('[Zelsis Supabase] Failed to initialize Supabase client:', err);
    }
  }
  return supabaseInstance;
};

// Authentication Helpers
export async function supabaseSignIn(email: string, password: string): Promise<{ user: UserProfile | null; error: string | null }> {
  const supabase = getSupabase();
  if (!supabase || !isSupabaseConfigured()) {
    return {
      user: null,
      error: 'Authentication service is unavailable. Please check Supabase configuration or network connection.'
    };
  }

  try {
    const { data, error } = await supabase.auth.signInWithPassword({ email, password });
    if (error) return { user: null, error: error.message };

    if (data.user) {
      const userProfile = mapSupabaseUserToProfile(data.user);
      return { user: userProfile, error: null };
    }
    return { user: null, error: 'User not found' };
  } catch (err: unknown) {
    return { user: null, error: err instanceof Error ? err.message : 'Authentication error occurred.' };
  }
}



export async function supabaseSignUp(email: string, password: string, name: string): Promise<{ user: UserProfile | null; error: string | null; requiresVerification?: boolean }> {
  const supabase = getSupabase();
  if (!supabase || !isSupabaseConfigured()) {
    return {
      user: null,
      error: 'Authentication service is unavailable. Please check Supabase configuration or network connection.',
      requiresVerification: false
    };
  }

  try {
    const { data, error } = await supabase.auth.signUp({
      email,
      password,
      options: {
        data: {
          full_name: name,
          tier: isPlatformAdminEmail(email) ? 'Enterprise' : 'Free'
        }
      }
    });

    if (error) return { user: null, error: error.message };

    if (data.user) {
      const userProfile = mapSupabaseUserToProfile(data.user);
      return { user: userProfile, error: null, requiresVerification: !data.user.email_confirmed_at };
    }
    return { user: null, error: 'Registration completed but user state could not be verified.' };
  } catch (err: unknown) {
    return { user: null, error: err instanceof Error ? err.message : 'Sign up error occurred.' };
  }
}

export async function supabaseResetPassword(email: string): Promise<{ success: boolean; message: string }> {
  const supabase = getSupabase();
  if (!supabase || !isSupabaseConfigured()) {
    return {
      success: false,
      message: 'Authentication service is unavailable. Please check Supabase configuration or network connection.'
    };
  }

  try {
    const { error } = await supabase.auth.resetPasswordForEmail(email, {
      redirectTo: `${window.location.origin}/dashboard`
    });
    if (error) return { success: false, message: error.message };
    return {
      success: true,
      message: `Password reset instruction email successfully sent to ${email}.`
    };
  } catch (err: unknown) {
    return { success: false, message: err instanceof Error ? err.message : 'Password reset request failed.' };
  }
}

export async function supabaseSignOut(): Promise<void> {
  const supabase = getSupabase();
  if (supabase && isSupabaseConfigured()) {
    try {
      await supabase.auth.signOut();
    } catch (err) {
      console.warn('[Zelsis Auth] Supabase sign out error:', err);
    }
  }
}

export function mapSupabaseUserToProfile(supabaseUser: {
  email?: string;
  user_metadata?: Record<string, unknown>;
  app_metadata?: Record<string, unknown>;
  email_confirmed_at?: string | null;
}): UserProfile {
  const metadata = supabaseUser?.user_metadata || {};
  const userEmailNorm = (supabaseUser?.email || '').toLowerCase().trim();
  const rawName = (metadata.full_name as string) || (metadata.name as string) || (metadata.user_name as string) || (userEmailNorm ? userEmailNorm.split('@')[0] : 'User');
  const avatar = (metadata.avatar_url as string) || (metadata.picture as string) || (metadata.user_name ? `https://github.com/${metadata.user_name}.png` : undefined);
  // Founder & Platform Administrator Detection (Configured via ADMIN_EMAILS / NEXT_PUBLIC_ADMIN_EMAILS)
  const isPlatformAdmin = isPlatformAdminEmail(userEmailNorm);

  let tier: 'Free' | 'Pro' | 'Enterprise' = 'Free';
  let expiresAt: string | undefined = undefined;
  let status: 'active' | 'past_due' | 'canceled' | 'trialing' = 'active';
  let billingCycle: 'monthly' | 'annual' | undefined = undefined;

  if (isPlatformAdmin) {
    tier = 'Enterprise';
    expiresAt = '2099-12-31T23:59:59.999Z';
    status = 'active';
    billingCycle = 'annual';
  } else {
    // Non-founder: strictly validate tier and reject tainted founder 2099 dates
    const rawTier = metadata.tier as 'Free' | 'Pro' | 'Enterprise' | undefined;
    const rawExpiresAt = metadata.expiresAt as string | undefined;

    const expiryYear = rawExpiresAt ? new Date(rawExpiresAt).getFullYear() : 0;
    const isTaintedDate = rawExpiresAt && (rawExpiresAt.includes('2099') || expiryYear > 2028);

    if (isTaintedDate || !rawTier || rawTier === 'Free') {
      tier = 'Free';
      expiresAt = undefined;
      status = 'canceled';
      billingCycle = undefined;
    } else {
      const expiryTime = rawExpiresAt ? new Date(rawExpiresAt).getTime() : 0;
      if (!isNaN(expiryTime) && expiryTime > Date.now()) {
        tier = rawTier;
        expiresAt = rawExpiresAt;
        status = (metadata.subscriptionStatus as any) || 'active';
        billingCycle = (metadata.billingCycle as any) || 'monthly';
      } else {
        tier = 'Free';
        expiresAt = undefined;
        status = 'canceled';
        billingCycle = undefined;
      }
    }
  }

  return {
    name: rawName || 'User',
    email: supabaseUser?.email || '',
    avatarUrl: avatar,
    tier,
    isLoggedIn: true,
    emailVerified: Boolean(
      supabaseUser?.email_confirmed_at != null ||
      supabaseUser?.app_metadata?.provider === 'github' ||
      supabaseUser?.app_metadata?.provider === 'google' ||
      metadata.email_verified === true
    ),
    expiresAt,
    status,
    gracePeriodUntil: undefined,
    billingCycle
  };
}

export async function syncUserProfileToSupabase(user: Partial<UserProfile>): Promise<boolean> {
  const supabase = getSupabase();
  if (!supabase || !isSupabaseConfigured()) return false;
  try {
    // F-02 Remediation: Strictly prevent client-side escalation of tier, expiresAt, or subscription status.
    // Client is only permitted to update profile display properties (full_name).
    // Paid tiers and subscriptions are managed exclusively by server webhooks and admin APIs.
    const { error } = await supabase.auth.updateUser({
      data: {
        ...(user.name ? { full_name: user.name } : {}),
      }
    });
    if (error) {
      console.warn('[Zelsis Auth] Failed to sync profile to Supabase metadata:', error.message);
      return false;
    }
    return true;
  } catch (err) {
    console.warn('[Zelsis Auth] syncUserProfileToSupabase error:', err);
    return false;
  }
}

export async function supabaseSignInWithOAuth(
  provider: 'github' | 'google',
  redirectTo?: string
): Promise<{ url?: string | null; error: string | null }> {
  const supabase = getSupabase();
  if (!supabase || !isSupabaseConfigured()) {
    return { error: 'Supabase is not configured' };
  }

  try {
    const defaultOrigin = typeof window !== 'undefined' ? window.location.origin : 'https://zelsis.com';
    const finalRedirect = redirectTo || `${defaultOrigin}/auth/callback`;

    const { data, error } = await supabase.auth.signInWithOAuth({
      provider,
      options: {
        redirectTo: finalRedirect,
        scopes: provider === 'github' ? 'read:user user:email' : undefined,
        queryParams: provider === 'google' ? {
          prompt: 'select_account',
          access_type: 'offline'
        } : undefined
      }
    });

    if (error) return { error: error.message };
    return { url: data?.url, error: null };
  } catch (err: unknown) {
    return { error: err instanceof Error ? err.message : 'OAuth initialization failed' };
  }
}

export async function supabaseGetSession(): Promise<{ user: UserProfile | null; session: Session | null; error: string | null }> {
  const supabase = getSupabase();
  if (!supabase || !isSupabaseConfigured()) {
    return { user: null, session: null, error: null };
  }

  try {
    // Use getUser() for server-side JWT verification instead of getSession()
    // getSession() reads from unverified local storage and can be forged
    const { data: { user: verifiedUser }, error: userError } = await supabase.auth.getUser();
    if (userError || !verifiedUser) {
      return { user: null, session: null, error: userError?.message || null };
    }

    const { data: { session } } = await supabase.auth.getSession();
    const profile = mapSupabaseUserToProfile(verifiedUser);
    return { user: profile, session, error: null };
  } catch (err: unknown) {
    return { user: null, session: null, error: err instanceof Error ? err.message : 'Failed to fetch session' };
  }
}
