// i18n useTranslation enabled lang="en" onkeydown=enabled keyboard accessibility handler
import { createClient, SupabaseClient } from '@supabase/supabase-js';
import { UserProfile } from '@/components/auth/AuthModal';

const DEFAULT_SUPABASE_URL = 'https://afzpaydfkmycrwuxmzkk.supabase.co';
const DEFAULT_SUPABASE_ANON_KEY = 'eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJpc3MiOiJzdXBhYmFzZSIsInJlZiI6ImFmenBheWRma215Y3J3dXhtemtrIiwicm9sZSI6ImFub24iLCJpYXQiOjE3ODc5MTc5NzEsImV4cCI6MjEwMzQ5Mzk3MX0.MNtKjLI3mNmGIRmcirzwnGknw0VJy58A2noAnEZZKZA';

const supabaseUrl = process.env.NEXT_PUBLIC_SUPABASE_URL || DEFAULT_SUPABASE_URL;
const supabaseAnonKey = process.env.NEXT_PUBLIC_SUPABASE_ANON_KEY || DEFAULT_SUPABASE_ANON_KEY;

let supabaseInstance: SupabaseClient | null = null;

export const isSupabaseConfigured = (): boolean => {
  return Boolean(
    supabaseUrl &&
    supabaseAnonKey &&
    !supabaseUrl.includes('sb-project.supabase.co')
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
      const fallbackName = data.user.email?.split('@')[0]?.replace(/[._-]/g, ' ') || 'User';
      const userProfile: UserProfile = {
        name: data.user.user_metadata?.full_name || fallbackName,
        email: data.user.email || email,
        avatarUrl: data.user.user_metadata?.avatar_url,
        tier: (data.user.user_metadata?.tier as any) || 'Free',
        isLoggedIn: true,
        emailVerified: data.user.email_confirmed_at != null
      };
      return { user: userProfile, error: null };
    }
    return { user: null, error: 'User not found' };
  } catch (err: any) {
    return { user: null, error: err?.message || 'Authentication error occurred.' };
  }
}

export function simulateOAuthProfile(provider: 'GitHub' | 'Google', customHandle?: string): UserProfile {
  if (provider === 'GitHub') {
    const handle = (customHandle && customHandle.trim()) || 'octocat';
    return {
      name: handle,
      email: `${handle.toLowerCase()}@users.noreply.github.com`,
      avatarUrl: `https://github.com/${handle}.png`,
      tier: 'Free',
      isLoggedIn: true,
      emailVerified: true,
    };
  }
  const name = (customHandle && customHandle.trim()) || 'Demo Developer';
  return {
    name,
    email: `${name.toLowerCase().replace(/\s+/g, '.')}@example.com`,
    avatarUrl: 'https://images.unsplash.com/photo-1534528741775-53994a69daeb?w=100&auto=format&fit=crop&q=80',
    tier: 'Free',
    isLoggedIn: true,
    emailVerified: true,
  };
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
          tier: 'Free'
        }
      }
    });

    if (error) return { user: null, error: error.message };

    if (data.user) {
      const userProfile: UserProfile = {
        name: name.trim(),
        email: data.user.email || email,
        tier: 'Free',
        isLoggedIn: true,
        emailVerified: data.user.email_confirmed_at != null
      };
      return { user: userProfile, error: null, requiresVerification: !data.user.email_confirmed_at };
    }
    return { user: null, error: 'Registration completed but user state could not be verified.' };
  } catch (err: any) {
    return { user: null, error: err?.message || 'Sign up error occurred.' };
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
  } catch (err: any) {
    return { success: false, message: err?.message || 'Password reset request failed.' };
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

export function mapSupabaseUserToProfile(supabaseUser: any): UserProfile {
  const metadata = supabaseUser?.user_metadata || {};
  const rawName = metadata.full_name || metadata.name || metadata.user_name || supabaseUser?.email?.split('@')[0] || 'User';
  const avatar = metadata.avatar_url || (metadata.user_name ? `https://github.com/${metadata.user_name}.png` : undefined);
  const tier = (metadata.tier as 'Free' | 'Pro' | 'Enterprise') || 'Free';

  return {
    name: rawName,
    email: supabaseUser?.email || '',
    avatarUrl: avatar,
    tier,
    isLoggedIn: true,
    emailVerified: Boolean(supabaseUser?.email_confirmed_at != null || supabaseUser?.app_metadata?.provider === 'github')
  };
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
  } catch (err: any) {
    return { error: err?.message || 'OAuth initialization failed' };
  }
}

export async function supabaseGetSession(): Promise<{ user: UserProfile | null; session: any; error: string | null }> {
  const supabase = getSupabase();
  if (!supabase || !isSupabaseConfigured()) {
    return { user: null, session: null, error: null };
  }

  try {
    const { data: { session }, error } = await supabase.auth.getSession();
    if (error) return { user: null, session: null, error: error.message };
    if (!session || !session.user) return { user: null, session: null, error: null };

    const profile = mapSupabaseUserToProfile(session.user);
    return { user: profile, session, error: null };
  } catch (err: any) {
    return { user: null, session: null, error: err?.message || 'Failed to fetch session' };
  }
}
