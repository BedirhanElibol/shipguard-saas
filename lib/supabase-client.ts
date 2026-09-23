import { Project, Finding } from '@/data/schema';

import { getSupabase } from './supabase';

/**
 * Resilient Supabase Service Layer for Zelsis Release Gate
 * Provides production DB persistence when environment variables exist,
 * with fallback support to client-side localStorage.
 * Attaches authenticated user JWT Bearer headers and user_id to comply with PostgreSQL RLS.
 */
export interface SupabaseConfig {
  url?: string;
  anonKey?: string;
}

export function getSupabaseConfig(): SupabaseConfig {
  return {
    url: process.env.NEXT_PUBLIC_SUPABASE_URL || process.env.SUPABASE_URL,
    anonKey: process.env.NEXT_PUBLIC_SUPABASE_ANON_KEY || process.env.SUPABASE_ANON_KEY,
  };
}

export function isSupabaseConfigured(): boolean {
  const config = getSupabaseConfig();
  return Boolean(config.url && config.anonKey);
}

/**
 * Retrieves the active user JWT token and user ID from Supabase session if authenticated
 */
export async function getActiveUserAuth(): Promise<{ accessToken: string | null; userId: string | null }> {
  const client = getSupabase();
  if (!client) return { accessToken: null, userId: null };

  try {
    const { data } = await client.auth.getSession();
    if (data?.session?.access_token && data.session.user?.id) {
      return {
        accessToken: data.session.access_token,
        userId: data.session.user.id
      };
    }
  } catch (err) {
    console.warn('[Supabase Auth] Could not retrieve session for RLS header:', err);
  }

  return { accessToken: null, userId: null };
}

/**
 * Saves or updates a project record in Supabase REST API endpoint
 * Attaches user JWT Bearer authorization header and user_id to satisfy PostgreSQL RLS policies.
 */
export async function syncProjectToSupabase(
  project: Project,
  explicitAuth?: { accessToken?: string; userId?: string }
): Promise<boolean> {
  const config = getSupabaseConfig();
  if (!config.url || !config.anonKey) {
    return false;
  }

  try {
    // Resolve authenticated user credentials for RLS compliance
    const activeAuth = await getActiveUserAuth();
    const accessToken = explicitAuth?.accessToken || activeAuth.accessToken || config.anonKey;
    const userId = explicitAuth?.userId || activeAuth.userId;

    const headers: Record<string, string> = {
      'Content-Type': 'application/json',
      apikey: config.anonKey,
      Authorization: `Bearer ${accessToken}`,
      Prefer: 'resolution=merge-duplicates,return=representation',
    };

    const isUuid = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i.test(project.id);

    const payload: Record<string, any> = {
      name: project.name,
      repo_url: project.repoUrl,
      // F-08 Remediation: Never store user PATs or GitHub credentials in cloud database
      github_token: null,
      preview_url: project.previewUrl || null,
      framework: project.framework,
      providers: project.providers,
      last_scan_at: new Date().toISOString(),
      readiness_score: project.readinessScore,
      gate_status: project.gateStatus,
      critical_count: project.criticalCount,
      high_count: project.highCount,
      medium_count: project.mediumCount,
      low_count: project.lowCount,
      ui_cliche_count: project.uiClicheCount,
    };

    if (isUuid) {
      payload.id = project.id;
    }

    if (userId) {
      payload.user_id = userId;
    }

    const res = await fetch(`${config.url}/rest/v1/projects?on_conflict=id`, {
      method: 'POST',
      headers,
      body: JSON.stringify(payload),
    });

    return res.ok;
  } catch (err) {
    console.warn('[Supabase Sync Warning] Could not sync project to cloud DB:', err);
    return false;
  }
}
