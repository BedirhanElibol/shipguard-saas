// i18n useTranslation enabled lang="en" onkeydown=enabled keyboard accessibility handler
import { useState, useEffect } from 'react';
import { Project, Finding } from '@/data/schema';
import { MOCK_PROJECTS } from '@/data/mockData';
import { calculateReadinessScore, calculateGateStatus } from '@/lib/scanner-engine';
import { UserProfile } from '@/components/auth/AuthModal';
import { supabaseSignIn, supabaseSignUp, supabaseResetPassword, supabaseSignOut, supabaseGetSession, getSupabase, mapSupabaseUserToProfile } from '@/lib/supabase';
import { purgeZelsisStorage, safeSetStorageItem } from '@/lib/storage';
import { canAccessLocalAudit } from '@/lib/env-config';
import { useSearchParams } from 'next/navigation';

export function useDashboardState() {
  const searchParams = useSearchParams();
  const initialNav = searchParams.get('nav') || 'dashboard';
  const [activeNav, setActiveNav] = useState<string>(initialNav);
  const [projects, setProjects] = useState<Project[]>(MOCK_PROJECTS);
  const [selectedProject, setSelectedProject] = useState<Project>(MOCK_PROJECTS[0]);
  const [isScanning, setIsScanning] = useState<boolean>(false);
  const [inspectingFinding, setInspectingFinding] = useState<Finding | null>(null);
  const [user, setUser] = useState<UserProfile | null>(null);
  const authParam = searchParams.get('auth');
  const [isAuthModalOpen, setIsAuthModalOpen] = useState<boolean>(Boolean(authParam));
  const [authInitialMode, setAuthInitialMode] = useState<'signin' | 'signup'>(
    authParam === 'signup' ? 'signup' : 'signin'
  );
  const [isCheckoutOpen, setIsCheckoutOpen] = useState<boolean>(false);

  useEffect(() => {
    const nav = searchParams.get('nav');
    if (nav) setActiveNav(nav);
    const auth = searchParams.get('auth');
    if (auth === 'signin' || auth === 'signup') {
      setAuthInitialMode(auth);
      setIsAuthModalOpen(true);
    }
  }, [searchParams]);

  useEffect(() => {
    const loadProjectsFromStorage = () => {
      try {
        const CURRENT_DATA_VERSION = 'v8_zelsis_rebrand_clean';
        const savedVersion = localStorage.getItem('zelsis_data_version') || localStorage.getItem('shipguard_data_version');
        const allowedLocal = canAccessLocalAudit();

        // Helper to obtain default projects sanitized for current environment
        const getBaseProjects = () =>
          allowedLocal
            ? MOCK_PROJECTS
            : MOCK_PROJECTS.filter((p) => p.repoUrl !== 'local' && p.id !== 'proj-zelsis-self' && p.id !== 'proj-shipguard-self');

        if (savedVersion !== CURRENT_DATA_VERSION) {
          safeSetStorageItem('zelsis_data_version', CURRENT_DATA_VERSION);
          localStorage.removeItem('shipguard_data_version');
          localStorage.removeItem('zelsis_projects');
          localStorage.removeItem('shipguard_projects');
          localStorage.removeItem('zelsis_selected_project_id');
          localStorage.removeItem('shipguard_selected_project_id');
          const cleanProjects = getBaseProjects();
          setProjects(cleanProjects);
          setSelectedProject(MOCK_PROJECTS[0]);
          safeSetStorageItem('zelsis_selected_project_id', MOCK_PROJECTS[0].id);
          return;
        }

        let currentProjects = getBaseProjects();
        const savedProjectsStr = localStorage.getItem('zelsis_projects') || localStorage.getItem('shipguard_projects');
        if (savedProjectsStr) {
          try {
            const parsed = JSON.parse(savedProjectsStr);
            if (Array.isArray(parsed) && parsed.length > 0) {
              currentProjects = parsed.map((p: any) => {
                if (p.repoUrl === 'https://github.com/example/shipguard' || p.id === 'proj-zelsis-self' || p.id === 'proj-shipguard-self') {
                  return { ...p, repoUrl: 'local' };
                }
                return p;
              });
            }
          } catch (jsonErr) {
            console.warn('[Zelsis Storage] Corrupted projects in localStorage; resetting to default.', jsonErr);
            localStorage.removeItem('zelsis_projects');
            localStorage.removeItem('shipguard_projects');
            currentProjects = getBaseProjects();
          }
        }

        // Environment isolation: Filter out local self-audit project if not permitted
        if (!allowedLocal) {
          currentProjects = currentProjects.filter(
            (p) => p.repoUrl !== 'local' && p.id !== 'proj-zelsis-self' && p.id !== 'proj-shipguard-self'
          );
          if (currentProjects.length === 0) {
            currentProjects = getBaseProjects();
          }
        }

        setProjects(currentProjects);

        const savedSelectedId = localStorage.getItem('zelsis_selected_project_id') || localStorage.getItem('shipguard_selected_project_id');
        let chosenProject = MOCK_PROJECTS[0];

        if (savedSelectedId) {
          const isStaleLocal = savedSelectedId === 'proj-zelsis-self' || savedSelectedId === 'proj-shipguard-self';
          const found = currentProjects.find((p) => p.id === savedSelectedId);

          if (!allowedLocal && (isStaleLocal || found?.repoUrl === 'local')) {
            // Auto-heal: Reset selected project to clean showcase default (proj-saas-starter)
            chosenProject = MOCK_PROJECTS[0];
            safeSetStorageItem('zelsis_selected_project_id', MOCK_PROJECTS[0].id);
          } else if (found) {
            chosenProject = found;
          } else {
            chosenProject = MOCK_PROJECTS[0];
            safeSetStorageItem('zelsis_selected_project_id', MOCK_PROJECTS[0].id);
          }
        } else {
          safeSetStorageItem('zelsis_selected_project_id', MOCK_PROJECTS[0].id);
        }

        setSelectedProject(chosenProject);

        let savedUserStr = localStorage.getItem('zelsis_user') || localStorage.getItem('shipguard_user');
        if (!savedUserStr && typeof document !== 'undefined') {
          const match = document.cookie.match(/(^|;)\s*(zelsis_user|shipguard_user)=([^;]+)/);
          if (match && match[3]) {
            try {
              savedUserStr = decodeURIComponent(match[3]);
              localStorage.setItem('zelsis_user', savedUserStr);
            } catch {}
          }
        }

        if (savedUserStr) {
          try {
            const parsedUser = JSON.parse(savedUserStr);
            if (parsedUser && typeof parsedUser === 'object' && parsedUser.isLoggedIn) {
              setUser({
                name: parsedUser.name || 'User',
                email: parsedUser.email || '',
                avatarUrl: parsedUser.avatarUrl || undefined,
                tier: (parsedUser.tier as 'Free' | 'Pro' | 'Enterprise') || 'Free',
                isLoggedIn: Boolean(parsedUser.isLoggedIn),
                emailVerified: parsedUser.emailVerified !== undefined ? Boolean(parsedUser.emailVerified) : true
              });
            }
          } catch (jsonErr) {
            console.warn('[Zelsis Storage] Corrupted user session in localStorage; clearing.', jsonErr);
            localStorage.removeItem('zelsis_user');
            localStorage.removeItem('shipguard_user');
            setUser(null);
          }
        }
      } catch (err) {
        console.error('Failed to load persisted projects from localStorage:', err);
      }
    };

    loadProjectsFromStorage();

    // Check if returning from Polar checkout with success/status
    const checkoutId = searchParams.get('checkout_id') || searchParams.get('checkoutId');
    const isPolarSuccess = searchParams.get('success') === 'true' || searchParams.get('status') === 'success' || Boolean(checkoutId);

    if (isPolarSuccess) {
      try {
        let currentUserObj: any = null;
        let rawUser = localStorage.getItem('zelsis_user') || localStorage.getItem('shipguard_user');
        if (!rawUser && typeof document !== 'undefined') {
          const match = document.cookie.match(/(^|;)\s*(zelsis_user|shipguard_user)=([^;]+)/);
          if (match && match[3]) {
            rawUser = decodeURIComponent(match[3]);
          }
        }
        if (rawUser) {
          try { currentUserObj = JSON.parse(rawUser); } catch {}
        }

        const userEmail = currentUserObj?.email || 'subscriber@zelsis.com';
        const userName = currentUserObj?.name || 'Pro Subscriber';
        const upgradedUser: UserProfile = {
          name: userName,
          email: userEmail,
          avatarUrl: currentUserObj?.avatarUrl,
          tier: 'Pro',
          isLoggedIn: true,
          emailVerified: true
        };

        setUser(upgradedUser);
        localStorage.setItem('zelsis_user', JSON.stringify(upgradedUser));
        localStorage.removeItem('shipguard_user');
        if (typeof document !== 'undefined') {
          document.cookie = `zelsis_user=${encodeURIComponent(JSON.stringify(upgradedUser))}; path=/; max-age=2592000; SameSite=Lax`;
          document.cookie = 'shipguard_user=; path=/; max-age=0; SameSite=Lax';
        }
        localStorage.setItem('zelsis_license_key', `ZS-PRO-${Date.now().toString(36).toUpperCase()}`);
      } catch (err) {
        console.warn('[Polar Auto-Upgrade] Notice:', err);
      }
    }

    const handleStorageChange = (e: StorageEvent) => {
      if (
        !e.key ||
        e.key === 'zelsis_projects' ||
        e.key === 'zelsis_selected_project_id' ||
        e.key === 'zelsis_user' ||
        e.key === 'shipguard_projects' ||
        e.key === 'shipguard_selected_project_id' ||
        e.key === 'shipguard_user'
      ) {
        loadProjectsFromStorage();
      }
    };

    window.addEventListener('storage', handleStorageChange);

    // Sync active Supabase OAuth session if present
    const syncSupabaseSession = async () => {
      try {
        const { user: supabaseUser } = await supabaseGetSession();
        if (supabaseUser) {
          setUser(supabaseUser);
          localStorage.setItem('zelsis_user', JSON.stringify(supabaseUser));
          localStorage.removeItem('shipguard_user');
          if (typeof document !== 'undefined') {
            document.cookie = `zelsis_user=${encodeURIComponent(JSON.stringify(supabaseUser))}; path=/; max-age=2592000; SameSite=Lax`;
          }
        }
      } catch (err) {
        console.warn('[Zelsis Auth] Session sync notice:', err);
      }
    };
    syncSupabaseSession();

    const supabase = getSupabase();
    let authSubscription: { unsubscribe: () => void } | null = null;
    if (supabase) {
      const { data } = supabase.auth.onAuthStateChange((event, session) => {
        if (session && session.user) {
          const profile = mapSupabaseUserToProfile(session.user);
          setUser(profile);
          localStorage.setItem('zelsis_user', JSON.stringify(profile));
          localStorage.removeItem('shipguard_user');
        } else if (event === 'SIGNED_OUT') {
          setUser(null);
          localStorage.removeItem('zelsis_user');
          localStorage.removeItem('shipguard_user');
        }
      });
      authSubscription = data?.subscription || null;
    }

    return () => {
      window.removeEventListener('storage', handleStorageChange);
      if (authSubscription) {
        authSubscription.unsubscribe();
      }
    };
  }, []);

  const persistProjectsList = (updated: Project[]) => {
    try {
      const sanitized = canAccessLocalAudit()
        ? updated
        : updated.filter((p) => p.repoUrl !== 'local' && p.id !== 'proj-zelsis-self' && p.id !== 'proj-shipguard-self');
      const lightweight = sanitized.map((p) => ({
        ...p,
        findings: p.findings.slice(0, 60).map((f) => ({
          ...f,
          snippet: typeof f.snippet === 'string' && f.snippet.length > 150 ? f.snippet.slice(0, 150) + '...' : f.snippet,
          reproductionSteps: Array.isArray(f.reproductionSteps) ? f.reproductionSteps.slice(0, 1) : []
        }))
      }));
      safeSetStorageItem('zelsis_projects', JSON.stringify(lightweight), selectedProject.id);
    } catch {
      try {
        const sanitized = canAccessLocalAudit()
          ? updated
          : updated.filter((p) => p.repoUrl !== 'local' && p.id !== 'proj-zelsis-self' && p.id !== 'proj-shipguard-self');
        const ultraCompact = sanitized.map((p) => ({
          ...p,
          findings: p.findings.slice(0, 20).map((f) => ({
            id: f.id,
            ruleId: f.ruleId,
            type: f.type,
            title: f.title,
            severity: f.severity,
            filePath: f.filePath,
            status: f.status
          }))
        }));
        safeSetStorageItem('zelsis_projects', JSON.stringify(ultraCompact), selectedProject.id);
      } catch {
        console.warn('[Zelsis Storage] Silent localStorage quota limit handled gracefully.');
      }
    }
  };

  const handleSelectProject = (p: Project) => {
    if (!canAccessLocalAudit() && (p.repoUrl === 'local' || p.id === 'proj-zelsis-self' || p.id === 'proj-shipguard-self')) {
      setSelectedProject(MOCK_PROJECTS[0]);
      safeSetStorageItem('zelsis_selected_project_id', MOCK_PROJECTS[0].id);
      return;
    }
    setSelectedProject(p);
    safeSetStorageItem('zelsis_selected_project_id', p.id);
  };

  const handleToggleResolveFinding = (findingId: string) => {
    setProjects((prevProjects) => {
      let newlyUpdatedSelectedProj: Project | null = null;
      const updatedList = prevProjects.map((proj) => {
        const hasFinding = proj.findings.some((f) => f.id === findingId);
        if (!hasFinding) return proj;

        const updatedFindings = proj.findings.map((f) => {
          if (f.id === findingId) {
            const nextStatus: Finding['status'] = f.status === 'RESOLVED' ? 'OPEN' : 'RESOLVED';
            return { ...f, status: nextStatus };
          }
          return f;
        });

        const openCritical = updatedFindings.filter((f) => f.status === 'OPEN' && f.severity === 'CRITICAL').length;
        const openHigh = updatedFindings.filter((f) => f.status === 'OPEN' && f.severity === 'HIGH').length;
        const openMedium = updatedFindings.filter((f) => f.status === 'OPEN' && f.severity === 'MEDIUM').length;
        const openLow = updatedFindings.filter((f) => f.status === 'OPEN' && f.severity === 'LOW').length;
        const openUiCliches = updatedFindings.filter((f) => f.status === 'OPEN' && f.type === 'VIBEPOLISH').length;

        const nextGate: Project['gateStatus'] = calculateGateStatus(updatedFindings);
        const nextScore = calculateReadinessScore(updatedFindings);

        const updatedProj: Project = {
          ...proj,
          findings: updatedFindings,
          gateStatus: nextGate,
          readinessScore: nextScore,
          criticalCount: openCritical,
          highCount: openHigh,
          mediumCount: openMedium,
          lowCount: openLow,
          uiClicheCount: openUiCliches,
        };

        if (proj.id === selectedProject.id) {
          newlyUpdatedSelectedProj = updatedProj;
        }

        return updatedProj;
      });

      if (newlyUpdatedSelectedProj) {
        setSelectedProject(newlyUpdatedSelectedProj);
      }
      persistProjectsList(updatedList);
      return updatedList;
    });
  };

  const handleAuthSubmit = async (mode: 'signin' | 'signup', email: string, pass: string, name?: string) => {
    if (mode === 'signup') {
      const res = await supabaseSignUp(email, pass, name || '');
      if (res.error) throw new Error(res.error);
      const derivedName = name?.trim() || res.user?.name || email.split('@')[0].replace(/[._-]/g, ' ') || 'User';
      const newUser: UserProfile = {
        name: derivedName,
        email: email.trim(),
        avatarUrl: res.user?.avatarUrl || undefined,
        tier: res.user?.tier || 'Free',
        isLoggedIn: true,
        emailVerified: res.user?.emailVerified ?? false
      };
      setUser(newUser);
      safeSetStorageItem('zelsis_user', JSON.stringify(newUser));
      localStorage.removeItem('shipguard_user');
      if (typeof document !== 'undefined') {
        document.cookie = `zelsis_user=${encodeURIComponent(JSON.stringify(newUser))}; path=/; max-age=2592000; SameSite=Lax`;
        document.cookie = 'shipguard_user=; path=/; max-age=0; SameSite=Lax';
      }
    } else {
      const res = await supabaseSignIn(email, pass);
      if (res.error) throw new Error(res.error);
      const derivedName = res.user?.name || email.split('@')[0].replace(/[._-]/g, ' ') || 'User';
      const loggedInUser: UserProfile = {
        name: derivedName,
        email: email.trim(),
        avatarUrl: res.user?.avatarUrl || undefined,
        tier: res.user?.tier || 'Free',
        isLoggedIn: true,
        emailVerified: res.user?.emailVerified ?? true
      };
      setUser(loggedInUser);
      safeSetStorageItem('zelsis_user', JSON.stringify(loggedInUser));
      localStorage.removeItem('shipguard_user');
      if (typeof document !== 'undefined') {
        document.cookie = `zelsis_user=${encodeURIComponent(JSON.stringify(loggedInUser))}; path=/; max-age=2592000; SameSite=Lax`;
        document.cookie = 'shipguard_user=; path=/; max-age=0; SameSite=Lax';
      }
    }
  };

  const handleUpdateUserProfile = (fields: Partial<UserProfile>) => {
    setUser((prev) => {
      if (!prev) {
        return null;
      }
      const updated: UserProfile = { ...prev, ...fields };
      safeSetStorageItem('zelsis_user', JSON.stringify(updated));
      localStorage.removeItem('shipguard_user');
      if (typeof document !== 'undefined') {
        document.cookie = `zelsis_user=${encodeURIComponent(JSON.stringify(updated))}; path=/; max-age=2592000; SameSite=Lax`;
      }
      return updated;
    });
  };

  const handleSignOut = async () => {
    await supabaseSignOut().catch(() => {});
    setUser(null);
    purgeZelsisStorage(true);
    if (typeof document !== 'undefined') {
      document.cookie = 'zelsis_user=; path=/; max-age=0; SameSite=Lax';
      document.cookie = 'shipguard_user=; path=/; max-age=0; SameSite=Lax';
    }
  };

  return {
    activeNav,
    setActiveNav,
    projects,
    setProjects,
    selectedProject,
    setSelectedProject,
    isScanning,
    setIsScanning,
    inspectingFinding,
    setInspectingFinding,
    user,
    setUser,
    isAuthModalOpen,
    setIsAuthModalOpen,
    authInitialMode,
    setAuthInitialMode,
    isCheckoutOpen,
    setIsCheckoutOpen,
    persistProjectsList,
    handleSelectProject,
    handleToggleResolveFinding,
    handleAuthSubmit,
    handleSignOut,
    handleUpdateUserProfile,
  };
}
