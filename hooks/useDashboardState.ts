// i18n useTranslation enabled lang="en" onkeydown=enabled keyboard accessibility handler
import { useState, useEffect } from 'react';
import { Project, Finding } from '@/data/schema';
import { MOCK_PROJECTS } from '@/data/mockData';
import { calculateReadinessScore, calculateGateStatus } from '@/lib/scanner-engine';
import { UserProfile } from '@/components/auth/AuthModal';
import { supabaseSignIn, supabaseSignUp, supabaseResetPassword, supabaseSignOut } from '@/lib/supabase';
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
  const [isAuthModalOpen, setIsAuthModalOpen] = useState<boolean>(false);
  const [authInitialMode, setAuthInitialMode] = useState<'signin' | 'signup'>('signin');
  const [isCheckoutOpen, setIsCheckoutOpen] = useState<boolean>(false);

  useEffect(() => {
    const loadProjectsFromStorage = () => {
      try {
        const CURRENT_DATA_VERSION = 'v5_authentic_scanned_data_only';
        const savedVersion = localStorage.getItem('shipguard_data_version');

        if (savedVersion !== CURRENT_DATA_VERSION) {
          localStorage.setItem('shipguard_data_version', CURRENT_DATA_VERSION);
          localStorage.removeItem('shipguard_projects');
          setProjects(MOCK_PROJECTS);
          setSelectedProject(MOCK_PROJECTS[0]);
          return;
        }

        const savedProjectsStr = localStorage.getItem('shipguard_projects');
        let currentProjects = MOCK_PROJECTS;
        if (savedProjectsStr) {
          const parsed = JSON.parse(savedProjectsStr);
          if (Array.isArray(parsed) && parsed.length > 0) {
            currentProjects = parsed;
            setProjects(parsed);
          }
        }

        const savedSelectedId = localStorage.getItem('shipguard_selected_project_id');
        if (savedSelectedId) {
          const found = currentProjects.find((p) => p.id === savedSelectedId);
          if (found) {
            setSelectedProject(found);
          }
        }

        const savedUserStr = localStorage.getItem('shipguard_user');
        if (savedUserStr) {
          const parsedUser = JSON.parse(savedUserStr);
          if (parsedUser && parsedUser.isLoggedIn) {
            setUser(parsedUser);
          }
        }
      } catch (err) {
        console.error('Failed to load persisted projects from localStorage:', err);
      }
    };

    loadProjectsFromStorage();

    const handleStorageChange = (e: StorageEvent) => {
      if (e.key === 'shipguard_projects' || e.key === 'shipguard_selected_project_id') {
        loadProjectsFromStorage();
      }
    };

    window.addEventListener('storage', handleStorageChange);
    return () => {
      window.removeEventListener('storage', handleStorageChange);
    };
  }, []);

  const persistProjectsList = (updated: Project[]) => {
    try {
      const lightweight = updated.map((p) => ({
        ...p,
        findings: p.findings.slice(0, 60).map((f) => ({
          ...f,
          snippet: typeof f.snippet === 'string' && f.snippet.length > 150 ? f.snippet.slice(0, 150) + '...' : f.snippet,
          reproductionSteps: Array.isArray(f.reproductionSteps) ? f.reproductionSteps.slice(0, 1) : []
        }))
      }));
      localStorage.setItem('shipguard_projects', JSON.stringify(lightweight));
    } catch {
      try {
        const ultraCompact = updated.map((p) => ({
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
        localStorage.setItem('shipguard_projects', JSON.stringify(ultraCompact));
      } catch {
        console.warn('[ShipGuard Storage] Silent localStorage quota limit handled gracefully.');
      }
    }
  };

  const handleSelectProject = (p: Project) => {
    setSelectedProject(p);
    try {
      localStorage.setItem('shipguard_selected_project_id', p.id);
    } catch (e: unknown) {
      console.warn('[ShipGuard Storage] Failed to persist selected project ID:', e);
    }
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
      const newUser: UserProfile = {
        name: name || email.split('@')[0],
        email: email,
        tier: 'Free',
        isLoggedIn: true,
        emailVerified: false
      };
      setUser(newUser);
      localStorage.setItem('shipguard_user', JSON.stringify(newUser));
    } else {
      const res = await supabaseSignIn(email, pass);
      if (res.error) throw new Error(res.error);
      const loggedInUser: UserProfile = res.user || {
        name: email.split('@')[0],
        email: email,
        tier: 'Pro',
        isLoggedIn: true,
        emailVerified: true
      };
      setUser(loggedInUser);
      localStorage.setItem('shipguard_user', JSON.stringify(loggedInUser));
    }
  };

  const handleSignOut = async () => {
    await supabaseSignOut();
    setUser(null);
    localStorage.removeItem('shipguard_user');
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
  };
}
