'use client';

import React, { Suspense, useState, useEffect } from 'react';
import { Project, Finding, ScanHistoryItem } from '@/data/schema';
import { MOCK_PROJECTS, VIBEPOLISH_30_CATALOG, UI_RULES_CATALOG, AI_CLICHE_25_CATALOG } from '@/data/mockData';
import { AppShell } from '@/components/layout/AppShell';
import { DashboardView } from '@/components/dashboard/DashboardView';
import { SecurityAuditView } from '@/components/SecurityAuditView';
import { ComplianceAuditView } from '@/components/ComplianceAuditView';
import { InfraAuditView } from '@/components/InfraAuditView';
import { CicdAutomationView } from '@/components/CicdAutomationView';
import { VibePolishView } from '@/components/VibePolishView';
import { VibeCareView } from '@/components/VibeCareView';
import { RemediationQueueView } from '@/components/RemediationQueueView';
import { ProjectsView } from '@/components/ProjectsView';
import { ScanRunnerView } from '@/components/ScanRunnerView';
import { ScanHistoryView } from '@/components/ScanHistoryView';
import { ProjectSettingsView } from '@/components/ProjectSettingsView';
import { RemediationDrawer } from '@/components/findings/RemediationDrawer';
import { AuthModal, UserProfile } from '@/components/auth/AuthModal';
import { StripeCheckoutModal } from '@/components/checkout/StripeCheckoutModal';
import { CheckoutView } from '@/components/checkout/CheckoutView';
import { useDashboardState } from '@/hooks/useDashboardState';
import { useRouter, useSearchParams } from 'next/navigation';
import { verifyLicenseKey } from '@/lib/stripe-checkout';
import { safeSetStorageItem } from '@/lib/storage';
import { ShieldCheck, Plus } from 'lucide-react';
import { LifecycleBanner } from '@/components/dashboard/LifecycleBanner';
import { normalizeRepoUrl, extractRepoDisplayName } from '@/lib/github-api';

export default function DashboardPage() {
  return (
    <Suspense fallback={<div className="min-h-screen bg-[#0A0A0A]" />}>
      <DashboardContent />
    </Suspense>
  );
}

function DashboardContent() {
  const router = useRouter();
  const searchParams = useSearchParams();
  const {
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
    handleDeleteProject,
    handleToggleResolveFinding,
    handleSignOut,
    handleUpdateUserProfile,
  } = useDashboardState();

  const [checkoutInitialPlan, setCheckoutInitialPlan] = useState<'Pro' | 'Enterprise'>('Pro');
  const [scanProjectOverride, setScanProjectOverride] = useState<Project | null>(null);
  const hasProcessedRepoRef = React.useRef(false);

  const handleTriggerScan = (projectOverride?: Project) => {
    if (projectOverride) {
      handleSelectProject(projectOverride);
      setScanProjectOverride(projectOverride);
    } else {
      setScanProjectOverride(null);
    }
    setActiveNav('dashboard');
    setIsScanning(true);
  };

  const handleAddNewProject = (newP: Project) => {
    const newUrl = newP?.repoUrl || '';
    const normTarget = (newUrl === 'local' ? 'local' : (normalizeRepoUrl(newUrl) || newUrl)).toLowerCase().replace(/\/+$/, '').trim();
    setProjects((prev) => {
      const existingIdx = prev.findIndex((p) => {
        if (p.id === newP.id) return true;
        const pUrl = p?.repoUrl || '';
        const pNorm = (pUrl === 'local' ? 'local' : (normalizeRepoUrl(pUrl) || pUrl)).toLowerCase().replace(/\/+$/, '').trim();
        return pNorm === normTarget;
      });

      let updated: Project[];
      if (existingIdx >= 0) {
        const copy = [...prev];
        copy[existingIdx] = { ...copy[existingIdx], ...newP, id: copy[existingIdx].id };
        updated = copy;
      } else {
        updated = [newP, ...prev];
      }
      persistProjectsList(updated);
      return updated;
    });
    handleSelectProject(newP);
  };

  // Direct repo URL scan trigger (e.g. from Landing Hero or URL query params)
  useEffect(() => {
    const repoParam = searchParams.get('repo');
    const scanParam = searchParams.get('scan');
    if (!repoParam || hasProcessedRepoRef.current) return;
    hasProcessedRepoRef.current = true;

    const normalized = normalizeRepoUrl(repoParam);
    if (!normalized) return;

    const existing = projects.find(
      (p) => (p?.repoUrl || '').toLowerCase() === (normalized || '').toLowerCase()
    );

    if (existing) {
      handleSelectProject(existing);
      if (scanParam === 'true') {
        handleTriggerScan(existing);
      }
    } else {
      const displayName = extractRepoDisplayName(normalized);
      const newProj: Project = {
        id: `proj-import-${Date.now()}`,
        name: displayName,
        repoUrl: normalized,
        framework: 'Next.js 15',
        providers: ['GitHub Action', 'Vercel'],
        lastScanAt: 'Ready to Run Audit',
        readinessScore: 100,
        gateStatus: 'PASSED',
        criticalCount: 0,
        highCount: 0,
        mediumCount: 0,
        lowCount: 0,
        uiClicheCount: 0,
        findings: []
      };
      handleAddNewProject(newProj);
      if (scanParam === 'true') {
        handleTriggerScan(newProj);
      }
    }

    if (typeof window !== 'undefined') {
      const cleanUrl = new URL(window.location.href);
      cleanUrl.searchParams.delete('repo');
      cleanUrl.searchParams.delete('scan');
      window.history.replaceState({}, '', cleanUrl.toString());
    }
  }, [searchParams, projects]);

  const handleOpenCheckoutModal = (requestedPlan?: 'Pro' | 'Enterprise') => {
    if (requestedPlan) {
      setCheckoutInitialPlan(requestedPlan);
    } else {
      setCheckoutInitialPlan(user?.tier === 'Pro' ? 'Enterprise' : 'Pro');
    }
    if (!user || !user.isLoggedIn) {
      setAuthInitialMode('signup');
      setIsAuthModalOpen(true);
    } else {
      setIsCheckoutOpen(true);
    }
  };

  const handleLoadDemoFindings = (demoFindings: Finding[]) => {
    const criticals = demoFindings.filter((f) => f.status === 'OPEN' && f.severity === 'CRITICAL').length;
    const highs = demoFindings.filter((f) => f.status === 'OPEN' && f.severity === 'HIGH').length;
    const mediums = demoFindings.filter((f) => f.status === 'OPEN' && f.severity === 'MEDIUM').length;
    const lows = demoFindings.filter((f) => f.status === 'OPEN' && f.severity === 'LOW').length;
    const uiCliches = demoFindings.filter((f) => f.status === 'OPEN' && f.type === 'VIBEPOLISH').length;
    const updated: Project = {
      ...selectedProject,
      findings: demoFindings,
      criticalCount: criticals,
      highCount: highs,
      mediumCount: mediums,
      lowCount: lows,
      uiClicheCount: uiCliches,
      readinessScore: 68,
      gateStatus: 'FAILED',
      lastScanAt: 'Just now (Demo Template)'
    };
    setSelectedProject(updated);
    setProjects((prev) => {
      const updatedList = prev.map((p) => (p.id === selectedProject.id ? updated : p));
      persistProjectsList(updatedList);
      return updatedList;
    });
  };

  if (projects.length === 0) {
    const handleRestoreDemoShowcase = () => {
      const demoProject = MOCK_PROJECTS[0];
      setProjects([demoProject]);
      persistProjectsList([demoProject]);
      handleSelectProject(demoProject);
    };

    return (
      <div className="min-h-screen bg-[#0A0A0A] text-white flex items-center justify-center p-4 sm:p-6">
        <div className="max-w-md w-full bg-[#141414] border border-white/10 rounded-2xl p-6 sm:p-8 flex flex-col items-center text-center shadow-2xl">
          <div className="w-14 h-14 rounded-2xl bg-emerald-500/10 border border-emerald-500/30 flex items-center justify-center text-emerald-400 mb-5 shadow-inner">
            <ShieldCheck size={28} />
          </div>

          <h2 className="text-xl font-extrabold text-white tracking-tight mb-2">
            No Projects Connected
          </h2>

          <p className="text-xs sm:text-sm text-[#A1A1AA] leading-relaxed mb-6">
            Connect your GitHub repository to audit deployment readiness against OWASP security, performance, and UI quality standards, or explore with our interactive showcase.
          </p>

          <div className="flex flex-col sm:flex-row gap-3 w-full">
            <button
              onClick={handleRestoreDemoShowcase}
              className="btn btn-primary flex-1 py-2.5 px-4 rounded-xl text-xs font-bold font-mono bg-white text-black hover:bg-neutral-200 transition-all flex items-center justify-center gap-2 shadow-lg"
            >
              <ShieldCheck size={14} />
              <span>Load Demo Showcase</span>
            </button>

            <button
              onClick={() => {
                const newProj: Project = {
                  id: `proj-${Date.now()}`,
                  name: 'My New Application',
                  repoUrl: 'https://github.com/example/repo',
                  framework: 'Next.js 15',
                  providers: ['Vercel', 'PostgreSQL'],
                  lastScanAt: 'Never audited',
                  readinessScore: 100,
                  gateStatus: 'PASSED',
                  criticalCount: 0,
                  highCount: 0,
                  mediumCount: 0,
                  lowCount: 0,
                  uiClicheCount: 0,
                  findings: []
                };
                handleAddNewProject(newProj);
              }}
              className="btn btn-secondary flex-1 py-2.5 px-4 rounded-xl text-xs font-bold font-mono border-white/10 text-white hover:bg-white/5 transition-all flex items-center justify-center gap-2"
            >
              <Plus size={14} />
              <span>Connect Your First Project</span>
            </button>
          </div>
        </div>
      </div>
    );
  }

  return (
    <AppShell
      projects={projects}
      activeNav={activeNav}
      onNavigate={(nav) => {
        setIsScanning(false);
        setActiveNav(nav);
      }}
      selectedProject={selectedProject}
      onSelectProject={handleSelectProject}
      onTriggerScan={handleTriggerScan}
      onNavigateLanding={() => router.push('/')}
      onAddNewProject={handleAddNewProject}
      user={user}
      onOpenAuth={(mode) => {
        setAuthInitialMode(mode);
        setIsAuthModalOpen(true);
      }}
      onSignOut={handleSignOut}
      onOpenCheckout={() => handleOpenCheckoutModal()}
    >
      <div className="flex flex-col gap-6 w-full">
        <LifecycleBanner user={user} />
        {isScanning ? (
          <ScanRunnerView
            project={scanProjectOverride || selectedProject}
            onCompleteScan={(result) => {
              const currentTarget = scanProjectOverride || selectedProject;
              if (result) {
                const newScanHistoryItem: ScanHistoryItem = {
                  id: `SCAN-${Date.now().toString(36).toUpperCase()}`,
                  date: new Date().toLocaleString(),
                  target: currentTarget.repoUrl,
                  score: result.score,
                  gateStatus: result.gateStatus,
                  criticalCount: result.criticalCount,
                  highCount: result.highCount,
                  mediumCount: result.mediumCount,
                  duration: '3.4s',
                  triggeredBy: 'Manual Dashboard Audit'
                };
                const updatedProject: Project = {
                  ...currentTarget,
                  readinessScore: result.score,
                  gateStatus: result.gateStatus,
                  criticalCount: result.criticalCount,
                  highCount: result.highCount,
                  mediumCount: result.mediumCount,
                  lowCount: result.lowCount,
                  uiClicheCount: result.uiClicheCount,
                  findings: result.findings,
                  lastScanAt: new Date().toLocaleString(),
                  scanHistory: [newScanHistoryItem, ...((currentTarget as any).scanHistory || [])].slice(0, 20)
                };
                setSelectedProject(updatedProject);
                setProjects((prev) => {
                  const exists = prev.some((p) => p.id === currentTarget.id);
                  const updatedList = exists
                    ? prev.map((p) => (p.id === currentTarget.id ? updatedProject : p))
                    : [updatedProject, ...prev];
                  persistProjectsList(updatedList);
                  return updatedList;
                });
              }
              setScanProjectOverride(null);
              setIsScanning(false);
              setActiveNav('dashboard');
            }}
          />
        ) : (
          <>
            {activeNav === 'dashboard' && (
              <DashboardView
                project={selectedProject}
                onTriggerScan={handleTriggerScan}
                onInspectFinding={(f) => setInspectingFinding(f)}
                onNavigatePillar={(p) => setActiveNav(p)}
                onLoadDemoFindings={handleLoadDemoFindings}
                user={user}
                onOpenAuth={(mode) => {
                  setAuthInitialMode(mode);
                  setIsAuthModalOpen(true);
                }}
                onAddNewProject={handleAddNewProject}
                onSelectProject={handleSelectProject}
              />
            )}

            {activeNav === 'security' && (
              <SecurityAuditView
                findings={selectedProject.findings}
                onInspectFinding={(f) => setInspectingFinding(f)}
              />
            )}

            {activeNav === 'compliance' && (
              <ComplianceAuditView
                findings={selectedProject.findings}
                onInspectFinding={(f) => setInspectingFinding(f)}
              />
            )}

            {activeNav === 'infra' && (
              <InfraAuditView
                findings={selectedProject.findings}
                onInspectFinding={(f) => setInspectingFinding(f)}
              />
            )}

            {activeNav === 'vibepolish' && (
              <VibePolishView
                rules={VIBEPOLISH_30_CATALOG}
                title="Design & UX Polish Matrix"
                description="Automated design system audit evaluating visual hierarchy, responsive layout shifts, micro-interactions, color contrasts, and accessibility standards."
              />
            )}

            {activeNav === 'aicliche' && (
              <VibePolishView
                rules={AI_CLICHE_25_CATALOG}
                title="AI Anti-Pattern & Cliché Detector"
                description="Deep pattern analysis scanning for AI-generated design anti-patterns, generic layout locks, non-standard component trees, and trust-eroding visual tropes."
              />
            )}

            {activeNav === 'aimaster' && (
              <VibePolishView
                rules={UI_RULES_CATALOG}
                title="Master Quality & Resilience Matrix"
                description="Full-stack architecture audit covering OWASP top vulnerabilities, RAG retrieval leakage, agent execution boundaries, token cost governance, and production SLA metrics."
              />
            )}

            {activeNav === 'vibecare' && (
              <VibeCareView
                project={selectedProject}
                user={user}
                onOpenCheckout={() => handleOpenCheckoutModal('Enterprise')}
              />
            )}

            {activeNav === 'cicd' && (
              <CicdAutomationView projectName={selectedProject.name} />
            )}

            {activeNav === 'remediation' && (
              <RemediationQueueView
                projects={projects}
                onInspectFinding={(f) => setInspectingFinding(f)}
                onToggleResolveFinding={handleToggleResolveFinding}
              />
            )}

            {activeNav === 'projects' && (
              <ProjectsView
                projects={projects}
                onSelectProject={(p) => {
                  handleSelectProject(p);
                  setActiveNav('dashboard');
                }}
                onAddNewProject={handleAddNewProject}
                onDeleteProject={handleDeleteProject}
                onTriggerScan={handleTriggerScan}
                user={user}
                onOpenCheckout={() => handleOpenCheckoutModal()}
              />
            )}

          {activeNav === 'scans' && (
            <ScanHistoryView
              project={selectedProject}
              onTriggerScan={handleTriggerScan}
            />
          )}

          {activeNav === 'checkout' && (
            <CheckoutView
              initialPlanId={user?.tier === 'Pro' ? 'vibecare' : 'zelsis-core'}
              initialBilling="monthly"
              onBackToPricing={() => setActiveNav('dashboard')}
              user={user}
              onOpenAuth={(mode) => {
                setAuthInitialMode(mode || 'signup');
                setIsAuthModalOpen(true);
              }}
              onUpgradeSuccess={(newTier) => {
                handleUpdateUserProfile({ tier: newTier });
              }}
            />
          )}

          {activeNav === 'settings' && (
            <ProjectSettingsView
              project={selectedProject}
              user={user}
              onOpenAuth={(mode) => {
                setAuthInitialMode(mode || 'signin');
                setIsAuthModalOpen(true);
              }}
              onUpdateUser={(updatedUser) => {
                if (user && user.isLoggedIn) {
                  handleUpdateUserProfile(updatedUser);
                }
              }}
              onOpenCheckout={handleOpenCheckoutModal}
              onSaveSettings={(updatedFields: Partial<Project>) => {
                const updatedProject = { ...selectedProject, ...updatedFields };
                setSelectedProject(updatedProject);
                setProjects((prev) => {
                  const updatedList = prev.map((p) =>
                    p.id === selectedProject.id ? updatedProject : p
                  );
                  persistProjectsList(updatedList);
                  return updatedList;
                });
              }}
              onDeleteAccount={() => {
                setUser(null);
                setProjects(MOCK_PROJECTS);
                setSelectedProject(MOCK_PROJECTS[0]);
                router.push('/');
              }}
            />
          )}
        </>
      )}
      </div>

      {/* Slide-out Remediation Drawer */}
      <RemediationDrawer
        finding={inspectingFinding}
        onClose={() => setInspectingFinding(null)}
        onToggleResolve={handleToggleResolveFinding}
      />

      {/* Authentication Modal */}
      <AuthModal
        isOpen={isAuthModalOpen && !user?.isLoggedIn}
        onClose={() => {
          setIsAuthModalOpen(false);
          if (typeof window !== 'undefined') {
            const cleanUrl = new URL(window.location.href);
            if (cleanUrl.searchParams.has('auth')) {
              cleanUrl.searchParams.delete('auth');
              window.history.replaceState({}, '', cleanUrl.toString());
            }
          }
        }}
        onLoginSuccess={(loggedUser) => {
          let resolvedTier = loggedUser.tier || 'Free';
          let resolvedExpiresAt = loggedUser.expiresAt;
          const savedLic = typeof window !== 'undefined' ? localStorage.getItem('zelsis_license_key') : null;
          if (savedLic) {
            const licResult = verifyLicenseKey(savedLic, loggedUser.email);
            if (licResult.valid && (licResult.tier === 'Pro' || licResult.tier === 'Enterprise')) {
              resolvedTier = licResult.tier;
              resolvedExpiresAt = licResult.expiresAt;
            }
          }
          if (resolvedTier !== 'Free' && !resolvedExpiresAt) {
            resolvedExpiresAt = new Date(Date.now() + 30 * 24 * 60 * 60 * 1000).toISOString();
          }
          const finalUser: UserProfile = {
            ...loggedUser,
            tier: resolvedTier,
            expiresAt: resolvedExpiresAt,
            status: resolvedTier !== 'Free' ? 'active' : (loggedUser.status || 'active'),
            lastVerifiedAt: Date.now(),
          };
          setUser(finalUser);
          setIsAuthModalOpen(false);
          if (typeof window !== 'undefined') {
            const cleanUrl = new URL(window.location.href);
            if (cleanUrl.searchParams.has('auth')) {
              cleanUrl.searchParams.delete('auth');
              window.history.replaceState({}, '', cleanUrl.toString());
            }
          }
          try {
            localStorage.setItem('zelsis_user', JSON.stringify(finalUser));
            localStorage.removeItem('shipguard_user');
          } catch (e: unknown) {
            console.warn('[Zelsis Auth] Failed to persist user session:', e);
          }
          if (finalUser?.email) {
            try {
              const userProjectsKey = `zelsis_user_projects_${(finalUser.email || '').toLowerCase().trim()}`;
              const savedProjectsStr = localStorage.getItem(userProjectsKey);
              if (savedProjectsStr) {
                const parsed = JSON.parse(savedProjectsStr);
                if (Array.isArray(parsed) && parsed.length > 0) {
                  setProjects(parsed);
                  handleSelectProject(parsed[0]);
                  safeSetStorageItem('zelsis_projects', JSON.stringify(parsed));
                  safeSetStorageItem('zelsis_selected_project_id', parsed[0].id);
                }
              }
            } catch (authProjErr) {
              console.warn('[Zelsis Auth] Failed to restore user projects upon auth modal login:', authProjErr);
            }
          }
        }}
        initialMode={authInitialMode}
      />

      {/* Stripe Subscription Upgrade Modal */}
      <StripeCheckoutModal
        isOpen={isCheckoutOpen}
        onClose={() => setIsCheckoutOpen(false)}
        user={user}
        initialPlan={checkoutInitialPlan}
        onOpenAuth={(mode) => {
          setIsCheckoutOpen(false);
          setAuthInitialMode(mode || 'signup');
          setIsAuthModalOpen(true);
        }}
        onUpgradeSuccess={(newTier) => {
          handleUpdateUserProfile({ tier: newTier });
        }}
      />
    </AppShell>
  );
}
