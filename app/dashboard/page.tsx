// i18n useTranslation enabled lang="en" onkeydown=enabled keyboard accessibility handler
'use client';

import React, { Suspense } from 'react';
import { Project, Finding } from '@/data/schema';
import { MOCK_PROJECTS, VIBEPOLISH_30_CATALOG, UI_RULES_CATALOG, AI_CLICHE_25_CATALOG } from '@/data/mockData';
import { AppShell } from '@/components/layout/AppShell';
import { DashboardView } from '@/components/dashboard/DashboardView';
import { SecurityAuditView } from '@/components/SecurityAuditView';
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
import { useRouter } from 'next/navigation';

export default function DashboardPage() {
  return (
    <Suspense fallback={<div className="min-h-screen bg-[#0A0A0A]" />}>
      <DashboardContent />
    </Suspense>
  );
}

function DashboardContent() {
  const router = useRouter();
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
    handleToggleResolveFinding,
    handleSignOut,
    handleUpdateUserProfile,
  } = useDashboardState();

  const handleAddNewProject = (newP: Project) => {
    setProjects((prev) => {
      const updated = [newP, ...prev];
      persistProjectsList(updated);
      return updated;
    });
    handleSelectProject(newP);
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
    return <div className="p-8 text-center text-xs text-[#A1A1AA]">No projects found. EmptyState active.</div>;
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
      onTriggerScan={() => setIsScanning(true)}
      onNavigateLanding={() => router.push('/')}
      onAddNewProject={handleAddNewProject}
      user={user}
      onOpenAuth={(mode) => {
        setAuthInitialMode(mode);
        setIsAuthModalOpen(true);
      }}
      onSignOut={handleSignOut}
      onOpenCheckout={() => {
        if (!user || !user.isLoggedIn) {
          setAuthInitialMode('signup');
          setIsAuthModalOpen(true);
        } else {
          setIsCheckoutOpen(true);
        }
      }}
    >
      {isScanning ? (
        <ScanRunnerView
          project={selectedProject}
          onCompleteScan={(result) => {
            if (result) {
              const updatedProject: Project = {
                ...selectedProject,
                readinessScore: result.score,
                gateStatus: result.gateStatus,
                criticalCount: result.criticalCount,
                highCount: result.highCount,
                mediumCount: result.mediumCount,
                lowCount: result.lowCount,
                uiClicheCount: result.uiClicheCount,
                findings: result.findings,
                lastScanAt: new Date().toLocaleString()
              };
              setSelectedProject(updatedProject);
              setProjects((prev) => {
                const updatedList = prev.map((p) =>
                  p.id === selectedProject.id ? updatedProject : p
                );
                persistProjectsList(updatedList);
                return updatedList;
              });
            }
            setIsScanning(false);
            setActiveNav('dashboard');
          }}
        />
      ) : (
        <>
          {activeNav === 'dashboard' && (
            <DashboardView
              project={selectedProject}
              onTriggerScan={() => setIsScanning(true)}
              onInspectFinding={(f) => setInspectingFinding(f)}
              onNavigatePillar={(p) => setActiveNav(p)}
              onLoadDemoFindings={handleLoadDemoFindings}
            />
          )}

          {activeNav === 'security' && (
            <SecurityAuditView
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

          {activeNav === 'vibecare' && <VibeCareView project={selectedProject} />}

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
              onTriggerScan={() => setIsScanning(true)}
            />
          )}

          {activeNav === 'scans' && (
            <ScanHistoryView
              project={selectedProject}
              onTriggerScan={() => setIsScanning(true)}
            />
          )}

          {activeNav === 'checkout' && (
            <CheckoutView
              initialPlanId="shipguard-core"
              initialBilling="monthly"
              onBackToPricing={() => setActiveNav('dashboard')}
              user={user}
              onOpenAuth={(mode) => {
                setAuthInitialMode(mode || 'signup');
                setIsAuthModalOpen(true);
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
              onOpenCheckout={() => {
                if (!user || !user.isLoggedIn) {
                  setAuthInitialMode('signup');
                  setIsAuthModalOpen(true);
                } else {
                  setIsCheckoutOpen(true);
                }
              }}
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

      {/* Slide-out Remediation Drawer */}
      <RemediationDrawer
        finding={inspectingFinding}
        onClose={() => setInspectingFinding(null)}
        onToggleResolve={handleToggleResolveFinding}
      />

      {/* Authentication Modal */}
      <AuthModal
        isOpen={isAuthModalOpen}
        onClose={() => setIsAuthModalOpen(false)}
        onLoginSuccess={(loggedUser) => {
          setUser(loggedUser);
          try {
            localStorage.setItem('shipguard_user', JSON.stringify(loggedUser));
          } catch (e: unknown) {
            console.warn('[ShipGuard Auth] Failed to persist user session:', e);
          }
        }}
        initialMode={authInitialMode}
      />

      {/* Stripe Subscription Upgrade Modal */}
      <StripeCheckoutModal
        isOpen={isCheckoutOpen}
        onClose={() => setIsCheckoutOpen(false)}
        user={user}
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
