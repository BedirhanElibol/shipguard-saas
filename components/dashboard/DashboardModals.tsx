'use client';

import React from 'react';
import dynamic from 'next/dynamic';
import { Project } from '@/data/schema';

const AuditCompareModal = dynamic(
  () => import('./AuditCompareModal').then((mod) => mod.AuditCompareModal),
  { ssr: false }
);

const NotificationSettingsModal = dynamic(
  () => import('./NotificationSettingsModal').then((mod) => mod.NotificationSettingsModal),
  { ssr: false }
);

const RuleConfiguratorModal = dynamic(
  () => import('./RuleConfiguratorModal').then((mod) => mod.RuleConfiguratorModal),
  { ssr: false }
);

const ExecutiveBriefingModal = dynamic(
  () => import('./ExecutiveBriefingModal').then((mod) => mod.ExecutiveBriefingModal),
  { ssr: false }
);

const RuleKnowledgeBaseModal = dynamic(
  () => import('./RuleKnowledgeBaseModal').then((mod) => mod.RuleKnowledgeBaseModal),
  { ssr: false }
);

const DeploymentManifestModal = dynamic(
  () => import('./DeploymentManifestModal').then((mod) => mod.DeploymentManifestModal),
  { ssr: false }
);

const PenTestPayloadGenerator = dynamic(
  () => import('./PenTestPayloadGenerator').then((mod) => mod.PenTestPayloadGenerator),
  { ssr: false }
);

const BadgeGeneratorModal = dynamic(
  () => import('./BadgeGeneratorModal').then((mod) => mod.BadgeGeneratorModal),
  { ssr: false }
);

const CiCdIntegrationModal = dynamic(
  () => import('./CiCdIntegrationModal').then((mod) => mod.CiCdIntegrationModal),
  { ssr: false }
);

export type ActiveModalType =
  | 'compare'
  | 'notif'
  | 'rules'
  | 'briefing'
  | 'kb'
  | 'manifest'
  | 'pentest'
  | 'badge'
  | 'cicd'
  | null;

export interface DashboardModalsProps {
  project: Project;
  activeModal: ActiveModalType;
  onClose: () => void;
}

export const DashboardModals: React.FC<DashboardModalsProps> = ({
  project,
  activeModal,
  onClose,
}) => {
  if (!activeModal) return null;

  return (
    <>
      <AuditCompareModal
        isOpen={activeModal === 'compare'}
        onClose={onClose}
        project={project}
      />

      <NotificationSettingsModal
        isOpen={activeModal === 'notif'}
        onClose={onClose}
        projectName={project.name}
        repoUrl={project.repoUrl}
      />

      <RuleConfiguratorModal
        isOpen={activeModal === 'rules'}
        onClose={onClose}
        projectName={project.name}
      />

      <ExecutiveBriefingModal
        isOpen={activeModal === 'briefing'}
        onClose={onClose}
        project={project}
      />

      <RuleKnowledgeBaseModal
        isOpen={activeModal === 'kb'}
        onClose={onClose}
      />

      <DeploymentManifestModal
        isOpen={activeModal === 'manifest'}
        onClose={onClose}
        projectName={project.name}
      />

      <PenTestPayloadGenerator
        isOpen={activeModal === 'pentest'}
        onClose={onClose}
        findings={project.findings}
        targetUrl={project.repoUrl}
      />

      <BadgeGeneratorModal
        isOpen={activeModal === 'badge'}
        onClose={onClose}
        project={project}
      />

      <CiCdIntegrationModal
        isOpen={activeModal === 'cicd'}
        onClose={onClose}
        project={project}
      />
    </>
  );
};
