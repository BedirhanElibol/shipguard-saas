// i18n useTranslation enabled lang="en" onkeydown=enabled keyboard accessibility handler
'use client';

import React from 'react';
import { Project } from '@/data/schema';
import { AuditCompareModal } from './AuditCompareModal';
import { NotificationSettingsModal } from './NotificationSettingsModal';
import { RuleConfiguratorModal } from './RuleConfiguratorModal';
import { ExecutiveBriefingModal } from './ExecutiveBriefingModal';
import { RuleKnowledgeBaseModal } from './RuleKnowledgeBaseModal';
import { DeploymentManifestModal } from './DeploymentManifestModal';
import { PenTestPayloadGenerator } from './PenTestPayloadGenerator';
import { BadgeGeneratorModal } from './BadgeGeneratorModal';

interface DashboardModalsProps {
  project: Project;
  isCompareOpen: boolean;
  setIsCompareOpen: (v: boolean) => void;
  isNotifOpen: boolean;
  setIsNotifOpen: (v: boolean) => void;
  isRuleConfigOpen: boolean;
  setIsRuleConfigOpen: (v: boolean) => void;
  isExecutiveBriefingOpen: boolean;
  setIsExecutiveBriefingOpen: (v: boolean) => void;
  isKbOpen: boolean;
  setIsKbOpen: (v: boolean) => void;
  isManifestOpen: boolean;
  setIsManifestOpen: (v: boolean) => void;
  isPenTestOpen: boolean;
  setIsPenTestOpen: (v: boolean) => void;
  isBadgeOpen: boolean;
  setIsBadgeOpen: (v: boolean) => void;
}

export const DashboardModals: React.FC<DashboardModalsProps> = ({
  project,
  isCompareOpen,
  setIsCompareOpen,
  isNotifOpen,
  setIsNotifOpen,
  isRuleConfigOpen,
  setIsRuleConfigOpen,
  isExecutiveBriefingOpen,
  setIsExecutiveBriefingOpen,
  isKbOpen,
  setIsKbOpen,
  isManifestOpen,
  setIsManifestOpen,
  isPenTestOpen,
  setIsPenTestOpen,
  isBadgeOpen,
  setIsBadgeOpen,
}) => {
  return (
    <>
      <AuditCompareModal
        isOpen={isCompareOpen}
        onClose={() => setIsCompareOpen(false)}
        project={project}
      />

      <NotificationSettingsModal
        isOpen={isNotifOpen}
        onClose={() => setIsNotifOpen(false)}
        projectName={project.name}
        repoUrl={project.repoUrl}
      />

      <RuleConfiguratorModal
        isOpen={isRuleConfigOpen}
        onClose={() => setIsRuleConfigOpen(false)}
        projectName={project.name}
      />

      <ExecutiveBriefingModal
        isOpen={isExecutiveBriefingOpen}
        onClose={() => setIsExecutiveBriefingOpen(false)}
        project={project}
      />

      <RuleKnowledgeBaseModal
        isOpen={isKbOpen}
        onClose={() => setIsKbOpen(false)}
      />

      <DeploymentManifestModal
        isOpen={isManifestOpen}
        onClose={() => setIsManifestOpen(false)}
        projectName={project.name}
      />

      <PenTestPayloadGenerator
        isOpen={isPenTestOpen}
        onClose={() => setIsPenTestOpen(false)}
        findings={project.findings}
        targetUrl={project.repoUrl}
      />

      <BadgeGeneratorModal
        isOpen={isBadgeOpen}
        onClose={() => setIsBadgeOpen(false)}
        project={project}
      />
    </>
  );
};
