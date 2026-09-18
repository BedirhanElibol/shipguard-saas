'use client';

import React from 'react';
import { Finding, PlanUsageQuota } from '@/data/schema';
import { UserProfile } from '@/components/auth/AuthModal';
import { FindingDetailModal } from './FindingDetailModal';

export interface RemediationDrawerProps {
  finding: Finding | null;
  onClose: () => void;
  onToggleResolve: (id: string) => void;
  user?: UserProfile | null;
  quota?: PlanUsageQuota;
  onRecordAiPrompt?: () => void;
  onOpenCheckout?: (plan?: 'Pro' | 'Enterprise') => void;
}

export const RemediationDrawer: React.FC<RemediationDrawerProps> = ({
  finding,
  onClose,
  onToggleResolve,
  user,
  quota,
  onRecordAiPrompt,
  onOpenCheckout,
}) => {
  return (
    <FindingDetailModal
      isOpen={finding !== null}
      finding={finding}
      onClose={onClose}
      onToggleResolve={onToggleResolve}
      user={user}
      quota={quota}
      onRecordAiPrompt={onRecordAiPrompt}
      onOpenCheckout={onOpenCheckout}
    />
  );
};
