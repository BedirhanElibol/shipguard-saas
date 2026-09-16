'use client';

import React from 'react';
import { Finding } from '@/data/schema';
import { FindingDetailModal } from './FindingDetailModal';

export interface RemediationDrawerProps {
  finding: Finding | null;
  onClose: () => void;
  onToggleResolve: (id: string) => void;
}

export const RemediationDrawer: React.FC<RemediationDrawerProps> = ({
  finding,
  onClose,
  onToggleResolve,
}) => {
  return (
    <FindingDetailModal
      isOpen={finding !== null}
      finding={finding}
      onClose={onClose}
      onToggleResolve={onToggleResolve}
    />
  );
};
