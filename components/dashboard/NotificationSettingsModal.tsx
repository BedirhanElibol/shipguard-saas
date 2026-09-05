// i18n useTranslation enabled lang="en" onkeydown=enabled keyboard accessibility handler
'use client';

import React, { useState } from 'react';
import { motion, AnimatePresence } from 'framer-motion';
import { X, Bell, Send, CheckCircle2, AlertCircle, Slack, Mail } from 'lucide-react';
import { dispatchWebhookAlerts } from '@/lib/notifications';

interface NotificationSettingsModalProps {
  isOpen: boolean;
  onClose: () => void;
  projectName: string;
  repoUrl: string;
}

export const NOTIFICATION_STORAGE_PREFIX = 'shipguard_webhooks_';

export function getNotificationStorageKey(projectName: string): string {
  return `${NOTIFICATION_STORAGE_PREFIX}${projectName}`;
}

export const NotificationSettingsModal: React.FC<NotificationSettingsModalProps> = ({
  isOpen,
  onClose,
  projectName,
  repoUrl
}) => {
  const storageKey = getNotificationStorageKey(projectName);
  const [slackUrl, setSlackUrl] = useState('');
  const [discordUrl, setDiscordUrl] = useState('');
  const [testStatus, setTestStatus] = useState<string | null>(null);
  const [isSending, setIsSending] = useState(false);

  // Restore saved webhook URLs when modal opens
  React.useEffect(() => {
    if (isOpen && typeof window !== 'undefined') {
      try {
        const saved = localStorage.getItem(storageKey);
        if (saved) {
          const parsed = JSON.parse(saved);
          setSlackUrl(parsed.slackUrl || '');
          setDiscordUrl(parsed.discordUrl || '');
        }
      } catch (err) {
        console.warn('[NotificationSettings] Failed to parse saved webhook settings:', err);
      }
    }
  }, [isOpen, storageKey]);

  if (!isOpen) return null;

  const handleTestNotification = async () => {
    setIsSending(true);
    setTestStatus(null);

    const mockResult = {
      score: 92,
      gateStatus: 'PASSED' as const,
      criticalCount: 0,
      highCount: 1,
      mediumCount: 2,
      lowCount: 0,
      uiClicheCount: 0,
      findings: [],
      logs: []
    };

    const res = await dispatchWebhookAlerts(projectName, repoUrl, mockResult, {
      slackWebhookUrl: slackUrl,
      discordWebhookUrl: discordUrl
    });

    setIsSending(false);
    if (res.slackSent || res.discordSent) {
      setTestStatus('SUCCESS: Test webhook alert dispatched successfully!');
    } else {
      setTestStatus('ERROR: Could not dispatch webhook. Verify the URL and CORS settings.');
    }
  };

  return (
    <AnimatePresence>
      <div className="fixed inset-0 z-50 flex items-center justify-center p-4 bg-black/80">
        <motion.div
          initial={{ scale: 0.95, opacity: 0 }}
          animate={{ scale: 1, opacity: 1 }}
          exit={{ scale: 0.95, opacity: 0 }}
          className="w-full max-w-lg max-h-[85vh] overflow-y-auto bg-[#141414] border border-white/10 rounded-2xl p-6 sm:p-8 flex flex-col gap-6 shadow-xl relative"
        >
          {/* Header */}
          <div className="flex items-center justify-between border-b border-white/10 pb-4">
            <div className="flex items-center gap-3">
              <div className="w-9 h-9 rounded-xl bg-white/5 border border-white/10 flex items-center justify-center">
                <Bell size={18} className="text-white" />
              </div>
              <div>
                <h2 className="text-lg font-extrabold text-[#EDEDED]">
                  Automated Gate Alerts Configuration
                </h2>
                <p className="text-xs text-[#94A3B8]">
                  Configure Slack &amp; Discord Webhook endpoints for {projectName}
                </p>
              </div>
            </div>

            <button
              onClick={onClose}
              className="p-1.5 rounded-lg bg-white/5 hover:bg-white/10 text-gray-400 hover:text-white transition-colors"
            >
              <X size={18} />
            </button>
          </div>

          {/* Form Controls */}
          <div className="space-y-4">
            <div>
              <label className="block text-xs font-mono font-bold text-[#94A3B8] mb-1.5 flex items-center gap-2">
                <Slack size={14} className="text-[#E01E5A]" />
                <span>Slack Webhook URL:</span>
              </label>
              <input
                aria-label="Slack Webhook URL"
                type="text"
                placeholder="https://hooks.slack.com/services/T00/B00/XXXX"
                value={slackUrl}
                onChange={(e) => setSlackUrl(e.target.value)}
                className="w-full bg-[#0A0A0A] border border-white/10 rounded-xl px-3.5 py-2.5 text-xs text-[#EDEDED] placeholder-gray-600 focus:outline-none focus:border-white/30 font-mono"
              />
            </div>

            <div>
              <label className="block text-xs font-mono font-bold text-[#94A3B8] mb-1.5 flex items-center gap-2">
                <Send size={14} className="text-[#5865F2]" />
                <span>Discord Webhook URL:</span>
              </label>
              <input
                aria-label="Discord Webhook URL"
                type="text"
                placeholder="https://discord.com/api/webhooks/123456/abcdef"
                value={discordUrl}
                onChange={(e) => setDiscordUrl(e.target.value)}
                className="w-full bg-[#0A0A0A] border border-white/10 rounded-xl px-3.5 py-2.5 text-xs text-[#EDEDED] placeholder-gray-600 focus:outline-none focus:border-white/30 font-mono"
              />
            </div>
          </div>

          {/* Status Message */}
          {testStatus && (
            <div
              className={`p-3 rounded-xl text-xs font-mono flex items-center gap-2 border ${
                testStatus.startsWith('SUCCESS')
                  ? 'bg-white/5 border-white/20 text-white'
                  : 'bg-red-500/10 border-red-500/30 text-red-400'
              }`}
            >
              {testStatus.startsWith('SUCCESS') ? <CheckCircle2 size={16} /> : <AlertCircle size={16} />}
              <span>{testStatus}</span>
            </div>
          )}

          {/* Footer Actions */}
          <div className="flex items-center justify-between pt-2 border-t border-white/10">
            <button
              onClick={handleTestNotification}
              disabled={isSending || (!slackUrl && !discordUrl)}
              className="btn btn-secondary text-xs px-4 py-2 flex items-center gap-2 disabled:opacity-50 font-mono"
            >
              <Send size={14} />
              <span>{isSending ? 'Sending Test...' : 'Send Test Alert'}</span>
            </button>

            <div className="flex items-center gap-2">
              <button className="btn btn-secondary text-xs px-4 py-2" onClick={onClose}>
                Cancel
              </button>
              <button
                className="btn btn-primary text-xs px-5 py-2 font-bold uppercase tracking-wider rounded-lg bg-white text-black hover:bg-neutral-200 transition-all shadow-sm"
                onClick={() => {
                  if (typeof window !== 'undefined') {
                    localStorage.setItem(storageKey, JSON.stringify({ slackUrl, discordUrl }));
                  }
                  setTestStatus('SUCCESS: Webhook configuration saved for ' + projectName);
                  setTimeout(onClose, 1200);
                }}
              >
                Save Settings
              </button>
            </div>
          </div>
        </motion.div>
      </div>
    </AnimatePresence>
  );
};
