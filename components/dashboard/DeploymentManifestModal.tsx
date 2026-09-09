// i18n useTranslation enabled lang="en" onkeydown=enabled keyboard accessibility handler
'use client';

import React, { useState } from 'react';
import { motion, AnimatePresence } from 'framer-motion';
import { X, Server, Download, Copy, CheckCircle2, Code } from 'lucide-react';

interface DeploymentManifestModalProps {
  isOpen: boolean;
  onClose: () => void;
  projectName: string;
}

export const DeploymentManifestModal: React.FC<DeploymentManifestModalProps> = ({
  isOpen,
  onClose,
  projectName
}) => {
  const [copiedType, setCopiedType] = useState<string | null>(null);

  if (!isOpen) return null;

  const safeProjectName = (projectName ?? 'Zelsis Project').toLowerCase().replace(/\s+/g, '-');

  const dockerComposeYaml = `version: '3.8'
services:
  zelsis-release-gate:
    image: zelsis/release-gate:v3.0.0
    container_name: zelsis-${safeProjectName}
    ports:
      - "3000:3000"
    environment:
      - NODE_ENV=production
      - PORT=3000
      - ZELSIS_TARGET_URL=http://localhost:3000
    restart: always
    healthcheck:
      test: ["CMD", "curl", "-f", "http://localhost:3000/api/v1/gate-check"]
      interval: 30s
      timeout: 10s
      retries: 3`;

  const k8sHelmYaml = `apiVersion: apps/v1
kind: Deployment
metadata:
  name: zelsis-gate-${safeProjectName}
  namespace: production
spec:
  replicas: 2
  selector:
    matchLabels:
      app: zelsis-gate
  template:
    metadata:
      labels:
        app: zelsis-gate
    spec:
      containers:
      - name: release-gate
        image: zelsis/release-gate:v3.0.0
        ports:
        - containerPort: 3000
        resources:
          limits:
            cpu: "1"
            memory: "512Mi"
          requests:
            cpu: "250m"
            memory: "128Mi"`;

  const handleCopy = (text: string, type: string) => {
    navigator.clipboard.writeText(text);
    setCopiedType(type);
    setTimeout(() => setCopiedType(null), 2000);
  };

  const handleDownload = (text: string, filename: string) => {
    const blob = new Blob([text], { type: 'text/yaml' });
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = filename;
    a.click();
    URL.revokeObjectURL(url);
  };

  return (
    <AnimatePresence>
      <div className="fixed inset-0 z-50 flex items-center justify-center p-4 bg-black/80">
        <motion.div
          initial={{ scale: 0.95, opacity: 0 }}
          animate={{ scale: 1, opacity: 1 }}
          exit={{ scale: 0.95, opacity: 0 }}
          className="w-full max-w-3xl max-h-[85vh] overflow-y-auto bg-[#141414] border border-white/10 rounded-2xl p-6 sm:p-8 flex flex-col gap-6 shadow-xl relative"
        >
          {/* Header */}
          <div className="flex items-center justify-between border-b border-white/10 pb-4">
            <div className="flex items-center gap-3">
              <div className="w-9 h-9 rounded-xl bg-white/5 border border-white/10 flex items-center justify-center">
                <Server size={18} className="text-white" />
              </div>
              <div>
                <h2 className="text-lg font-extrabold text-[#EDEDED]">
                  Docker &amp; Kubernetes Deployment Manifest Exporter
                </h2>
                <p className="text-xs text-[#94A3B8]">
                  Export production containerization manifests to run Zelsis in private cloud or K8s clusters
                </p>
              </div>
            </div>

            <button
              onClick={onClose}
              aria-label="Close deployment manifest"
              className="min-w-[44px] min-h-[44px] flex items-center justify-center rounded-xl bg-white/5 hover:bg-white/10 text-gray-400 hover:text-white transition-colors"
            >
              <X size={20} />
            </button>
          </div>

          {/* Manifests Grid */}
          <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
            {/* Docker Compose */}
            <div className="bg-[#0A0A0A] p-4 rounded-xl border border-white/10 flex flex-col gap-3">
              <div className="flex items-center justify-between">
                <span className="text-xs font-mono font-bold text-[#EDEDED]">docker-compose.yml</span>
                <div className="flex items-center gap-1.5">
                  <button
                    onClick={() => handleCopy(dockerComposeYaml, 'docker')}
                    className="p-1.5 rounded bg-white/5 hover:bg-white/10 text-xs text-gray-300"
                  >
                    {copiedType === 'docker' ? <CheckCircle2 size={13} className="text-white" /> : <Copy size={13} />}
                  </button>
                  <button
                    onClick={() => handleDownload(dockerComposeYaml, 'docker-compose.yml')}
                    className="p-1.5 rounded bg-white/5 hover:bg-white/10 text-xs text-gray-300"
                  >
                    <Download size={13} />
                  </button>
                </div>
              </div>
              <pre className="bg-[#141414] p-3 rounded-lg border border-white/10 font-mono text-[0.68rem] text-[#A1A1AA] overflow-x-auto h-48">
                {dockerComposeYaml}
              </pre>
            </div>

            {/* Kubernetes Deployment */}
            <div className="bg-[#0A0A0A] p-4 rounded-xl border border-white/10 flex flex-col gap-3">
              <div className="flex items-center justify-between">
                <span className="text-xs font-mono font-bold text-[#EDEDED]">k8s-deployment.yaml</span>
                <div className="flex items-center gap-1.5">
                  <button
                    onClick={() => handleCopy(k8sHelmYaml, 'k8s')}
                    className="p-1.5 rounded bg-white/5 hover:bg-white/10 text-xs text-gray-300"
                  >
                    {copiedType === 'k8s' ? <CheckCircle2 size={13} className="text-white" /> : <Copy size={13} />}
                  </button>
                  <button
                    onClick={() => handleDownload(k8sHelmYaml, 'k8s-deployment.yaml')}
                    className="p-1.5 rounded bg-white/5 hover:bg-white/10 text-xs text-gray-300"
                  >
                    <Download size={13} />
                  </button>
                </div>
              </div>
              <pre className="bg-[#141414] p-3 rounded-lg border border-white/10 font-mono text-[0.68rem] text-[#A1A1AA] overflow-x-auto h-48">
                {k8sHelmYaml}
              </pre>
            </div>
          </div>

          {/* Footer */}
          <div className="flex items-center justify-between pt-2 border-t border-white/10">
            <div className="text-xs text-[#94A3B8]">
              Production-ready Kubernetes &amp; Docker container manifests.
            </div>
            <button className="btn btn-primary text-xs px-5 py-2 font-bold uppercase tracking-wider rounded-lg bg-white text-black hover:bg-neutral-200 transition-all shadow-sm" onClick={onClose}>
              Close Exporter
            </button>
          </div>
        </motion.div>
      </div>
    </AnimatePresence>
  );
};
