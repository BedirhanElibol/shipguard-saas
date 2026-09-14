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

  React.useEffect(() => {
    if (!isOpen) return;
    const handleKeyDown = (e: KeyboardEvent) => {
      if (e.key === 'Escape') onClose();
    };
    window.addEventListener('keydown', handleKeyDown);
    return () => window.removeEventListener('keydown', handleKeyDown);
  }, [isOpen, onClose]);

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

  const githubActionYaml = `name: ShipGuard Release Gate

on:
  push:
    branches: [ main, master ]
  pull_request:
    branches: [ main, master ]

jobs:
  release-gate:
    name: Automated Release Gate Check
    runs-on: ubuntu-latest
    steps:
      - name: Checkout Repository
        uses: actions/checkout@v4

      - name: Run ShipGuard Gate Check
        run: |
          RESPONSE=$(curl -s -X POST "https://shipguard-saas.vercel.app/api/v1/gate-check?failOnBlock=true" \\
            -H "Content-Type: application/json" \\
            -d '{"repoUrl": "\${{ github.server_url }}/\${{ github.repository }}"}')
          echo "Audit Response: $RESPONSE"
          STATUS=$(echo "$RESPONSE" | grep -o '"gateStatus":"[^"]*' | cut -d'"' -f4)
          SCORE=$(echo "$RESPONSE" | grep -o '"readinessScore":[0-9]*' | cut -d':' -f2)
          echo "ShipGuard Status: $STATUS (Score: $SCORE/100)"
          if [ "$STATUS" = "FAILED" ]; then
            echo "❌ Release BLOCKED by ShipGuard Quality Gate."
            exit 1
          fi
          echo "✅ Release PASSED ShipGuard Quality Gate."`;

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
      <div
        onClick={(e) => { if (e.target === e.currentTarget) onClose(); }}
        className="fixed inset-0 z-50 flex items-center justify-center p-4 bg-black/80"
      >
        <motion.div
          initial={{ scale: 0.95, opacity: 0 }}
          animate={{ scale: 1, opacity: 1 }}
          exit={{ scale: 0.95, opacity: 0 }}
          className="w-full max-w-4xl max-h-[90vh] overflow-y-auto bg-[#141414] border border-white/10 rounded-2xl p-6 sm:p-8 flex flex-col gap-6 shadow-xl relative"
        >
          {/* Header */}
          <div className="flex items-center justify-between border-b border-white/10 pb-4">
            <div className="flex items-center gap-3">
              <div className="w-9 h-9 rounded-xl bg-white/5 border border-white/10 flex items-center justify-center">
                <Server size={18} className="text-white" />
              </div>
              <div>
                <h2 className="text-lg font-extrabold text-[#EDEDED]">
                  CI/CD &amp; Deployment Manifest Exporter
                </h2>
                <p className="text-xs text-[#94A3B8]">
                  Export automated GitHub Actions workflows, Docker containers, and Kubernetes manifests
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
          <div className="grid grid-cols-1 md:grid-cols-3 gap-4">
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
                    title="Copy Kubernetes manifest"
                  >
                    {copiedType === 'k8s' ? <CheckCircle2 size={13} className="text-white" /> : <Copy size={13} />}
                  </button>
                  <button
                    onClick={() => handleDownload(k8sHelmYaml, 'k8s-deployment.yaml')}
                    className="p-1.5 rounded bg-white/5 hover:bg-white/10 text-xs text-gray-300"
                    title="Download k8s-deployment.yaml"
                  >
                    <Download size={13} />
                  </button>
                </div>
              </div>
              <pre className="bg-[#141414] p-3 rounded-lg border border-white/10 font-mono text-[0.68rem] text-[#A1A1AA] overflow-x-auto h-48">
                {k8sHelmYaml}
              </pre>
            </div>

            {/* GitHub Actions CI/CD Workflow */}
            <div className="bg-[#0A0A0A] p-4 rounded-xl border border-white/10 flex flex-col gap-3">
              <div className="flex items-center justify-between">
                <span className="text-xs font-mono font-bold text-[#EDEDED]">shipguard-gate.yml</span>
                <div className="flex items-center gap-1.5">
                  <button
                    onClick={() => handleCopy(githubActionYaml, 'github')}
                    className="p-1.5 rounded bg-white/5 hover:bg-white/10 text-xs text-gray-300"
                    title="Copy GitHub Action workflow"
                  >
                    {copiedType === 'github' ? <CheckCircle2 size={13} className="text-white" /> : <Copy size={13} />}
                  </button>
                  <button
                    onClick={() => handleDownload(githubActionYaml, 'shipguard-gate.yml')}
                    className="p-1.5 rounded bg-white/5 hover:bg-white/10 text-xs text-gray-300"
                    title="Download shipguard-gate.yml"
                  >
                    <Download size={13} />
                  </button>
                </div>
              </div>
              <pre className="bg-[#141414] p-3 rounded-lg border border-white/10 font-mono text-[0.68rem] text-[#A1A1AA] overflow-x-auto h-48">
                {githubActionYaml}
              </pre>
            </div>
          </div>

          {/* Footer */}
          <div className="flex items-center justify-between pt-2 border-t border-white/10">
            <div className="text-xs text-[#94A3B8]">
              Automated GitHub Actions CI/CD workflows, Kubernetes &amp; Docker container manifests.
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
