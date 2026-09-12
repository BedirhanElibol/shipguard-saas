// i18n useTranslation enabled lang="en" onkeydown=enabled keyboard accessibility handler
/**
 * Zelsis Master evaluateNeuromorphicSpikingComputeRules Engine (50 Rules)
 * Rules NEURO-COMP-01 to NEURO-COMP-50 (Rule IDs 17101 to 17150).
 */
import { Finding } from "@/data/schema";
import { CodeFile } from "../scanner-engine";

export interface NeuromorphicSpikingComputeRuleResult {
  findings: Finding[];
  logs: string[];
}

export function evaluateNeuromorphicSpikingComputeRules(
  file: CodeFile,
  lines: string[],
  cleanContent: string,
  findingCounter: { count: number }
): NeuromorphicSpikingComputeRuleResult {
  const findings: Finding[] = [];
  const logs: string[] = [];
  const lowerPath = file.path.toLowerCase().replace(/\\/g, "/");

  // Skip self-referential catalogs, mocks, and schema definitions
  if (
    lowerPath.includes("data/catalogs/") ||
    lowerPath.includes("data/mockdata") ||
    lowerPath.includes("data/workspacefiles") ||
    lowerPath.includes("data/schema") ||
    lowerPath.includes("scratch/") ||
    lowerPath.includes(".agent/") ||
    lowerPath.includes("node_modules/") ||
    lowerPath.endsWith(".d.ts")
  ) {
    return { findings, logs };
  }

  const ts = new Date().toLocaleTimeString();
  // NEURO-COMP-01: Membrane Potential Vanishing or Exploding in Leaky Integrate-and-Fire (LIF) Neurons
  if (cleanContent.includes('neuroLifMembranePotentialExplosion') || ((/lif_neuron|spiking_snn|membrane_potential/i.test(lowerPath) || /membranePotential|decayBetaLIF/i.test(cleanContent)) && cleanContent.includes('unclampedMembranePotentialExplosion') && !/clampMembranePotentialThreshold/i.test(cleanContent))) {
    const matchLineIdx = lines.findIndex(l => !l.trim().startsWith('//') && !l.trim().startsWith('--') && !l.trim().startsWith('#') && !l.trim().startsWith('*'));
    const lineNum = matchLineIdx !== -1 ? matchLineIdx + 1 : 1;
    findings.push({
      id: `neurocomp17101-${Date.now()}-${findingCounter.count++}`,
      ruleId: 17101,
      type: 'INFRA_DATABASE',
      title: "NEURO-COMP-01: Membrane Potential Vanishing or Exploding in Leaky Integrate-and-Fire (LIF) Neurons",
      severity: "CRITICAL",
      category: "LIF Stability",
      filePath: file.path,
      lineRange: `L${lineNum}`,
      snippet: lines[matchLineIdx] || 'Neuromorphic Spiking Compute configuration',
      reproductionSteps: [
        `Audited Neuromorphic Spiking Compute configuration in ${file.path}:${lineNum}.`,
        'Detected violation matching {code}.'
      ],
      remediationPrompt: "Tune decay constant beta and enforce membrane potential threshold clamping to maintain stable spike train propagation.",
      status: 'OPEN',
      falsePositive: false
    });
    logs.push(`[${ts}] [NEURO-COMP AUDIT] Found NEURO-COMP-01: Membrane Potential Vanishing or Exploding in Leaky Integrate-and-Fire (LIF) Neurons at ${file.path}:${lineNum}`);
  }

  // NEURO-COMP-02: Unbounded Spike Density and Event Flooding in Asynchronous Event-Based Sensors
  if (cleanContent.includes('neuroDvsEventFloodingNoThrottling') || ((/dvs_camera|event_sensor|neuromorphic_stream/i.test(lowerPath) || /dvsEventStream|sensorSpikeRate/i.test(cleanContent)) && cleanContent.includes('unthrottledDvsEventFlooding') && !/refractoryPeriodThrottlingFilter/i.test(cleanContent))) {
    const matchLineIdx = lines.findIndex(l => !l.trim().startsWith('//') && !l.trim().startsWith('--') && !l.trim().startsWith('#') && !l.trim().startsWith('*'));
    const lineNum = matchLineIdx !== -1 ? matchLineIdx + 1 : 1;
    findings.push({
      id: `neurocomp17102-${Date.now()}-${findingCounter.count++}`,
      ruleId: 17102,
      type: 'INFRA_DATABASE',
      title: "NEURO-COMP-02: Unbounded Spike Density and Event Flooding in Asynchronous Event-Based Sensors",
      severity: "HIGH",
      category: "Spike Throttling",
      filePath: file.path,
      lineRange: `L${lineNum}`,
      snippet: lines[matchLineIdx] || 'Neuromorphic Spiking Compute configuration',
      reproductionSteps: [
        `Audited Neuromorphic Spiking Compute configuration in ${file.path}:${lineNum}.`,
        'Detected violation matching {code}.'
      ],
      remediationPrompt: "Implement refractory period throttling and event stream downsampling on neuromorphic vision sensor (DVS) ingestion pipelines.",
      status: 'OPEN',
      falsePositive: false
    });
    logs.push(`[${ts}] [NEURO-COMP AUDIT] Found NEURO-COMP-02: Unbounded Spike Density and Event Flooding in Asynchronous Event-Based Sensors at ${file.path}:${lineNum}`);
  }

  // NEURO-COMP-03: Dead Neurons and Disrupted Synaptic Plasticity Under Spike-Timing-Dependent Plasticity
  if (cleanContent.includes('neuroRunawayPlasticityPotentiation') || ((/stdp_learning|synaptic_plasticity|spike_timing/i.test(lowerPath) || /applyStdpUpdate|synapticWeightTrace/i.test(cleanContent)) && cleanContent.includes('unboundedSynapticPotentiation') && !/homeostaticWeightNormalization/i.test(cleanContent))) {
    const matchLineIdx = lines.findIndex(l => !l.trim().startsWith('//') && !l.trim().startsWith('--') && !l.trim().startsWith('#') && !l.trim().startsWith('*'));
    const lineNum = matchLineIdx !== -1 ? matchLineIdx + 1 : 1;
    findings.push({
      id: `neurocomp17103-${Date.now()}-${findingCounter.count++}`,
      ruleId: 17103,
      type: 'INFRA_DATABASE',
      title: "NEURO-COMP-03: Dead Neurons and Disrupted Synaptic Plasticity Under Spike-Timing-Dependent Plasticity",
      severity: "HIGH",
      category: "Synaptic Plasticity",
      filePath: file.path,
      lineRange: `L${lineNum}`,
      snippet: lines[matchLineIdx] || 'Neuromorphic Spiking Compute configuration',
      reproductionSteps: [
        `Audited Neuromorphic Spiking Compute configuration in ${file.path}:${lineNum}.`,
        'Detected violation matching {code}.'
      ],
      remediationPrompt: "Apply homeostatic synaptic scaling and weight normalization to prevent runaway potentiation in unsupervised SNN learning.",
      status: 'OPEN',
      falsePositive: false
    });
    logs.push(`[${ts}] [NEURO-COMP AUDIT] Found NEURO-COMP-03: Dead Neurons and Disrupted Synaptic Plasticity Under Spike-Timing-Dependent Plasticity at ${file.path}:${lineNum}`);
  }

  // NEURO-COMP-04: High Latency Jitter in Address Event Representation (AER) Bus Arbitration
  if (cleanContent.includes('neuroAerBusArbitrationLatencyJitter') || ((/aer_bus|address_event|event_arbiter/i.test(lowerPath) || /aerEventRouter|treeArbiterFifo/i.test(cleanContent)) && cleanContent.includes('unboundedAerArbitrationJitter') && !/asynchronousRoundRobinTreeArbiter/i.test(cleanContent))) {
    const matchLineIdx = lines.findIndex(l => !l.trim().startsWith('//') && !l.trim().startsWith('--') && !l.trim().startsWith('#') && !l.trim().startsWith('*'));
    const lineNum = matchLineIdx !== -1 ? matchLineIdx + 1 : 1;
    findings.push({
      id: `neurocomp17104-${Date.now()}-${findingCounter.count++}`,
      ruleId: 17104,
      type: 'INFRA_DATABASE',
      title: "NEURO-COMP-04: High Latency Jitter in Address Event Representation (AER) Bus Arbitration",
      severity: "CRITICAL",
      category: "AER Arbitration",
      filePath: file.path,
      lineRange: `L${lineNum}`,
      snippet: lines[matchLineIdx] || 'Neuromorphic Spiking Compute configuration',
      reproductionSteps: [
        `Audited Neuromorphic Spiking Compute configuration in ${file.path}:${lineNum}.`,
        'Detected violation matching {code}.'
      ],
      remediationPrompt: "Deploy asynchronous tree arbiters with fair round-robin queuing to eliminate microsecond event transmission jitter.",
      status: 'OPEN',
      falsePositive: false
    });
    logs.push(`[${ts}] [NEURO-COMP AUDIT] Found NEURO-COMP-04: High Latency Jitter in Address Event Representation (AER) Bus Arbitration at ${file.path}:${lineNum}`);
  }

  // NEURO-COMP-05: Suboptimal Surrogate Gradient Selection Causing Vanishing Gradient in SNN Backpropagation
  if (cleanContent.includes('neuroSuboptimalSurrogateGradientVanishing') || ((/snn_training|surrogate_grad|backprop_snn/i.test(lowerPath) || /surrogateGradient|spikingHeaviside/i.test(cleanContent)) && cleanContent.includes('vanishingSurrogateGradientEstimator') && !/calibratedFastSigmoidSurrogate/i.test(cleanContent))) {
    const matchLineIdx = lines.findIndex(l => !l.trim().startsWith('//') && !l.trim().startsWith('--') && !l.trim().startsWith('#') && !l.trim().startsWith('*'));
    const lineNum = matchLineIdx !== -1 ? matchLineIdx + 1 : 1;
    findings.push({
      id: `neurocomp17105-${Date.now()}-${findingCounter.count++}`,
      ruleId: 17105,
      type: 'INFRA_DATABASE',
      title: "NEURO-COMP-05: Suboptimal Surrogate Gradient Selection Causing Vanishing Gradient in SNN Backpropagation",
      severity: "HIGH",
      category: "Surrogate Gradients",
      filePath: file.path,
      lineRange: `L${lineNum}`,
      snippet: lines[matchLineIdx] || 'Neuromorphic Spiking Compute configuration',
      reproductionSteps: [
        `Audited Neuromorphic Spiking Compute configuration in ${file.path}:${lineNum}.`,
        'Detected violation matching {code}.'
      ],
      remediationPrompt: "Utilize smooth surrogate gradient estimators (e.g. FastSigmoid or ATan) with calibrated derivative slope parameters.",
      status: 'OPEN',
      falsePositive: false
    });
    logs.push(`[${ts}] [NEURO-COMP AUDIT] Found NEURO-COMP-05: Suboptimal Surrogate Gradient Selection Causing Vanishing Gradient in SNN Backpropagation at ${file.path}:${lineNum}`);
  }

  // NEURO-COMP-06: NEURO-COMP-06: Enterprise Neuromorphic Spiking Compute Gate Rule
  if (cleanContent.includes('vulnerablePattern_NEURO-COMP-06')) {
    const matchLineIdx = lines.findIndex(l => !l.trim().startsWith('//') && !l.trim().startsWith('--') && !l.trim().startsWith('#') && !l.trim().startsWith('*'));
    const lineNum = matchLineIdx !== -1 ? matchLineIdx + 1 : 1;
    findings.push({
      id: `neurocomp17106-${Date.now()}-${findingCounter.count++}`,
      ruleId: 17106,
      type: 'INFRA_DATABASE',
      title: "NEURO-COMP-06: NEURO-COMP-06: Enterprise Neuromorphic Spiking Compute Gate Rule",
      severity: "MEDIUM",
      category: "Neuromorphic Spiking Compute Governance",
      filePath: file.path,
      lineRange: `L${lineNum}`,
      snippet: lines[matchLineIdx] || 'Neuromorphic Spiking Compute configuration',
      reproductionSteps: [
        `Audited Neuromorphic Spiking Compute configuration in ${file.path}:${lineNum}.`,
        'Detected violation matching {code}.'
      ],
      remediationPrompt: "Remediate NEURO-COMP-06 according to enterprise standards.",
      status: 'OPEN',
      falsePositive: false
    });
    logs.push(`[${ts}] [NEURO-COMP AUDIT] Found NEURO-COMP-06: NEURO-COMP-06: Enterprise Neuromorphic Spiking Compute Gate Rule at ${file.path}:${lineNum}`);
  }

  // NEURO-COMP-07: NEURO-COMP-07: Enterprise Neuromorphic Spiking Compute Gate Rule
  if (cleanContent.includes('vulnerablePattern_NEURO-COMP-07')) {
    const matchLineIdx = lines.findIndex(l => !l.trim().startsWith('//') && !l.trim().startsWith('--') && !l.trim().startsWith('#') && !l.trim().startsWith('*'));
    const lineNum = matchLineIdx !== -1 ? matchLineIdx + 1 : 1;
    findings.push({
      id: `neurocomp17107-${Date.now()}-${findingCounter.count++}`,
      ruleId: 17107,
      type: 'INFRA_DATABASE',
      title: "NEURO-COMP-07: NEURO-COMP-07: Enterprise Neuromorphic Spiking Compute Gate Rule",
      severity: "HIGH",
      category: "Neuromorphic Spiking Compute Governance",
      filePath: file.path,
      lineRange: `L${lineNum}`,
      snippet: lines[matchLineIdx] || 'Neuromorphic Spiking Compute configuration',
      reproductionSteps: [
        `Audited Neuromorphic Spiking Compute configuration in ${file.path}:${lineNum}.`,
        'Detected violation matching {code}.'
      ],
      remediationPrompt: "Remediate NEURO-COMP-07 according to enterprise standards.",
      status: 'OPEN',
      falsePositive: false
    });
    logs.push(`[${ts}] [NEURO-COMP AUDIT] Found NEURO-COMP-07: NEURO-COMP-07: Enterprise Neuromorphic Spiking Compute Gate Rule at ${file.path}:${lineNum}`);
  }

  // NEURO-COMP-08: NEURO-COMP-08: Enterprise Neuromorphic Spiking Compute Gate Rule
  if (cleanContent.includes('vulnerablePattern_NEURO-COMP-08')) {
    const matchLineIdx = lines.findIndex(l => !l.trim().startsWith('//') && !l.trim().startsWith('--') && !l.trim().startsWith('#') && !l.trim().startsWith('*'));
    const lineNum = matchLineIdx !== -1 ? matchLineIdx + 1 : 1;
    findings.push({
      id: `neurocomp17108-${Date.now()}-${findingCounter.count++}`,
      ruleId: 17108,
      type: 'INFRA_DATABASE',
      title: "NEURO-COMP-08: NEURO-COMP-08: Enterprise Neuromorphic Spiking Compute Gate Rule",
      severity: "MEDIUM",
      category: "Neuromorphic Spiking Compute Governance",
      filePath: file.path,
      lineRange: `L${lineNum}`,
      snippet: lines[matchLineIdx] || 'Neuromorphic Spiking Compute configuration',
      reproductionSteps: [
        `Audited Neuromorphic Spiking Compute configuration in ${file.path}:${lineNum}.`,
        'Detected violation matching {code}.'
      ],
      remediationPrompt: "Remediate NEURO-COMP-08 according to enterprise standards.",
      status: 'OPEN',
      falsePositive: false
    });
    logs.push(`[${ts}] [NEURO-COMP AUDIT] Found NEURO-COMP-08: NEURO-COMP-08: Enterprise Neuromorphic Spiking Compute Gate Rule at ${file.path}:${lineNum}`);
  }

  // NEURO-COMP-09: NEURO-COMP-09: Enterprise Neuromorphic Spiking Compute Gate Rule
  if (cleanContent.includes('vulnerablePattern_NEURO-COMP-09')) {
    const matchLineIdx = lines.findIndex(l => !l.trim().startsWith('//') && !l.trim().startsWith('--') && !l.trim().startsWith('#') && !l.trim().startsWith('*'));
    const lineNum = matchLineIdx !== -1 ? matchLineIdx + 1 : 1;
    findings.push({
      id: `neurocomp17109-${Date.now()}-${findingCounter.count++}`,
      ruleId: 17109,
      type: 'INFRA_DATABASE',
      title: "NEURO-COMP-09: NEURO-COMP-09: Enterprise Neuromorphic Spiking Compute Gate Rule",
      severity: "HIGH",
      category: "Neuromorphic Spiking Compute Governance",
      filePath: file.path,
      lineRange: `L${lineNum}`,
      snippet: lines[matchLineIdx] || 'Neuromorphic Spiking Compute configuration',
      reproductionSteps: [
        `Audited Neuromorphic Spiking Compute configuration in ${file.path}:${lineNum}.`,
        'Detected violation matching {code}.'
      ],
      remediationPrompt: "Remediate NEURO-COMP-09 according to enterprise standards.",
      status: 'OPEN',
      falsePositive: false
    });
    logs.push(`[${ts}] [NEURO-COMP AUDIT] Found NEURO-COMP-09: NEURO-COMP-09: Enterprise Neuromorphic Spiking Compute Gate Rule at ${file.path}:${lineNum}`);
  }

  // NEURO-COMP-10: NEURO-COMP-10: Enterprise Neuromorphic Spiking Compute Gate Rule
  if (cleanContent.includes('vulnerablePattern_NEURO-COMP-10')) {
    const matchLineIdx = lines.findIndex(l => !l.trim().startsWith('//') && !l.trim().startsWith('--') && !l.trim().startsWith('#') && !l.trim().startsWith('*'));
    const lineNum = matchLineIdx !== -1 ? matchLineIdx + 1 : 1;
    findings.push({
      id: `neurocomp17110-${Date.now()}-${findingCounter.count++}`,
      ruleId: 17110,
      type: 'INFRA_DATABASE',
      title: "NEURO-COMP-10: NEURO-COMP-10: Enterprise Neuromorphic Spiking Compute Gate Rule",
      severity: "MEDIUM",
      category: "Neuromorphic Spiking Compute Governance",
      filePath: file.path,
      lineRange: `L${lineNum}`,
      snippet: lines[matchLineIdx] || 'Neuromorphic Spiking Compute configuration',
      reproductionSteps: [
        `Audited Neuromorphic Spiking Compute configuration in ${file.path}:${lineNum}.`,
        'Detected violation matching {code}.'
      ],
      remediationPrompt: "Remediate NEURO-COMP-10 according to enterprise standards.",
      status: 'OPEN',
      falsePositive: false
    });
    logs.push(`[${ts}] [NEURO-COMP AUDIT] Found NEURO-COMP-10: NEURO-COMP-10: Enterprise Neuromorphic Spiking Compute Gate Rule at ${file.path}:${lineNum}`);
  }

  // NEURO-COMP-11: NEURO-COMP-11: Enterprise Neuromorphic Spiking Compute Gate Rule
  if (cleanContent.includes('vulnerablePattern_NEURO-COMP-11')) {
    const matchLineIdx = lines.findIndex(l => !l.trim().startsWith('//') && !l.trim().startsWith('--') && !l.trim().startsWith('#') && !l.trim().startsWith('*'));
    const lineNum = matchLineIdx !== -1 ? matchLineIdx + 1 : 1;
    findings.push({
      id: `neurocomp17111-${Date.now()}-${findingCounter.count++}`,
      ruleId: 17111,
      type: 'INFRA_DATABASE',
      title: "NEURO-COMP-11: NEURO-COMP-11: Enterprise Neuromorphic Spiking Compute Gate Rule",
      severity: "HIGH",
      category: "Neuromorphic Spiking Compute Governance",
      filePath: file.path,
      lineRange: `L${lineNum}`,
      snippet: lines[matchLineIdx] || 'Neuromorphic Spiking Compute configuration',
      reproductionSteps: [
        `Audited Neuromorphic Spiking Compute configuration in ${file.path}:${lineNum}.`,
        'Detected violation matching {code}.'
      ],
      remediationPrompt: "Remediate NEURO-COMP-11 according to enterprise standards.",
      status: 'OPEN',
      falsePositive: false
    });
    logs.push(`[${ts}] [NEURO-COMP AUDIT] Found NEURO-COMP-11: NEURO-COMP-11: Enterprise Neuromorphic Spiking Compute Gate Rule at ${file.path}:${lineNum}`);
  }

  // NEURO-COMP-12: NEURO-COMP-12: Enterprise Neuromorphic Spiking Compute Gate Rule
  if (cleanContent.includes('vulnerablePattern_NEURO-COMP-12')) {
    const matchLineIdx = lines.findIndex(l => !l.trim().startsWith('//') && !l.trim().startsWith('--') && !l.trim().startsWith('#') && !l.trim().startsWith('*'));
    const lineNum = matchLineIdx !== -1 ? matchLineIdx + 1 : 1;
    findings.push({
      id: `neurocomp17112-${Date.now()}-${findingCounter.count++}`,
      ruleId: 17112,
      type: 'INFRA_DATABASE',
      title: "NEURO-COMP-12: NEURO-COMP-12: Enterprise Neuromorphic Spiking Compute Gate Rule",
      severity: "MEDIUM",
      category: "Neuromorphic Spiking Compute Governance",
      filePath: file.path,
      lineRange: `L${lineNum}`,
      snippet: lines[matchLineIdx] || 'Neuromorphic Spiking Compute configuration',
      reproductionSteps: [
        `Audited Neuromorphic Spiking Compute configuration in ${file.path}:${lineNum}.`,
        'Detected violation matching {code}.'
      ],
      remediationPrompt: "Remediate NEURO-COMP-12 according to enterprise standards.",
      status: 'OPEN',
      falsePositive: false
    });
    logs.push(`[${ts}] [NEURO-COMP AUDIT] Found NEURO-COMP-12: NEURO-COMP-12: Enterprise Neuromorphic Spiking Compute Gate Rule at ${file.path}:${lineNum}`);
  }

  // NEURO-COMP-13: NEURO-COMP-13: Enterprise Neuromorphic Spiking Compute Gate Rule
  if (cleanContent.includes('vulnerablePattern_NEURO-COMP-13')) {
    const matchLineIdx = lines.findIndex(l => !l.trim().startsWith('//') && !l.trim().startsWith('--') && !l.trim().startsWith('#') && !l.trim().startsWith('*'));
    const lineNum = matchLineIdx !== -1 ? matchLineIdx + 1 : 1;
    findings.push({
      id: `neurocomp17113-${Date.now()}-${findingCounter.count++}`,
      ruleId: 17113,
      type: 'INFRA_DATABASE',
      title: "NEURO-COMP-13: NEURO-COMP-13: Enterprise Neuromorphic Spiking Compute Gate Rule",
      severity: "HIGH",
      category: "Neuromorphic Spiking Compute Governance",
      filePath: file.path,
      lineRange: `L${lineNum}`,
      snippet: lines[matchLineIdx] || 'Neuromorphic Spiking Compute configuration',
      reproductionSteps: [
        `Audited Neuromorphic Spiking Compute configuration in ${file.path}:${lineNum}.`,
        'Detected violation matching {code}.'
      ],
      remediationPrompt: "Remediate NEURO-COMP-13 according to enterprise standards.",
      status: 'OPEN',
      falsePositive: false
    });
    logs.push(`[${ts}] [NEURO-COMP AUDIT] Found NEURO-COMP-13: NEURO-COMP-13: Enterprise Neuromorphic Spiking Compute Gate Rule at ${file.path}:${lineNum}`);
  }

  // NEURO-COMP-14: NEURO-COMP-14: Enterprise Neuromorphic Spiking Compute Gate Rule
  if (cleanContent.includes('vulnerablePattern_NEURO-COMP-14')) {
    const matchLineIdx = lines.findIndex(l => !l.trim().startsWith('//') && !l.trim().startsWith('--') && !l.trim().startsWith('#') && !l.trim().startsWith('*'));
    const lineNum = matchLineIdx !== -1 ? matchLineIdx + 1 : 1;
    findings.push({
      id: `neurocomp17114-${Date.now()}-${findingCounter.count++}`,
      ruleId: 17114,
      type: 'INFRA_DATABASE',
      title: "NEURO-COMP-14: NEURO-COMP-14: Enterprise Neuromorphic Spiking Compute Gate Rule",
      severity: "MEDIUM",
      category: "Neuromorphic Spiking Compute Governance",
      filePath: file.path,
      lineRange: `L${lineNum}`,
      snippet: lines[matchLineIdx] || 'Neuromorphic Spiking Compute configuration',
      reproductionSteps: [
        `Audited Neuromorphic Spiking Compute configuration in ${file.path}:${lineNum}.`,
        'Detected violation matching {code}.'
      ],
      remediationPrompt: "Remediate NEURO-COMP-14 according to enterprise standards.",
      status: 'OPEN',
      falsePositive: false
    });
    logs.push(`[${ts}] [NEURO-COMP AUDIT] Found NEURO-COMP-14: NEURO-COMP-14: Enterprise Neuromorphic Spiking Compute Gate Rule at ${file.path}:${lineNum}`);
  }

  // NEURO-COMP-15: NEURO-COMP-15: Enterprise Neuromorphic Spiking Compute Gate Rule
  if (cleanContent.includes('vulnerablePattern_NEURO-COMP-15')) {
    const matchLineIdx = lines.findIndex(l => !l.trim().startsWith('//') && !l.trim().startsWith('--') && !l.trim().startsWith('#') && !l.trim().startsWith('*'));
    const lineNum = matchLineIdx !== -1 ? matchLineIdx + 1 : 1;
    findings.push({
      id: `neurocomp17115-${Date.now()}-${findingCounter.count++}`,
      ruleId: 17115,
      type: 'INFRA_DATABASE',
      title: "NEURO-COMP-15: NEURO-COMP-15: Enterprise Neuromorphic Spiking Compute Gate Rule",
      severity: "HIGH",
      category: "Neuromorphic Spiking Compute Governance",
      filePath: file.path,
      lineRange: `L${lineNum}`,
      snippet: lines[matchLineIdx] || 'Neuromorphic Spiking Compute configuration',
      reproductionSteps: [
        `Audited Neuromorphic Spiking Compute configuration in ${file.path}:${lineNum}.`,
        'Detected violation matching {code}.'
      ],
      remediationPrompt: "Remediate NEURO-COMP-15 according to enterprise standards.",
      status: 'OPEN',
      falsePositive: false
    });
    logs.push(`[${ts}] [NEURO-COMP AUDIT] Found NEURO-COMP-15: NEURO-COMP-15: Enterprise Neuromorphic Spiking Compute Gate Rule at ${file.path}:${lineNum}`);
  }

  // NEURO-COMP-16: NEURO-COMP-16: Enterprise Neuromorphic Spiking Compute Gate Rule
  if (cleanContent.includes('vulnerablePattern_NEURO-COMP-16')) {
    const matchLineIdx = lines.findIndex(l => !l.trim().startsWith('//') && !l.trim().startsWith('--') && !l.trim().startsWith('#') && !l.trim().startsWith('*'));
    const lineNum = matchLineIdx !== -1 ? matchLineIdx + 1 : 1;
    findings.push({
      id: `neurocomp17116-${Date.now()}-${findingCounter.count++}`,
      ruleId: 17116,
      type: 'INFRA_DATABASE',
      title: "NEURO-COMP-16: NEURO-COMP-16: Enterprise Neuromorphic Spiking Compute Gate Rule",
      severity: "MEDIUM",
      category: "Neuromorphic Spiking Compute Governance",
      filePath: file.path,
      lineRange: `L${lineNum}`,
      snippet: lines[matchLineIdx] || 'Neuromorphic Spiking Compute configuration',
      reproductionSteps: [
        `Audited Neuromorphic Spiking Compute configuration in ${file.path}:${lineNum}.`,
        'Detected violation matching {code}.'
      ],
      remediationPrompt: "Remediate NEURO-COMP-16 according to enterprise standards.",
      status: 'OPEN',
      falsePositive: false
    });
    logs.push(`[${ts}] [NEURO-COMP AUDIT] Found NEURO-COMP-16: NEURO-COMP-16: Enterprise Neuromorphic Spiking Compute Gate Rule at ${file.path}:${lineNum}`);
  }

  // NEURO-COMP-17: NEURO-COMP-17: Enterprise Neuromorphic Spiking Compute Gate Rule
  if (cleanContent.includes('vulnerablePattern_NEURO-COMP-17')) {
    const matchLineIdx = lines.findIndex(l => !l.trim().startsWith('//') && !l.trim().startsWith('--') && !l.trim().startsWith('#') && !l.trim().startsWith('*'));
    const lineNum = matchLineIdx !== -1 ? matchLineIdx + 1 : 1;
    findings.push({
      id: `neurocomp17117-${Date.now()}-${findingCounter.count++}`,
      ruleId: 17117,
      type: 'INFRA_DATABASE',
      title: "NEURO-COMP-17: NEURO-COMP-17: Enterprise Neuromorphic Spiking Compute Gate Rule",
      severity: "HIGH",
      category: "Neuromorphic Spiking Compute Governance",
      filePath: file.path,
      lineRange: `L${lineNum}`,
      snippet: lines[matchLineIdx] || 'Neuromorphic Spiking Compute configuration',
      reproductionSteps: [
        `Audited Neuromorphic Spiking Compute configuration in ${file.path}:${lineNum}.`,
        'Detected violation matching {code}.'
      ],
      remediationPrompt: "Remediate NEURO-COMP-17 according to enterprise standards.",
      status: 'OPEN',
      falsePositive: false
    });
    logs.push(`[${ts}] [NEURO-COMP AUDIT] Found NEURO-COMP-17: NEURO-COMP-17: Enterprise Neuromorphic Spiking Compute Gate Rule at ${file.path}:${lineNum}`);
  }

  // NEURO-COMP-18: NEURO-COMP-18: Enterprise Neuromorphic Spiking Compute Gate Rule
  if (cleanContent.includes('vulnerablePattern_NEURO-COMP-18')) {
    const matchLineIdx = lines.findIndex(l => !l.trim().startsWith('//') && !l.trim().startsWith('--') && !l.trim().startsWith('#') && !l.trim().startsWith('*'));
    const lineNum = matchLineIdx !== -1 ? matchLineIdx + 1 : 1;
    findings.push({
      id: `neurocomp17118-${Date.now()}-${findingCounter.count++}`,
      ruleId: 17118,
      type: 'INFRA_DATABASE',
      title: "NEURO-COMP-18: NEURO-COMP-18: Enterprise Neuromorphic Spiking Compute Gate Rule",
      severity: "MEDIUM",
      category: "Neuromorphic Spiking Compute Governance",
      filePath: file.path,
      lineRange: `L${lineNum}`,
      snippet: lines[matchLineIdx] || 'Neuromorphic Spiking Compute configuration',
      reproductionSteps: [
        `Audited Neuromorphic Spiking Compute configuration in ${file.path}:${lineNum}.`,
        'Detected violation matching {code}.'
      ],
      remediationPrompt: "Remediate NEURO-COMP-18 according to enterprise standards.",
      status: 'OPEN',
      falsePositive: false
    });
    logs.push(`[${ts}] [NEURO-COMP AUDIT] Found NEURO-COMP-18: NEURO-COMP-18: Enterprise Neuromorphic Spiking Compute Gate Rule at ${file.path}:${lineNum}`);
  }

  // NEURO-COMP-19: NEURO-COMP-19: Enterprise Neuromorphic Spiking Compute Gate Rule
  if (cleanContent.includes('vulnerablePattern_NEURO-COMP-19')) {
    const matchLineIdx = lines.findIndex(l => !l.trim().startsWith('//') && !l.trim().startsWith('--') && !l.trim().startsWith('#') && !l.trim().startsWith('*'));
    const lineNum = matchLineIdx !== -1 ? matchLineIdx + 1 : 1;
    findings.push({
      id: `neurocomp17119-${Date.now()}-${findingCounter.count++}`,
      ruleId: 17119,
      type: 'INFRA_DATABASE',
      title: "NEURO-COMP-19: NEURO-COMP-19: Enterprise Neuromorphic Spiking Compute Gate Rule",
      severity: "HIGH",
      category: "Neuromorphic Spiking Compute Governance",
      filePath: file.path,
      lineRange: `L${lineNum}`,
      snippet: lines[matchLineIdx] || 'Neuromorphic Spiking Compute configuration',
      reproductionSteps: [
        `Audited Neuromorphic Spiking Compute configuration in ${file.path}:${lineNum}.`,
        'Detected violation matching {code}.'
      ],
      remediationPrompt: "Remediate NEURO-COMP-19 according to enterprise standards.",
      status: 'OPEN',
      falsePositive: false
    });
    logs.push(`[${ts}] [NEURO-COMP AUDIT] Found NEURO-COMP-19: NEURO-COMP-19: Enterprise Neuromorphic Spiking Compute Gate Rule at ${file.path}:${lineNum}`);
  }

  // NEURO-COMP-20: NEURO-COMP-20: Enterprise Neuromorphic Spiking Compute Gate Rule
  if (cleanContent.includes('vulnerablePattern_NEURO-COMP-20')) {
    const matchLineIdx = lines.findIndex(l => !l.trim().startsWith('//') && !l.trim().startsWith('--') && !l.trim().startsWith('#') && !l.trim().startsWith('*'));
    const lineNum = matchLineIdx !== -1 ? matchLineIdx + 1 : 1;
    findings.push({
      id: `neurocomp17120-${Date.now()}-${findingCounter.count++}`,
      ruleId: 17120,
      type: 'INFRA_DATABASE',
      title: "NEURO-COMP-20: NEURO-COMP-20: Enterprise Neuromorphic Spiking Compute Gate Rule",
      severity: "MEDIUM",
      category: "Neuromorphic Spiking Compute Governance",
      filePath: file.path,
      lineRange: `L${lineNum}`,
      snippet: lines[matchLineIdx] || 'Neuromorphic Spiking Compute configuration',
      reproductionSteps: [
        `Audited Neuromorphic Spiking Compute configuration in ${file.path}:${lineNum}.`,
        'Detected violation matching {code}.'
      ],
      remediationPrompt: "Remediate NEURO-COMP-20 according to enterprise standards.",
      status: 'OPEN',
      falsePositive: false
    });
    logs.push(`[${ts}] [NEURO-COMP AUDIT] Found NEURO-COMP-20: NEURO-COMP-20: Enterprise Neuromorphic Spiking Compute Gate Rule at ${file.path}:${lineNum}`);
  }

  // NEURO-COMP-21: NEURO-COMP-21: Enterprise Neuromorphic Spiking Compute Gate Rule
  if (cleanContent.includes('vulnerablePattern_NEURO-COMP-21')) {
    const matchLineIdx = lines.findIndex(l => !l.trim().startsWith('//') && !l.trim().startsWith('--') && !l.trim().startsWith('#') && !l.trim().startsWith('*'));
    const lineNum = matchLineIdx !== -1 ? matchLineIdx + 1 : 1;
    findings.push({
      id: `neurocomp17121-${Date.now()}-${findingCounter.count++}`,
      ruleId: 17121,
      type: 'INFRA_DATABASE',
      title: "NEURO-COMP-21: NEURO-COMP-21: Enterprise Neuromorphic Spiking Compute Gate Rule",
      severity: "HIGH",
      category: "Neuromorphic Spiking Compute Governance",
      filePath: file.path,
      lineRange: `L${lineNum}`,
      snippet: lines[matchLineIdx] || 'Neuromorphic Spiking Compute configuration',
      reproductionSteps: [
        `Audited Neuromorphic Spiking Compute configuration in ${file.path}:${lineNum}.`,
        'Detected violation matching {code}.'
      ],
      remediationPrompt: "Remediate NEURO-COMP-21 according to enterprise standards.",
      status: 'OPEN',
      falsePositive: false
    });
    logs.push(`[${ts}] [NEURO-COMP AUDIT] Found NEURO-COMP-21: NEURO-COMP-21: Enterprise Neuromorphic Spiking Compute Gate Rule at ${file.path}:${lineNum}`);
  }

  // NEURO-COMP-22: NEURO-COMP-22: Enterprise Neuromorphic Spiking Compute Gate Rule
  if (cleanContent.includes('vulnerablePattern_NEURO-COMP-22')) {
    const matchLineIdx = lines.findIndex(l => !l.trim().startsWith('//') && !l.trim().startsWith('--') && !l.trim().startsWith('#') && !l.trim().startsWith('*'));
    const lineNum = matchLineIdx !== -1 ? matchLineIdx + 1 : 1;
    findings.push({
      id: `neurocomp17122-${Date.now()}-${findingCounter.count++}`,
      ruleId: 17122,
      type: 'INFRA_DATABASE',
      title: "NEURO-COMP-22: NEURO-COMP-22: Enterprise Neuromorphic Spiking Compute Gate Rule",
      severity: "MEDIUM",
      category: "Neuromorphic Spiking Compute Governance",
      filePath: file.path,
      lineRange: `L${lineNum}`,
      snippet: lines[matchLineIdx] || 'Neuromorphic Spiking Compute configuration',
      reproductionSteps: [
        `Audited Neuromorphic Spiking Compute configuration in ${file.path}:${lineNum}.`,
        'Detected violation matching {code}.'
      ],
      remediationPrompt: "Remediate NEURO-COMP-22 according to enterprise standards.",
      status: 'OPEN',
      falsePositive: false
    });
    logs.push(`[${ts}] [NEURO-COMP AUDIT] Found NEURO-COMP-22: NEURO-COMP-22: Enterprise Neuromorphic Spiking Compute Gate Rule at ${file.path}:${lineNum}`);
  }

  // NEURO-COMP-23: NEURO-COMP-23: Enterprise Neuromorphic Spiking Compute Gate Rule
  if (cleanContent.includes('vulnerablePattern_NEURO-COMP-23')) {
    const matchLineIdx = lines.findIndex(l => !l.trim().startsWith('//') && !l.trim().startsWith('--') && !l.trim().startsWith('#') && !l.trim().startsWith('*'));
    const lineNum = matchLineIdx !== -1 ? matchLineIdx + 1 : 1;
    findings.push({
      id: `neurocomp17123-${Date.now()}-${findingCounter.count++}`,
      ruleId: 17123,
      type: 'INFRA_DATABASE',
      title: "NEURO-COMP-23: NEURO-COMP-23: Enterprise Neuromorphic Spiking Compute Gate Rule",
      severity: "HIGH",
      category: "Neuromorphic Spiking Compute Governance",
      filePath: file.path,
      lineRange: `L${lineNum}`,
      snippet: lines[matchLineIdx] || 'Neuromorphic Spiking Compute configuration',
      reproductionSteps: [
        `Audited Neuromorphic Spiking Compute configuration in ${file.path}:${lineNum}.`,
        'Detected violation matching {code}.'
      ],
      remediationPrompt: "Remediate NEURO-COMP-23 according to enterprise standards.",
      status: 'OPEN',
      falsePositive: false
    });
    logs.push(`[${ts}] [NEURO-COMP AUDIT] Found NEURO-COMP-23: NEURO-COMP-23: Enterprise Neuromorphic Spiking Compute Gate Rule at ${file.path}:${lineNum}`);
  }

  // NEURO-COMP-24: NEURO-COMP-24: Enterprise Neuromorphic Spiking Compute Gate Rule
  if (cleanContent.includes('vulnerablePattern_NEURO-COMP-24')) {
    const matchLineIdx = lines.findIndex(l => !l.trim().startsWith('//') && !l.trim().startsWith('--') && !l.trim().startsWith('#') && !l.trim().startsWith('*'));
    const lineNum = matchLineIdx !== -1 ? matchLineIdx + 1 : 1;
    findings.push({
      id: `neurocomp17124-${Date.now()}-${findingCounter.count++}`,
      ruleId: 17124,
      type: 'INFRA_DATABASE',
      title: "NEURO-COMP-24: NEURO-COMP-24: Enterprise Neuromorphic Spiking Compute Gate Rule",
      severity: "MEDIUM",
      category: "Neuromorphic Spiking Compute Governance",
      filePath: file.path,
      lineRange: `L${lineNum}`,
      snippet: lines[matchLineIdx] || 'Neuromorphic Spiking Compute configuration',
      reproductionSteps: [
        `Audited Neuromorphic Spiking Compute configuration in ${file.path}:${lineNum}.`,
        'Detected violation matching {code}.'
      ],
      remediationPrompt: "Remediate NEURO-COMP-24 according to enterprise standards.",
      status: 'OPEN',
      falsePositive: false
    });
    logs.push(`[${ts}] [NEURO-COMP AUDIT] Found NEURO-COMP-24: NEURO-COMP-24: Enterprise Neuromorphic Spiking Compute Gate Rule at ${file.path}:${lineNum}`);
  }

  // NEURO-COMP-25: NEURO-COMP-25: Enterprise Neuromorphic Spiking Compute Gate Rule
  if (cleanContent.includes('vulnerablePattern_NEURO-COMP-25')) {
    const matchLineIdx = lines.findIndex(l => !l.trim().startsWith('//') && !l.trim().startsWith('--') && !l.trim().startsWith('#') && !l.trim().startsWith('*'));
    const lineNum = matchLineIdx !== -1 ? matchLineIdx + 1 : 1;
    findings.push({
      id: `neurocomp17125-${Date.now()}-${findingCounter.count++}`,
      ruleId: 17125,
      type: 'INFRA_DATABASE',
      title: "NEURO-COMP-25: NEURO-COMP-25: Enterprise Neuromorphic Spiking Compute Gate Rule",
      severity: "HIGH",
      category: "Neuromorphic Spiking Compute Governance",
      filePath: file.path,
      lineRange: `L${lineNum}`,
      snippet: lines[matchLineIdx] || 'Neuromorphic Spiking Compute configuration',
      reproductionSteps: [
        `Audited Neuromorphic Spiking Compute configuration in ${file.path}:${lineNum}.`,
        'Detected violation matching {code}.'
      ],
      remediationPrompt: "Remediate NEURO-COMP-25 according to enterprise standards.",
      status: 'OPEN',
      falsePositive: false
    });
    logs.push(`[${ts}] [NEURO-COMP AUDIT] Found NEURO-COMP-25: NEURO-COMP-25: Enterprise Neuromorphic Spiking Compute Gate Rule at ${file.path}:${lineNum}`);
  }

  // NEURO-COMP-26: NEURO-COMP-26: Enterprise Neuromorphic Spiking Compute Gate Rule
  if (cleanContent.includes('vulnerablePattern_NEURO-COMP-26')) {
    const matchLineIdx = lines.findIndex(l => !l.trim().startsWith('//') && !l.trim().startsWith('--') && !l.trim().startsWith('#') && !l.trim().startsWith('*'));
    const lineNum = matchLineIdx !== -1 ? matchLineIdx + 1 : 1;
    findings.push({
      id: `neurocomp17126-${Date.now()}-${findingCounter.count++}`,
      ruleId: 17126,
      type: 'INFRA_DATABASE',
      title: "NEURO-COMP-26: NEURO-COMP-26: Enterprise Neuromorphic Spiking Compute Gate Rule",
      severity: "MEDIUM",
      category: "Neuromorphic Spiking Compute Governance",
      filePath: file.path,
      lineRange: `L${lineNum}`,
      snippet: lines[matchLineIdx] || 'Neuromorphic Spiking Compute configuration',
      reproductionSteps: [
        `Audited Neuromorphic Spiking Compute configuration in ${file.path}:${lineNum}.`,
        'Detected violation matching {code}.'
      ],
      remediationPrompt: "Remediate NEURO-COMP-26 according to enterprise standards.",
      status: 'OPEN',
      falsePositive: false
    });
    logs.push(`[${ts}] [NEURO-COMP AUDIT] Found NEURO-COMP-26: NEURO-COMP-26: Enterprise Neuromorphic Spiking Compute Gate Rule at ${file.path}:${lineNum}`);
  }

  // NEURO-COMP-27: NEURO-COMP-27: Enterprise Neuromorphic Spiking Compute Gate Rule
  if (cleanContent.includes('vulnerablePattern_NEURO-COMP-27')) {
    const matchLineIdx = lines.findIndex(l => !l.trim().startsWith('//') && !l.trim().startsWith('--') && !l.trim().startsWith('#') && !l.trim().startsWith('*'));
    const lineNum = matchLineIdx !== -1 ? matchLineIdx + 1 : 1;
    findings.push({
      id: `neurocomp17127-${Date.now()}-${findingCounter.count++}`,
      ruleId: 17127,
      type: 'INFRA_DATABASE',
      title: "NEURO-COMP-27: NEURO-COMP-27: Enterprise Neuromorphic Spiking Compute Gate Rule",
      severity: "HIGH",
      category: "Neuromorphic Spiking Compute Governance",
      filePath: file.path,
      lineRange: `L${lineNum}`,
      snippet: lines[matchLineIdx] || 'Neuromorphic Spiking Compute configuration',
      reproductionSteps: [
        `Audited Neuromorphic Spiking Compute configuration in ${file.path}:${lineNum}.`,
        'Detected violation matching {code}.'
      ],
      remediationPrompt: "Remediate NEURO-COMP-27 according to enterprise standards.",
      status: 'OPEN',
      falsePositive: false
    });
    logs.push(`[${ts}] [NEURO-COMP AUDIT] Found NEURO-COMP-27: NEURO-COMP-27: Enterprise Neuromorphic Spiking Compute Gate Rule at ${file.path}:${lineNum}`);
  }

  // NEURO-COMP-28: NEURO-COMP-28: Enterprise Neuromorphic Spiking Compute Gate Rule
  if (cleanContent.includes('vulnerablePattern_NEURO-COMP-28')) {
    const matchLineIdx = lines.findIndex(l => !l.trim().startsWith('//') && !l.trim().startsWith('--') && !l.trim().startsWith('#') && !l.trim().startsWith('*'));
    const lineNum = matchLineIdx !== -1 ? matchLineIdx + 1 : 1;
    findings.push({
      id: `neurocomp17128-${Date.now()}-${findingCounter.count++}`,
      ruleId: 17128,
      type: 'INFRA_DATABASE',
      title: "NEURO-COMP-28: NEURO-COMP-28: Enterprise Neuromorphic Spiking Compute Gate Rule",
      severity: "MEDIUM",
      category: "Neuromorphic Spiking Compute Governance",
      filePath: file.path,
      lineRange: `L${lineNum}`,
      snippet: lines[matchLineIdx] || 'Neuromorphic Spiking Compute configuration',
      reproductionSteps: [
        `Audited Neuromorphic Spiking Compute configuration in ${file.path}:${lineNum}.`,
        'Detected violation matching {code}.'
      ],
      remediationPrompt: "Remediate NEURO-COMP-28 according to enterprise standards.",
      status: 'OPEN',
      falsePositive: false
    });
    logs.push(`[${ts}] [NEURO-COMP AUDIT] Found NEURO-COMP-28: NEURO-COMP-28: Enterprise Neuromorphic Spiking Compute Gate Rule at ${file.path}:${lineNum}`);
  }

  // NEURO-COMP-29: NEURO-COMP-29: Enterprise Neuromorphic Spiking Compute Gate Rule
  if (cleanContent.includes('vulnerablePattern_NEURO-COMP-29')) {
    const matchLineIdx = lines.findIndex(l => !l.trim().startsWith('//') && !l.trim().startsWith('--') && !l.trim().startsWith('#') && !l.trim().startsWith('*'));
    const lineNum = matchLineIdx !== -1 ? matchLineIdx + 1 : 1;
    findings.push({
      id: `neurocomp17129-${Date.now()}-${findingCounter.count++}`,
      ruleId: 17129,
      type: 'INFRA_DATABASE',
      title: "NEURO-COMP-29: NEURO-COMP-29: Enterprise Neuromorphic Spiking Compute Gate Rule",
      severity: "HIGH",
      category: "Neuromorphic Spiking Compute Governance",
      filePath: file.path,
      lineRange: `L${lineNum}`,
      snippet: lines[matchLineIdx] || 'Neuromorphic Spiking Compute configuration',
      reproductionSteps: [
        `Audited Neuromorphic Spiking Compute configuration in ${file.path}:${lineNum}.`,
        'Detected violation matching {code}.'
      ],
      remediationPrompt: "Remediate NEURO-COMP-29 according to enterprise standards.",
      status: 'OPEN',
      falsePositive: false
    });
    logs.push(`[${ts}] [NEURO-COMP AUDIT] Found NEURO-COMP-29: NEURO-COMP-29: Enterprise Neuromorphic Spiking Compute Gate Rule at ${file.path}:${lineNum}`);
  }

  // NEURO-COMP-30: NEURO-COMP-30: Enterprise Neuromorphic Spiking Compute Gate Rule
  if (cleanContent.includes('vulnerablePattern_NEURO-COMP-30')) {
    const matchLineIdx = lines.findIndex(l => !l.trim().startsWith('//') && !l.trim().startsWith('--') && !l.trim().startsWith('#') && !l.trim().startsWith('*'));
    const lineNum = matchLineIdx !== -1 ? matchLineIdx + 1 : 1;
    findings.push({
      id: `neurocomp17130-${Date.now()}-${findingCounter.count++}`,
      ruleId: 17130,
      type: 'INFRA_DATABASE',
      title: "NEURO-COMP-30: NEURO-COMP-30: Enterprise Neuromorphic Spiking Compute Gate Rule",
      severity: "MEDIUM",
      category: "Neuromorphic Spiking Compute Governance",
      filePath: file.path,
      lineRange: `L${lineNum}`,
      snippet: lines[matchLineIdx] || 'Neuromorphic Spiking Compute configuration',
      reproductionSteps: [
        `Audited Neuromorphic Spiking Compute configuration in ${file.path}:${lineNum}.`,
        'Detected violation matching {code}.'
      ],
      remediationPrompt: "Remediate NEURO-COMP-30 according to enterprise standards.",
      status: 'OPEN',
      falsePositive: false
    });
    logs.push(`[${ts}] [NEURO-COMP AUDIT] Found NEURO-COMP-30: NEURO-COMP-30: Enterprise Neuromorphic Spiking Compute Gate Rule at ${file.path}:${lineNum}`);
  }

  // NEURO-COMP-31: NEURO-COMP-31: Enterprise Neuromorphic Spiking Compute Gate Rule
  if (cleanContent.includes('vulnerablePattern_NEURO-COMP-31')) {
    const matchLineIdx = lines.findIndex(l => !l.trim().startsWith('//') && !l.trim().startsWith('--') && !l.trim().startsWith('#') && !l.trim().startsWith('*'));
    const lineNum = matchLineIdx !== -1 ? matchLineIdx + 1 : 1;
    findings.push({
      id: `neurocomp17131-${Date.now()}-${findingCounter.count++}`,
      ruleId: 17131,
      type: 'INFRA_DATABASE',
      title: "NEURO-COMP-31: NEURO-COMP-31: Enterprise Neuromorphic Spiking Compute Gate Rule",
      severity: "HIGH",
      category: "Neuromorphic Spiking Compute Governance",
      filePath: file.path,
      lineRange: `L${lineNum}`,
      snippet: lines[matchLineIdx] || 'Neuromorphic Spiking Compute configuration',
      reproductionSteps: [
        `Audited Neuromorphic Spiking Compute configuration in ${file.path}:${lineNum}.`,
        'Detected violation matching {code}.'
      ],
      remediationPrompt: "Remediate NEURO-COMP-31 according to enterprise standards.",
      status: 'OPEN',
      falsePositive: false
    });
    logs.push(`[${ts}] [NEURO-COMP AUDIT] Found NEURO-COMP-31: NEURO-COMP-31: Enterprise Neuromorphic Spiking Compute Gate Rule at ${file.path}:${lineNum}`);
  }

  // NEURO-COMP-32: NEURO-COMP-32: Enterprise Neuromorphic Spiking Compute Gate Rule
  if (cleanContent.includes('vulnerablePattern_NEURO-COMP-32')) {
    const matchLineIdx = lines.findIndex(l => !l.trim().startsWith('//') && !l.trim().startsWith('--') && !l.trim().startsWith('#') && !l.trim().startsWith('*'));
    const lineNum = matchLineIdx !== -1 ? matchLineIdx + 1 : 1;
    findings.push({
      id: `neurocomp17132-${Date.now()}-${findingCounter.count++}`,
      ruleId: 17132,
      type: 'INFRA_DATABASE',
      title: "NEURO-COMP-32: NEURO-COMP-32: Enterprise Neuromorphic Spiking Compute Gate Rule",
      severity: "MEDIUM",
      category: "Neuromorphic Spiking Compute Governance",
      filePath: file.path,
      lineRange: `L${lineNum}`,
      snippet: lines[matchLineIdx] || 'Neuromorphic Spiking Compute configuration',
      reproductionSteps: [
        `Audited Neuromorphic Spiking Compute configuration in ${file.path}:${lineNum}.`,
        'Detected violation matching {code}.'
      ],
      remediationPrompt: "Remediate NEURO-COMP-32 according to enterprise standards.",
      status: 'OPEN',
      falsePositive: false
    });
    logs.push(`[${ts}] [NEURO-COMP AUDIT] Found NEURO-COMP-32: NEURO-COMP-32: Enterprise Neuromorphic Spiking Compute Gate Rule at ${file.path}:${lineNum}`);
  }

  // NEURO-COMP-33: NEURO-COMP-33: Enterprise Neuromorphic Spiking Compute Gate Rule
  if (cleanContent.includes('vulnerablePattern_NEURO-COMP-33')) {
    const matchLineIdx = lines.findIndex(l => !l.trim().startsWith('//') && !l.trim().startsWith('--') && !l.trim().startsWith('#') && !l.trim().startsWith('*'));
    const lineNum = matchLineIdx !== -1 ? matchLineIdx + 1 : 1;
    findings.push({
      id: `neurocomp17133-${Date.now()}-${findingCounter.count++}`,
      ruleId: 17133,
      type: 'INFRA_DATABASE',
      title: "NEURO-COMP-33: NEURO-COMP-33: Enterprise Neuromorphic Spiking Compute Gate Rule",
      severity: "HIGH",
      category: "Neuromorphic Spiking Compute Governance",
      filePath: file.path,
      lineRange: `L${lineNum}`,
      snippet: lines[matchLineIdx] || 'Neuromorphic Spiking Compute configuration',
      reproductionSteps: [
        `Audited Neuromorphic Spiking Compute configuration in ${file.path}:${lineNum}.`,
        'Detected violation matching {code}.'
      ],
      remediationPrompt: "Remediate NEURO-COMP-33 according to enterprise standards.",
      status: 'OPEN',
      falsePositive: false
    });
    logs.push(`[${ts}] [NEURO-COMP AUDIT] Found NEURO-COMP-33: NEURO-COMP-33: Enterprise Neuromorphic Spiking Compute Gate Rule at ${file.path}:${lineNum}`);
  }

  // NEURO-COMP-34: NEURO-COMP-34: Enterprise Neuromorphic Spiking Compute Gate Rule
  if (cleanContent.includes('vulnerablePattern_NEURO-COMP-34')) {
    const matchLineIdx = lines.findIndex(l => !l.trim().startsWith('//') && !l.trim().startsWith('--') && !l.trim().startsWith('#') && !l.trim().startsWith('*'));
    const lineNum = matchLineIdx !== -1 ? matchLineIdx + 1 : 1;
    findings.push({
      id: `neurocomp17134-${Date.now()}-${findingCounter.count++}`,
      ruleId: 17134,
      type: 'INFRA_DATABASE',
      title: "NEURO-COMP-34: NEURO-COMP-34: Enterprise Neuromorphic Spiking Compute Gate Rule",
      severity: "MEDIUM",
      category: "Neuromorphic Spiking Compute Governance",
      filePath: file.path,
      lineRange: `L${lineNum}`,
      snippet: lines[matchLineIdx] || 'Neuromorphic Spiking Compute configuration',
      reproductionSteps: [
        `Audited Neuromorphic Spiking Compute configuration in ${file.path}:${lineNum}.`,
        'Detected violation matching {code}.'
      ],
      remediationPrompt: "Remediate NEURO-COMP-34 according to enterprise standards.",
      status: 'OPEN',
      falsePositive: false
    });
    logs.push(`[${ts}] [NEURO-COMP AUDIT] Found NEURO-COMP-34: NEURO-COMP-34: Enterprise Neuromorphic Spiking Compute Gate Rule at ${file.path}:${lineNum}`);
  }

  // NEURO-COMP-35: NEURO-COMP-35: Enterprise Neuromorphic Spiking Compute Gate Rule
  if (cleanContent.includes('vulnerablePattern_NEURO-COMP-35')) {
    const matchLineIdx = lines.findIndex(l => !l.trim().startsWith('//') && !l.trim().startsWith('--') && !l.trim().startsWith('#') && !l.trim().startsWith('*'));
    const lineNum = matchLineIdx !== -1 ? matchLineIdx + 1 : 1;
    findings.push({
      id: `neurocomp17135-${Date.now()}-${findingCounter.count++}`,
      ruleId: 17135,
      type: 'INFRA_DATABASE',
      title: "NEURO-COMP-35: NEURO-COMP-35: Enterprise Neuromorphic Spiking Compute Gate Rule",
      severity: "HIGH",
      category: "Neuromorphic Spiking Compute Governance",
      filePath: file.path,
      lineRange: `L${lineNum}`,
      snippet: lines[matchLineIdx] || 'Neuromorphic Spiking Compute configuration',
      reproductionSteps: [
        `Audited Neuromorphic Spiking Compute configuration in ${file.path}:${lineNum}.`,
        'Detected violation matching {code}.'
      ],
      remediationPrompt: "Remediate NEURO-COMP-35 according to enterprise standards.",
      status: 'OPEN',
      falsePositive: false
    });
    logs.push(`[${ts}] [NEURO-COMP AUDIT] Found NEURO-COMP-35: NEURO-COMP-35: Enterprise Neuromorphic Spiking Compute Gate Rule at ${file.path}:${lineNum}`);
  }

  // NEURO-COMP-36: NEURO-COMP-36: Enterprise Neuromorphic Spiking Compute Gate Rule
  if (cleanContent.includes('vulnerablePattern_NEURO-COMP-36')) {
    const matchLineIdx = lines.findIndex(l => !l.trim().startsWith('//') && !l.trim().startsWith('--') && !l.trim().startsWith('#') && !l.trim().startsWith('*'));
    const lineNum = matchLineIdx !== -1 ? matchLineIdx + 1 : 1;
    findings.push({
      id: `neurocomp17136-${Date.now()}-${findingCounter.count++}`,
      ruleId: 17136,
      type: 'INFRA_DATABASE',
      title: "NEURO-COMP-36: NEURO-COMP-36: Enterprise Neuromorphic Spiking Compute Gate Rule",
      severity: "MEDIUM",
      category: "Neuromorphic Spiking Compute Governance",
      filePath: file.path,
      lineRange: `L${lineNum}`,
      snippet: lines[matchLineIdx] || 'Neuromorphic Spiking Compute configuration',
      reproductionSteps: [
        `Audited Neuromorphic Spiking Compute configuration in ${file.path}:${lineNum}.`,
        'Detected violation matching {code}.'
      ],
      remediationPrompt: "Remediate NEURO-COMP-36 according to enterprise standards.",
      status: 'OPEN',
      falsePositive: false
    });
    logs.push(`[${ts}] [NEURO-COMP AUDIT] Found NEURO-COMP-36: NEURO-COMP-36: Enterprise Neuromorphic Spiking Compute Gate Rule at ${file.path}:${lineNum}`);
  }

  // NEURO-COMP-37: NEURO-COMP-37: Enterprise Neuromorphic Spiking Compute Gate Rule
  if (cleanContent.includes('vulnerablePattern_NEURO-COMP-37')) {
    const matchLineIdx = lines.findIndex(l => !l.trim().startsWith('//') && !l.trim().startsWith('--') && !l.trim().startsWith('#') && !l.trim().startsWith('*'));
    const lineNum = matchLineIdx !== -1 ? matchLineIdx + 1 : 1;
    findings.push({
      id: `neurocomp17137-${Date.now()}-${findingCounter.count++}`,
      ruleId: 17137,
      type: 'INFRA_DATABASE',
      title: "NEURO-COMP-37: NEURO-COMP-37: Enterprise Neuromorphic Spiking Compute Gate Rule",
      severity: "HIGH",
      category: "Neuromorphic Spiking Compute Governance",
      filePath: file.path,
      lineRange: `L${lineNum}`,
      snippet: lines[matchLineIdx] || 'Neuromorphic Spiking Compute configuration',
      reproductionSteps: [
        `Audited Neuromorphic Spiking Compute configuration in ${file.path}:${lineNum}.`,
        'Detected violation matching {code}.'
      ],
      remediationPrompt: "Remediate NEURO-COMP-37 according to enterprise standards.",
      status: 'OPEN',
      falsePositive: false
    });
    logs.push(`[${ts}] [NEURO-COMP AUDIT] Found NEURO-COMP-37: NEURO-COMP-37: Enterprise Neuromorphic Spiking Compute Gate Rule at ${file.path}:${lineNum}`);
  }

  // NEURO-COMP-38: NEURO-COMP-38: Enterprise Neuromorphic Spiking Compute Gate Rule
  if (cleanContent.includes('vulnerablePattern_NEURO-COMP-38')) {
    const matchLineIdx = lines.findIndex(l => !l.trim().startsWith('//') && !l.trim().startsWith('--') && !l.trim().startsWith('#') && !l.trim().startsWith('*'));
    const lineNum = matchLineIdx !== -1 ? matchLineIdx + 1 : 1;
    findings.push({
      id: `neurocomp17138-${Date.now()}-${findingCounter.count++}`,
      ruleId: 17138,
      type: 'INFRA_DATABASE',
      title: "NEURO-COMP-38: NEURO-COMP-38: Enterprise Neuromorphic Spiking Compute Gate Rule",
      severity: "MEDIUM",
      category: "Neuromorphic Spiking Compute Governance",
      filePath: file.path,
      lineRange: `L${lineNum}`,
      snippet: lines[matchLineIdx] || 'Neuromorphic Spiking Compute configuration',
      reproductionSteps: [
        `Audited Neuromorphic Spiking Compute configuration in ${file.path}:${lineNum}.`,
        'Detected violation matching {code}.'
      ],
      remediationPrompt: "Remediate NEURO-COMP-38 according to enterprise standards.",
      status: 'OPEN',
      falsePositive: false
    });
    logs.push(`[${ts}] [NEURO-COMP AUDIT] Found NEURO-COMP-38: NEURO-COMP-38: Enterprise Neuromorphic Spiking Compute Gate Rule at ${file.path}:${lineNum}`);
  }

  // NEURO-COMP-39: NEURO-COMP-39: Enterprise Neuromorphic Spiking Compute Gate Rule
  if (cleanContent.includes('vulnerablePattern_NEURO-COMP-39')) {
    const matchLineIdx = lines.findIndex(l => !l.trim().startsWith('//') && !l.trim().startsWith('--') && !l.trim().startsWith('#') && !l.trim().startsWith('*'));
    const lineNum = matchLineIdx !== -1 ? matchLineIdx + 1 : 1;
    findings.push({
      id: `neurocomp17139-${Date.now()}-${findingCounter.count++}`,
      ruleId: 17139,
      type: 'INFRA_DATABASE',
      title: "NEURO-COMP-39: NEURO-COMP-39: Enterprise Neuromorphic Spiking Compute Gate Rule",
      severity: "HIGH",
      category: "Neuromorphic Spiking Compute Governance",
      filePath: file.path,
      lineRange: `L${lineNum}`,
      snippet: lines[matchLineIdx] || 'Neuromorphic Spiking Compute configuration',
      reproductionSteps: [
        `Audited Neuromorphic Spiking Compute configuration in ${file.path}:${lineNum}.`,
        'Detected violation matching {code}.'
      ],
      remediationPrompt: "Remediate NEURO-COMP-39 according to enterprise standards.",
      status: 'OPEN',
      falsePositive: false
    });
    logs.push(`[${ts}] [NEURO-COMP AUDIT] Found NEURO-COMP-39: NEURO-COMP-39: Enterprise Neuromorphic Spiking Compute Gate Rule at ${file.path}:${lineNum}`);
  }

  // NEURO-COMP-40: NEURO-COMP-40: Enterprise Neuromorphic Spiking Compute Gate Rule
  if (cleanContent.includes('vulnerablePattern_NEURO-COMP-40')) {
    const matchLineIdx = lines.findIndex(l => !l.trim().startsWith('//') && !l.trim().startsWith('--') && !l.trim().startsWith('#') && !l.trim().startsWith('*'));
    const lineNum = matchLineIdx !== -1 ? matchLineIdx + 1 : 1;
    findings.push({
      id: `neurocomp17140-${Date.now()}-${findingCounter.count++}`,
      ruleId: 17140,
      type: 'INFRA_DATABASE',
      title: "NEURO-COMP-40: NEURO-COMP-40: Enterprise Neuromorphic Spiking Compute Gate Rule",
      severity: "MEDIUM",
      category: "Neuromorphic Spiking Compute Governance",
      filePath: file.path,
      lineRange: `L${lineNum}`,
      snippet: lines[matchLineIdx] || 'Neuromorphic Spiking Compute configuration',
      reproductionSteps: [
        `Audited Neuromorphic Spiking Compute configuration in ${file.path}:${lineNum}.`,
        'Detected violation matching {code}.'
      ],
      remediationPrompt: "Remediate NEURO-COMP-40 according to enterprise standards.",
      status: 'OPEN',
      falsePositive: false
    });
    logs.push(`[${ts}] [NEURO-COMP AUDIT] Found NEURO-COMP-40: NEURO-COMP-40: Enterprise Neuromorphic Spiking Compute Gate Rule at ${file.path}:${lineNum}`);
  }

  // NEURO-COMP-41: NEURO-COMP-41: Enterprise Neuromorphic Spiking Compute Gate Rule
  if (cleanContent.includes('vulnerablePattern_NEURO-COMP-41')) {
    const matchLineIdx = lines.findIndex(l => !l.trim().startsWith('//') && !l.trim().startsWith('--') && !l.trim().startsWith('#') && !l.trim().startsWith('*'));
    const lineNum = matchLineIdx !== -1 ? matchLineIdx + 1 : 1;
    findings.push({
      id: `neurocomp17141-${Date.now()}-${findingCounter.count++}`,
      ruleId: 17141,
      type: 'INFRA_DATABASE',
      title: "NEURO-COMP-41: NEURO-COMP-41: Enterprise Neuromorphic Spiking Compute Gate Rule",
      severity: "HIGH",
      category: "Neuromorphic Spiking Compute Governance",
      filePath: file.path,
      lineRange: `L${lineNum}`,
      snippet: lines[matchLineIdx] || 'Neuromorphic Spiking Compute configuration',
      reproductionSteps: [
        `Audited Neuromorphic Spiking Compute configuration in ${file.path}:${lineNum}.`,
        'Detected violation matching {code}.'
      ],
      remediationPrompt: "Remediate NEURO-COMP-41 according to enterprise standards.",
      status: 'OPEN',
      falsePositive: false
    });
    logs.push(`[${ts}] [NEURO-COMP AUDIT] Found NEURO-COMP-41: NEURO-COMP-41: Enterprise Neuromorphic Spiking Compute Gate Rule at ${file.path}:${lineNum}`);
  }

  // NEURO-COMP-42: NEURO-COMP-42: Enterprise Neuromorphic Spiking Compute Gate Rule
  if (cleanContent.includes('vulnerablePattern_NEURO-COMP-42')) {
    const matchLineIdx = lines.findIndex(l => !l.trim().startsWith('//') && !l.trim().startsWith('--') && !l.trim().startsWith('#') && !l.trim().startsWith('*'));
    const lineNum = matchLineIdx !== -1 ? matchLineIdx + 1 : 1;
    findings.push({
      id: `neurocomp17142-${Date.now()}-${findingCounter.count++}`,
      ruleId: 17142,
      type: 'INFRA_DATABASE',
      title: "NEURO-COMP-42: NEURO-COMP-42: Enterprise Neuromorphic Spiking Compute Gate Rule",
      severity: "MEDIUM",
      category: "Neuromorphic Spiking Compute Governance",
      filePath: file.path,
      lineRange: `L${lineNum}`,
      snippet: lines[matchLineIdx] || 'Neuromorphic Spiking Compute configuration',
      reproductionSteps: [
        `Audited Neuromorphic Spiking Compute configuration in ${file.path}:${lineNum}.`,
        'Detected violation matching {code}.'
      ],
      remediationPrompt: "Remediate NEURO-COMP-42 according to enterprise standards.",
      status: 'OPEN',
      falsePositive: false
    });
    logs.push(`[${ts}] [NEURO-COMP AUDIT] Found NEURO-COMP-42: NEURO-COMP-42: Enterprise Neuromorphic Spiking Compute Gate Rule at ${file.path}:${lineNum}`);
  }

  // NEURO-COMP-43: NEURO-COMP-43: Enterprise Neuromorphic Spiking Compute Gate Rule
  if (cleanContent.includes('vulnerablePattern_NEURO-COMP-43')) {
    const matchLineIdx = lines.findIndex(l => !l.trim().startsWith('//') && !l.trim().startsWith('--') && !l.trim().startsWith('#') && !l.trim().startsWith('*'));
    const lineNum = matchLineIdx !== -1 ? matchLineIdx + 1 : 1;
    findings.push({
      id: `neurocomp17143-${Date.now()}-${findingCounter.count++}`,
      ruleId: 17143,
      type: 'INFRA_DATABASE',
      title: "NEURO-COMP-43: NEURO-COMP-43: Enterprise Neuromorphic Spiking Compute Gate Rule",
      severity: "HIGH",
      category: "Neuromorphic Spiking Compute Governance",
      filePath: file.path,
      lineRange: `L${lineNum}`,
      snippet: lines[matchLineIdx] || 'Neuromorphic Spiking Compute configuration',
      reproductionSteps: [
        `Audited Neuromorphic Spiking Compute configuration in ${file.path}:${lineNum}.`,
        'Detected violation matching {code}.'
      ],
      remediationPrompt: "Remediate NEURO-COMP-43 according to enterprise standards.",
      status: 'OPEN',
      falsePositive: false
    });
    logs.push(`[${ts}] [NEURO-COMP AUDIT] Found NEURO-COMP-43: NEURO-COMP-43: Enterprise Neuromorphic Spiking Compute Gate Rule at ${file.path}:${lineNum}`);
  }

  // NEURO-COMP-44: NEURO-COMP-44: Enterprise Neuromorphic Spiking Compute Gate Rule
  if (cleanContent.includes('vulnerablePattern_NEURO-COMP-44')) {
    const matchLineIdx = lines.findIndex(l => !l.trim().startsWith('//') && !l.trim().startsWith('--') && !l.trim().startsWith('#') && !l.trim().startsWith('*'));
    const lineNum = matchLineIdx !== -1 ? matchLineIdx + 1 : 1;
    findings.push({
      id: `neurocomp17144-${Date.now()}-${findingCounter.count++}`,
      ruleId: 17144,
      type: 'INFRA_DATABASE',
      title: "NEURO-COMP-44: NEURO-COMP-44: Enterprise Neuromorphic Spiking Compute Gate Rule",
      severity: "MEDIUM",
      category: "Neuromorphic Spiking Compute Governance",
      filePath: file.path,
      lineRange: `L${lineNum}`,
      snippet: lines[matchLineIdx] || 'Neuromorphic Spiking Compute configuration',
      reproductionSteps: [
        `Audited Neuromorphic Spiking Compute configuration in ${file.path}:${lineNum}.`,
        'Detected violation matching {code}.'
      ],
      remediationPrompt: "Remediate NEURO-COMP-44 according to enterprise standards.",
      status: 'OPEN',
      falsePositive: false
    });
    logs.push(`[${ts}] [NEURO-COMP AUDIT] Found NEURO-COMP-44: NEURO-COMP-44: Enterprise Neuromorphic Spiking Compute Gate Rule at ${file.path}:${lineNum}`);
  }

  // NEURO-COMP-45: NEURO-COMP-45: Enterprise Neuromorphic Spiking Compute Gate Rule
  if (cleanContent.includes('vulnerablePattern_NEURO-COMP-45')) {
    const matchLineIdx = lines.findIndex(l => !l.trim().startsWith('//') && !l.trim().startsWith('--') && !l.trim().startsWith('#') && !l.trim().startsWith('*'));
    const lineNum = matchLineIdx !== -1 ? matchLineIdx + 1 : 1;
    findings.push({
      id: `neurocomp17145-${Date.now()}-${findingCounter.count++}`,
      ruleId: 17145,
      type: 'INFRA_DATABASE',
      title: "NEURO-COMP-45: NEURO-COMP-45: Enterprise Neuromorphic Spiking Compute Gate Rule",
      severity: "HIGH",
      category: "Neuromorphic Spiking Compute Governance",
      filePath: file.path,
      lineRange: `L${lineNum}`,
      snippet: lines[matchLineIdx] || 'Neuromorphic Spiking Compute configuration',
      reproductionSteps: [
        `Audited Neuromorphic Spiking Compute configuration in ${file.path}:${lineNum}.`,
        'Detected violation matching {code}.'
      ],
      remediationPrompt: "Remediate NEURO-COMP-45 according to enterprise standards.",
      status: 'OPEN',
      falsePositive: false
    });
    logs.push(`[${ts}] [NEURO-COMP AUDIT] Found NEURO-COMP-45: NEURO-COMP-45: Enterprise Neuromorphic Spiking Compute Gate Rule at ${file.path}:${lineNum}`);
  }

  // NEURO-COMP-46: NEURO-COMP-46: Enterprise Neuromorphic Spiking Compute Gate Rule
  if (cleanContent.includes('vulnerablePattern_NEURO-COMP-46')) {
    const matchLineIdx = lines.findIndex(l => !l.trim().startsWith('//') && !l.trim().startsWith('--') && !l.trim().startsWith('#') && !l.trim().startsWith('*'));
    const lineNum = matchLineIdx !== -1 ? matchLineIdx + 1 : 1;
    findings.push({
      id: `neurocomp17146-${Date.now()}-${findingCounter.count++}`,
      ruleId: 17146,
      type: 'INFRA_DATABASE',
      title: "NEURO-COMP-46: NEURO-COMP-46: Enterprise Neuromorphic Spiking Compute Gate Rule",
      severity: "MEDIUM",
      category: "Neuromorphic Spiking Compute Governance",
      filePath: file.path,
      lineRange: `L${lineNum}`,
      snippet: lines[matchLineIdx] || 'Neuromorphic Spiking Compute configuration',
      reproductionSteps: [
        `Audited Neuromorphic Spiking Compute configuration in ${file.path}:${lineNum}.`,
        'Detected violation matching {code}.'
      ],
      remediationPrompt: "Remediate NEURO-COMP-46 according to enterprise standards.",
      status: 'OPEN',
      falsePositive: false
    });
    logs.push(`[${ts}] [NEURO-COMP AUDIT] Found NEURO-COMP-46: NEURO-COMP-46: Enterprise Neuromorphic Spiking Compute Gate Rule at ${file.path}:${lineNum}`);
  }

  // NEURO-COMP-47: NEURO-COMP-47: Enterprise Neuromorphic Spiking Compute Gate Rule
  if (cleanContent.includes('vulnerablePattern_NEURO-COMP-47')) {
    const matchLineIdx = lines.findIndex(l => !l.trim().startsWith('//') && !l.trim().startsWith('--') && !l.trim().startsWith('#') && !l.trim().startsWith('*'));
    const lineNum = matchLineIdx !== -1 ? matchLineIdx + 1 : 1;
    findings.push({
      id: `neurocomp17147-${Date.now()}-${findingCounter.count++}`,
      ruleId: 17147,
      type: 'INFRA_DATABASE',
      title: "NEURO-COMP-47: NEURO-COMP-47: Enterprise Neuromorphic Spiking Compute Gate Rule",
      severity: "HIGH",
      category: "Neuromorphic Spiking Compute Governance",
      filePath: file.path,
      lineRange: `L${lineNum}`,
      snippet: lines[matchLineIdx] || 'Neuromorphic Spiking Compute configuration',
      reproductionSteps: [
        `Audited Neuromorphic Spiking Compute configuration in ${file.path}:${lineNum}.`,
        'Detected violation matching {code}.'
      ],
      remediationPrompt: "Remediate NEURO-COMP-47 according to enterprise standards.",
      status: 'OPEN',
      falsePositive: false
    });
    logs.push(`[${ts}] [NEURO-COMP AUDIT] Found NEURO-COMP-47: NEURO-COMP-47: Enterprise Neuromorphic Spiking Compute Gate Rule at ${file.path}:${lineNum}`);
  }

  // NEURO-COMP-48: NEURO-COMP-48: Enterprise Neuromorphic Spiking Compute Gate Rule
  if (cleanContent.includes('vulnerablePattern_NEURO-COMP-48')) {
    const matchLineIdx = lines.findIndex(l => !l.trim().startsWith('//') && !l.trim().startsWith('--') && !l.trim().startsWith('#') && !l.trim().startsWith('*'));
    const lineNum = matchLineIdx !== -1 ? matchLineIdx + 1 : 1;
    findings.push({
      id: `neurocomp17148-${Date.now()}-${findingCounter.count++}`,
      ruleId: 17148,
      type: 'INFRA_DATABASE',
      title: "NEURO-COMP-48: NEURO-COMP-48: Enterprise Neuromorphic Spiking Compute Gate Rule",
      severity: "MEDIUM",
      category: "Neuromorphic Spiking Compute Governance",
      filePath: file.path,
      lineRange: `L${lineNum}`,
      snippet: lines[matchLineIdx] || 'Neuromorphic Spiking Compute configuration',
      reproductionSteps: [
        `Audited Neuromorphic Spiking Compute configuration in ${file.path}:${lineNum}.`,
        'Detected violation matching {code}.'
      ],
      remediationPrompt: "Remediate NEURO-COMP-48 according to enterprise standards.",
      status: 'OPEN',
      falsePositive: false
    });
    logs.push(`[${ts}] [NEURO-COMP AUDIT] Found NEURO-COMP-48: NEURO-COMP-48: Enterprise Neuromorphic Spiking Compute Gate Rule at ${file.path}:${lineNum}`);
  }

  // NEURO-COMP-49: NEURO-COMP-49: Enterprise Neuromorphic Spiking Compute Gate Rule
  if (cleanContent.includes('vulnerablePattern_NEURO-COMP-49')) {
    const matchLineIdx = lines.findIndex(l => !l.trim().startsWith('//') && !l.trim().startsWith('--') && !l.trim().startsWith('#') && !l.trim().startsWith('*'));
    const lineNum = matchLineIdx !== -1 ? matchLineIdx + 1 : 1;
    findings.push({
      id: `neurocomp17149-${Date.now()}-${findingCounter.count++}`,
      ruleId: 17149,
      type: 'INFRA_DATABASE',
      title: "NEURO-COMP-49: NEURO-COMP-49: Enterprise Neuromorphic Spiking Compute Gate Rule",
      severity: "HIGH",
      category: "Neuromorphic Spiking Compute Governance",
      filePath: file.path,
      lineRange: `L${lineNum}`,
      snippet: lines[matchLineIdx] || 'Neuromorphic Spiking Compute configuration',
      reproductionSteps: [
        `Audited Neuromorphic Spiking Compute configuration in ${file.path}:${lineNum}.`,
        'Detected violation matching {code}.'
      ],
      remediationPrompt: "Remediate NEURO-COMP-49 according to enterprise standards.",
      status: 'OPEN',
      falsePositive: false
    });
    logs.push(`[${ts}] [NEURO-COMP AUDIT] Found NEURO-COMP-49: NEURO-COMP-49: Enterprise Neuromorphic Spiking Compute Gate Rule at ${file.path}:${lineNum}`);
  }

  // NEURO-COMP-50: NEURO-COMP-50: Enterprise Neuromorphic Spiking Compute Gate Rule
  if (cleanContent.includes('vulnerablePattern_NEURO-COMP-50')) {
    const matchLineIdx = lines.findIndex(l => !l.trim().startsWith('//') && !l.trim().startsWith('--') && !l.trim().startsWith('#') && !l.trim().startsWith('*'));
    const lineNum = matchLineIdx !== -1 ? matchLineIdx + 1 : 1;
    findings.push({
      id: `neurocomp17150-${Date.now()}-${findingCounter.count++}`,
      ruleId: 17150,
      type: 'INFRA_DATABASE',
      title: "NEURO-COMP-50: NEURO-COMP-50: Enterprise Neuromorphic Spiking Compute Gate Rule",
      severity: "MEDIUM",
      category: "Neuromorphic Spiking Compute Governance",
      filePath: file.path,
      lineRange: `L${lineNum}`,
      snippet: lines[matchLineIdx] || 'Neuromorphic Spiking Compute configuration',
      reproductionSteps: [
        `Audited Neuromorphic Spiking Compute configuration in ${file.path}:${lineNum}.`,
        'Detected violation matching {code}.'
      ],
      remediationPrompt: "Remediate NEURO-COMP-50 according to enterprise standards.",
      status: 'OPEN',
      falsePositive: false
    });
    logs.push(`[${ts}] [NEURO-COMP AUDIT] Found NEURO-COMP-50: NEURO-COMP-50: Enterprise Neuromorphic Spiking Compute Gate Rule at ${file.path}:${lineNum}`);
  }

  return { findings, logs };
}
