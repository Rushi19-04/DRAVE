import React from "react";
import { CheckCircle2, XCircle, Clock, AlertCircle } from "lucide-react";

interface EvidenceReport {
  tests_passed: number;
  tests_total: number;
  schema_risk: string | null;
  schema_compatibility_pct: number | null;
  robustness_score: number | null;
  gates: {
    passed_all_gates: boolean;
    syntax_valid: boolean;
    all_required_tests_pass: boolean;
    no_critical_schema_incompatibility: boolean;
    volume_within_policy: boolean;
    no_known_attack_missed: boolean;
  };
  volume_status?: string | null;
  volume_message?: string | null;
  attack_expected?: number | null;
  attack_missed?: number | null;
  regression_total?: number | null;
  regressions_found?: number | null;
}

interface PipelineStageViewProps {
  evidence: EvidenceReport | undefined;
}

interface StageConfig {
  name: string;
  status: 'passed' | 'failed' | 'pending' | 'skipped';
  details: string;
}

export const PipelineStageView: React.FC<PipelineStageViewProps> = ({ evidence }) => {
  if (!evidence) {
    return (
      <div className="flex items-center gap-2 text-gray-500 text-sm italic">
        <Clock className="w-4 h-4" /> No CI Pipeline Data Available
      </div>
    );
  }

  const stages: StageConfig[] = [];

  // Syntax
  stages.push({
    name: "Syntax",
    status: evidence.gates.syntax_valid ? "passed" : "failed",
    details: evidence.gates.syntax_valid ? "Valid Sigma" : "Invalid YAML/Sigma syntax"
  });

  // Schema
  stages.push({
    name: "Schema",
    status: evidence.gates.no_critical_schema_incompatibility ? "passed" : "failed",
    details: `Compatibility: ${evidence.schema_compatibility_pct}% (Risk: ${evidence.schema_risk})`
  });

  // Unit Tests
  const hasTests = evidence.tests_total > 0;
  stages.push({
    name: "Unit Tests",
    status: hasTests ? (evidence.tests_passed === evidence.tests_total ? "passed" : "failed") : "skipped",
    details: hasTests ? `${evidence.tests_passed} / ${evidence.tests_total} passed` : "No unit tests found"
  });

  // Regression
  stages.push({
    name: "Regression",
    status: evidence.regression_total !== undefined && evidence.regression_total !== null
      ? (evidence.regressions_found === 0 ? "passed" : "failed")
      : "skipped",
    details: evidence.regression_total ? `Found ${evidence.regressions_found} regressions` : "Not evaluated"
  });

  // Attack Replay
  stages.push({
    name: "Attack Replay",
    status: evidence.attack_expected !== undefined && evidence.attack_expected !== null
      ? (evidence.attack_missed === 0 ? "passed" : "failed")
      : "skipped",
    details: evidence.attack_expected ? `Missed ${evidence.attack_missed} out of ${evidence.attack_expected}` : "No attack scenarios"
  });

  // Robustness
  stages.push({
    name: "Robustness",
    status: evidence.robustness_score !== null && evidence.robustness_score !== undefined
      ? (evidence.robustness_score > 0 ? "passed" : "failed")
      : "skipped",
    details: evidence.robustness_score !== null ? `Variation coverage: ${(evidence.robustness_score * 100).toFixed(0)}%` : "No variations"
  });

  // Volume
  stages.push({
    name: "Volume",
    status: evidence.volume_status ? (evidence.volume_status === "PASS" ? "passed" : (evidence.volume_status === "FAIL" ? "failed" : "pending")) : "skipped",
    details: evidence.volume_message || "Not evaluated"
  });

  // Gates
  stages.push({
    name: "Deploy Gates",
    status: evidence.gates.passed_all_gates ? "passed" : "failed",
    details: evidence.gates.passed_all_gates ? "CLEARED" : "BLOCKED"
  });

  return (
    <div className="w-full flex items-center overflow-x-auto py-4 px-2 space-x-1">
      {stages.map((stage, idx) => {
        let Icon = CheckCircle2;
        let colorClass = "text-green-500";
        let bgClass = "bg-green-500/10";
        let borderClass = "border-green-500/30";

        if (stage.status === 'failed') {
          Icon = XCircle;
          colorClass = "text-red-500";
          bgClass = "bg-red-500/10";
          borderClass = "border-red-500/30";
        } else if (stage.status === 'pending') {
          Icon = AlertCircle;
          colorClass = "text-yellow-500";
          bgClass = "bg-yellow-500/10";
          borderClass = "border-yellow-500/30";
        } else if (stage.status === 'skipped') {
          Icon = Clock;
          colorClass = "text-gray-500";
          bgClass = "bg-gray-800";
          borderClass = "border-gray-700";
        }

        return (
          <React.Fragment key={stage.name}>
            <div className={`relative flex flex-col items-center justify-center min-w-[90px] group cursor-pointer p-2 rounded border ${bgClass} ${borderClass} hover:bg-opacity-20 transition-all`}>
              <Icon className={`w-5 h-5 mb-1 ${colorClass}`} />
              <span className={`text-[10px] font-medium uppercase tracking-wider text-center ${colorClass}`}>
                {stage.name}
              </span>
              
              {/* Tooltip on Hover */}
              <div className="absolute bottom-full mb-2 hidden group-hover:block w-max max-w-[200px] z-10 bg-gray-900 border border-gray-700 text-xs text-gray-200 p-2 rounded shadow-xl">
                <span className="font-bold block mb-1">{stage.name}</span>
                {stage.details}
              </div>
            </div>
            
            {/* Connector Line */}
            {idx < stages.length - 1 && (
              <div className="w-6 h-px bg-gray-700 flex-shrink-0" />
            )}
          </React.Fragment>
        );
      })}
    </div>
  );
};
