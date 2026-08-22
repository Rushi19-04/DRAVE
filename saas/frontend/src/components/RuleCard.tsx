import React, { useState } from 'react';
import { Shield, Activity, Calendar, Terminal } from 'lucide-react';
import { DeploymentModal } from './DeploymentModal';

interface RuleCardProps {
  rule: any;
  onDeploy: (ruleId: string, confirmationId: string) => Promise<any>;
}

export function RuleCard({ rule, onDeploy }: RuleCardProps) {
  const [showDeploy, setShowDeploy] = useState(false);

  // Derive styling based on health score (mocked safely if not available)
  const healthScore = rule.health_score || 0;
  const isHealthy = healthScore >= 80;
  const healthColor = isHealthy ? 'text-neonGreen' : (healthScore >= 50 ? 'text-yellow-400' : 'text-neonRed');
  const healthGlow = isHealthy ? 'shadow-[0_0_10px_rgba(57,255,20,0.2)]' : '';

  return (
    <>
      <div className={`glass-card p-5 flex flex-col h-full group ${healthGlow}`}>
        
        {/* Header */}
        <div className="flex justify-between items-start mb-4">
          <div className="flex items-center gap-3">
            <div className={`p-2 rounded-lg bg-surface border border-white/5 ${healthColor}`}>
              <Shield size={20} />
            </div>
            <div>
              <h3 className="font-bold text-white text-lg group-hover:text-neonBlue transition-colors line-clamp-1" title={rule.name}>
                {rule.name}
              </h3>
              <p className="text-xs text-gray-400 font-mono flex items-center gap-1 mt-1">
                <Terminal size={12} /> {rule.platform} | {rule.language}
              </p>
            </div>
          </div>
          <div className={`text-xl font-black ${healthColor}`}>
            {healthScore.toFixed(0)}
          </div>
        </div>

        {/* Body */}
        <div className="flex-1">
          <p className="text-sm text-gray-300 line-clamp-3 mb-4">
            {rule.description}
          </p>
          <div className="flex flex-wrap gap-2 mb-4">
            <span className="px-2 py-1 text-[10px] uppercase font-bold tracking-wider rounded bg-red-500/10 text-red-400 border border-red-500/20">
              Severity: {rule.severity}
            </span>
            {rule.tags && rule.tags.slice(0, 2).map((tag: string) => (
              <span key={tag} className="px-2 py-1 text-[10px] rounded bg-white/5 text-gray-300 border border-white/10">
                {tag}
              </span>
            ))}
          </div>
        </div>

        {/* Footer */}
        <div className="pt-4 border-t border-white/5 flex items-center justify-between mt-auto">
          <div className="text-xs text-gray-500 flex items-center gap-1">
            <Calendar size={12} />
            {new Date(rule.created_at).toLocaleDateString()}
          </div>
          <button 
            onClick={() => setShowDeploy(true)}
            className="px-4 py-1.5 bg-neonBlue/10 hover:bg-neonBlue text-neonBlue hover:text-black hover:shadow-[0_0_15px_rgba(0,240,255,0.6)] rounded-lg text-sm font-bold transition-all duration-300"
          >
            Deploy
          </button>
        </div>
      </div>

      {showDeploy && (
        <DeploymentModal
          ruleId={rule.id}
          ruleName={rule.name}
          onClose={() => setShowDeploy(false)}
          onDeploy={(cid) => onDeploy(rule.id, cid)}
        />
      )}
    </>
  );
}
