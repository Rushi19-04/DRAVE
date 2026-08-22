import React, { useState } from 'react';
import { X, ShieldAlert, CheckCircle, AlertTriangle, Loader2 } from 'lucide-react';

interface DeploymentModalProps {
  ruleId: string;
  ruleName: string;
  onClose: () => void;
  onDeploy: (confirmationId: string) => Promise<any>;
}

export function DeploymentModal({ ruleId, ruleName, onClose, onDeploy }: DeploymentModalProps) {
  const [confirmation, setConfirmation] = useState('');
  const [loading, setLoading] = useState(false);
  const [result, setResult] = useState<{ status: string; detail?: string } | null>(null);

  const isMatch = confirmation === ruleId;

  const handleDeploy = async () => {
    if (!isMatch) return;
    setLoading(true);
    setResult(null);
    try {
      const response = await onDeploy(confirmation);
      setResult({ status: 'success' });
    } catch (err: any) {
      setResult({ status: 'error', detail: err.message || 'Deployment failed' });
    } finally {
      setLoading(false);
    }
  };

  return (
    <div className="fixed inset-0 z-50 flex items-center justify-center bg-black/60 backdrop-blur-sm p-4">
      <div className="glass-panel w-full max-w-lg rounded-2xl overflow-hidden animate-in fade-in zoom-in duration-300">
        
        {/* Header */}
        <div className="flex items-center justify-between p-6 border-b border-white/10 bg-surface/50">
          <div className="flex items-center gap-3">
            <div className="p-2 bg-neonRed/10 text-neonRed rounded-lg">
              <ShieldAlert size={24} />
            </div>
            <h2 className="text-xl font-bold text-white tracking-wide">Tier 3 Deployment Gate</h2>
          </div>
          <button onClick={onClose} className="text-gray-400 hover:text-white transition-colors" disabled={loading}>
            <X size={24} />
          </button>
        </div>

        {/* Body */}
        <div className="p-6 space-y-6">
          
          {result?.status === 'success' ? (
            <div className="flex flex-col items-center justify-center text-center space-y-4 py-8">
              <div className="w-16 h-16 rounded-full bg-neonGreen/10 flex items-center justify-center text-neonGreen">
                <CheckCircle size={32} />
              </div>
              <h3 className="text-2xl font-bold text-white neon-text-green">Deployment Successful</h3>
              <p className="text-gray-300">The detection rule is now live.</p>
              <button 
                onClick={onClose}
                className="mt-4 px-6 py-2 bg-white/10 hover:bg-white/20 text-white rounded-lg transition-colors font-medium"
              >
                Close
              </button>
            </div>
          ) : (
            <>
              <div className="bg-red-500/10 border border-red-500/20 rounded-xl p-4 flex gap-3 text-red-200">
                <AlertTriangle className="shrink-0 text-neonRed" />
                <div className="text-sm">
                  <p className="font-semibold text-white mb-1">Safety Critical Action</p>
                  <p>Deploying <span className="font-mono text-neonBlue bg-black/30 px-1 rounded">{ruleName}</span> to the live SIEM environment. This action requires explicit manual confirmation.</p>
                </div>
              </div>

              {result?.status === 'error' && (
                <div className="bg-red-500/10 border border-red-500/20 rounded-xl p-3 text-red-400 text-sm">
                  Error: {result.detail}
                </div>
              )}

              <div className="space-y-2">
                <label className="block text-sm font-medium text-gray-300">
                  Type the exact Detection ID to confirm:
                </label>
                <div className="p-3 bg-black/40 border border-white/5 rounded-lg text-xs font-mono text-gray-400 select-all">
                  {ruleId}
                </div>
                <input
                  type="text"
                  value={confirmation}
                  onChange={(e) => setConfirmation(e.target.value)}
                  placeholder="Paste Detection ID here..."
                  disabled={loading}
                  data-testid="confirmation-input"
                  className="w-full mt-2 bg-surface border border-white/10 rounded-lg p-3 text-white focus:outline-none focus:border-neonBlue focus:ring-1 focus:ring-neonBlue transition-all"
                />
              </div>

              <div className="flex justify-end gap-3 pt-4">
                <button
                  onClick={onClose}
                  disabled={loading}
                  className="px-5 py-2.5 rounded-lg text-sm font-medium text-gray-300 hover:text-white hover:bg-white/5 transition-colors"
                >
                  Cancel
                </button>
                <button
                  onClick={handleDeploy}
                  disabled={!isMatch || loading}
                  data-testid="deploy-button"
                  className={`px-5 py-2.5 rounded-lg text-sm font-medium flex items-center gap-2 transition-all duration-300
                    ${isMatch 
                      ? 'bg-neonRed text-white hover:bg-red-500 shadow-[0_0_15px_rgba(255,0,60,0.5)]' 
                      : 'bg-white/5 text-gray-500 cursor-not-allowed'
                    }
                  `}
                >
                  {loading && <Loader2 size={16} className="animate-spin" />}
                  {loading ? 'Deploying...' : 'Confirm Deployment'}
                </button>
              </div>
            </>
          )}

        </div>
      </div>
    </div>
  );
}
