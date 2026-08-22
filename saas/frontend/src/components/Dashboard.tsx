import React, { useEffect, useState } from 'react';
import { Activity, ShieldCheck, Zap } from 'lucide-react';
import { useAuth } from '@clerk/clerk-react';
import { RuleCard } from './RuleCard';

export function Dashboard() {
  const { getToken } = useAuth();
  const API_BASE_URL = import.meta.env.VITE_API_BASE_URL || 'http://localhost:8000';
  const [rules, setRules] = useState<any[]>([]);
  const [health, setHealth] = useState({ average_health: 0, total_records: 0 });
  const [loading, setLoading] = useState(true);

  const fetchDashboardData = async () => {
    try {
      const token = await getToken();
      const headers = {
        'Authorization': `Bearer ${token}`
      };
      const [rulesRes, healthRes] = await Promise.all([
        fetch(`${API_BASE_URL}/api/v1/rules`, { headers }),
        fetch(`${API_BASE_URL}/api/v1/health`, { headers })
      ]);
      const rulesData = await rulesRes.json();
      const healthData = await healthRes.json();
      setRules(rulesData);
      setHealth(healthData);
    } catch (err) {
      console.error("Failed to fetch dashboard data", err);
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    fetchDashboardData();
  }, []);

  const handleDeploy = async (ruleId: string, confirmationId: string) => {
    const token = await getToken();
    const res = await fetch(`${API_BASE_URL}/api/v1/deployments`, {
      method: 'POST',
      headers: { 
        'Content-Type': 'application/json',
        'Authorization': `Bearer ${token}`
      },
      body: JSON.stringify({
        rule_id: ruleId,
        target_siem: 'splunk',
        confirmation_id: confirmationId
      })
    });
    const data = await res.json();
    if (!res.ok) {
      throw new Error(data.detail || 'Deployment failed');
    }
    return data;
  };

  if (loading) {
    return (
      <div className="flex items-center justify-center min-h-screen">
        <div className="animate-spin text-neonBlue">
          <Zap size={48} />
        </div>
      </div>
    );
  }

  return (
    <div className="max-w-7xl mx-auto px-4 py-8 space-y-8">
      {/* Header & Global Health */}
      <div className="glass-panel rounded-2xl p-8 flex flex-col md:flex-row items-center justify-between gap-6">
        <div>
          <h1 className="text-4xl font-black text-white tracking-tight flex items-center gap-3">
            <Zap className="text-neonBlue" size={36} />
            DRAVE <span className="text-gray-400 font-light">SaaS</span>
          </h1>
          <p className="text-gray-400 mt-2">Enterprise Detection Management</p>
        </div>
        
        <div className="flex gap-6">
          <div className="bg-surface/50 border border-white/5 rounded-xl p-4 min-w-[140px] text-center shadow-lg">
            <p className="text-gray-400 text-sm font-medium mb-1">Total Rules</p>
            <div className="text-3xl font-black text-white flex items-center justify-center gap-2">
              <ShieldCheck size={24} className="text-neonPurple" />
              {rules.length}
            </div>
          </div>
          
          <div className="bg-surface/50 border border-white/5 rounded-xl p-4 min-w-[140px] text-center shadow-[0_0_15px_rgba(57,255,20,0.1)]">
            <p className="text-gray-400 text-sm font-medium mb-1">Global Health</p>
            <div className="text-3xl font-black flex items-center justify-center gap-2 neon-text-green text-neonGreen">
              <Activity size={24} />
              {health.average_health.toFixed(1)}
            </div>
          </div>
        </div>
      </div>

      {/* Rules Grid */}
      <div>
        <h2 className="text-xl font-bold text-white mb-6 flex items-center gap-2">
          Active Detections
        </h2>
        <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-6">
          {rules.map(rule => (
            <RuleCard key={rule.id} rule={rule} onDeploy={handleDeploy} />
          ))}
          {rules.length === 0 && (
            <div className="col-span-full py-12 text-center text-gray-500 border border-dashed border-white/10 rounded-2xl">
              No detection rules found. CI/CD must ingest rules first.
            </div>
          )}
        </div>
      </div>
    </div>
  );
}
