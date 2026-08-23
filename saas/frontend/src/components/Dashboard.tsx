import { useEffect, useState } from 'react';
import { Zap, Plus, Settings as SettingsIcon, LayoutDashboard } from 'lucide-react';
import { useAuth, UserButton } from '@clerk/clerk-react';
import { CreateRuleModal } from './CreateRuleModal';
import { Settings } from './Settings';
import { PipelineStageView } from './PipelineStageView';
import { DeploymentModal } from './DeploymentModal';

export function Dashboard() {
  const { getToken } = useAuth();
  const API_BASE_URL = import.meta.env.VITE_API_BASE_URL || 'http://localhost:8000';
  const [rules, setRules] = useState<any[]>([]);
  const [health, setHealth] = useState({ average_health: 0, total_records: 0 });
  const [loading, setLoading] = useState(true);
  const [isCreateModalOpen, setIsCreateModalOpen] = useState(false);
  const [activeTab, setActiveTab] = useState<'rules' | 'settings'>('rules');
  const [selectedDeployRule, setSelectedDeployRule] = useState<any | null>(null);

  const loadData = async () => {
    try {
      const token = await getToken();
      const headers = { 'Authorization': `Bearer ${token}` };
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
    loadData();
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
      <div className="flex items-center justify-center min-h-screen bg-gray-950">
        <div className="animate-spin text-blue-500">
          <Zap size={48} />
        </div>
      </div>
    );
  }

  return (
    <div className="flex h-screen bg-gray-950 text-gray-200 font-sans overflow-hidden">
      {/* Sidebar */}
      <aside className="w-64 bg-gray-900 border-r border-gray-800 flex flex-col">
        <div className="p-6 flex items-center gap-3 border-b border-gray-800">
          <Zap className="text-blue-500" size={28} />
          <h1 className="text-xl font-black text-white tracking-tight">DRAVE <span className="text-gray-500 font-light">SaaS</span></h1>
        </div>
        
        <nav className="flex-1 p-4 space-y-2">
          <button 
            onClick={() => setActiveTab('rules')}
            className={`w-full flex items-center gap-3 px-4 py-3 rounded-lg text-sm font-medium transition-colors ${activeTab === 'rules' ? 'bg-blue-600/10 text-blue-400 border border-blue-500/20' : 'text-gray-400 hover:text-gray-200 hover:bg-gray-800'}`}
          >
            <LayoutDashboard size={18} />
            Detections
          </button>
          <button 
            onClick={() => setActiveTab('settings')}
            className={`w-full flex items-center gap-3 px-4 py-3 rounded-lg text-sm font-medium transition-colors ${activeTab === 'settings' ? 'bg-blue-600/10 text-blue-400 border border-blue-500/20' : 'text-gray-400 hover:text-gray-200 hover:bg-gray-800'}`}
          >
            <SettingsIcon size={18} />
            API Keys & Integrations
          </button>
        </nav>
        
        <div className="p-4 border-t border-gray-800 flex items-center justify-between">
          <div className="flex items-center gap-3 text-sm">
            <div className="w-8 h-8 rounded-full bg-gray-800 border border-gray-700 overflow-hidden flex items-center justify-center">
              <UserButton appearance={{ elements: { userButtonAvatarBox: "w-full h-full" } }} />
            </div>
            <span className="font-medium text-gray-300">Workspace</span>
          </div>
        </div>
      </aside>

      {/* Main Content */}
      <main className="flex-1 flex flex-col overflow-hidden">
        {/* Topbar */}
        <header className="h-16 border-b border-gray-800 bg-gray-900/50 flex items-center justify-between px-8">
          <h2 className="text-lg font-semibold text-white flex items-center gap-2">
            {activeTab === 'rules' ? 'Active Detections' : 'Settings'}
          </h2>
          
          {activeTab === 'rules' && (
            <div className="flex gap-4">
              <div className="flex items-center gap-2 bg-gray-800 border border-gray-700 rounded-md px-3 py-1">
                <span className="text-xs text-gray-400 font-medium">Health</span>
                <span className="text-sm font-bold text-green-400">{health.average_health.toFixed(1)}</span>
              </div>
              <button 
                onClick={() => setIsCreateModalOpen(true)}
                className="flex items-center gap-2 bg-blue-600 hover:bg-blue-500 text-white px-4 py-1.5 rounded-md text-sm font-medium transition-all"
              >
                <Plus size={16} /> New Rule
              </button>
            </div>
          )}
        </header>

        {/* Content Area */}
        <div className="flex-1 overflow-y-auto p-8 bg-[#0a0a0c]">
          {activeTab === 'settings' ? (
            <div className="max-w-4xl">
              <Settings />
            </div>
          ) : (
            <div className="w-full">
              {rules.length === 0 ? (
                <div className="py-20 text-center text-gray-500 border border-dashed border-gray-700 rounded-lg">
                  No detection rules found. Create one or push via CI.
                </div>
              ) : (
                <div className="flex flex-col gap-4">
                  {rules.map(rule => {
                    const severityColors: any = {
                      high: "text-red-400 bg-red-400/10 border-red-400/20",
                      medium: "text-orange-400 bg-orange-400/10 border-orange-400/20",
                      low: "text-blue-400 bg-blue-400/10 border-blue-400/20",
                      critical: "text-purple-400 bg-purple-400/10 border-purple-400/20"
                    };
                    const sevStyle = severityColors[rule.severity?.toLowerCase()] || "text-gray-400 bg-gray-400/10 border-gray-400/20";
                    
                    return (
                      <div key={rule.id} className="bg-gray-900 border border-gray-800 rounded-lg p-5 flex flex-col xl:flex-row xl:items-center gap-6 shadow-sm hover:border-gray-700 transition-colors">
                        {/* Rule Info */}
                        <div className="flex-1 min-w-[300px]">
                          <div className="flex items-center gap-3 mb-2">
                            <h3 className="text-lg font-bold text-gray-100">{rule.name}</h3>
                            <span className={`px-2 py-0.5 rounded text-[10px] font-bold uppercase tracking-wider border ${sevStyle}`}>
                              {rule.severity}
                            </span>
                          </div>
                          <p className="text-gray-400 text-sm mb-3">ID: <code className="text-gray-500 font-mono text-xs">{rule.id}</code></p>
                          <div className="flex items-center gap-2">
                            {rule.attack_mappings?.map((m: string) => (
                              <span key={m} className="px-2 py-1 bg-gray-800 border border-gray-700 rounded text-xs text-gray-300 font-mono">
                                {m}
                              </span>
                            ))}
                          </div>
                        </div>

                        {/* Pipeline Stage View */}
                        <div className="flex-2 w-full xl:w-auto xl:min-w-[600px] overflow-x-auto">
                          <PipelineStageView evidence={rule.evidence_report} />
                        </div>

                        {/* Actions */}
                        <div className="flex xl:flex-col items-center justify-end gap-3 min-w-[120px]">
                           <button
                             onClick={() => setSelectedDeployRule(rule)}
                             className="w-full bg-gray-800 hover:bg-gray-700 border border-gray-700 hover:border-gray-600 text-white px-4 py-2 rounded text-sm font-medium transition-colors"
                           >
                             Deploy
                           </button>
                           <button className="w-full bg-transparent hover:bg-gray-800 text-gray-400 hover:text-white px-4 py-2 rounded text-sm font-medium transition-colors border border-transparent">
                             View JSON
                           </button>
                        </div>
                      </div>
                    );
                  })}
                </div>
              )}
            </div>
          )}
        </div>
      </main>

      {/* Modals */}
      {isCreateModalOpen && (
        <CreateRuleModal 
          apiBaseUrl={API_BASE_URL}
          onClose={() => setIsCreateModalOpen(false)}
          onSuccess={() => {
            setIsCreateModalOpen(false);
            loadData();
          }}
        />
      )}

      {selectedDeployRule && (
        <DeploymentModal
          ruleId={selectedDeployRule.id}
          ruleName={selectedDeployRule.name}
          onClose={() => setSelectedDeployRule(null)}
          onDeploy={(confirmationId: string) => handleDeploy(selectedDeployRule.id, confirmationId)}
        />
      )}
    </div>
  );
}
