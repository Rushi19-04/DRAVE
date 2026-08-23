import { useEffect, useState } from 'react';
import { Zap, Plus, Settings as SettingsIcon, LayoutDashboard, Activity, Search, Filter, ShieldCheck, ShieldAlert, GitBranch } from 'lucide-react';
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
  const [activeTab, setActiveTab] = useState<'rules' | 'runs' | 'settings'>('rules');
  const [selectedDeployRule, setSelectedDeployRule] = useState<any | null>(null);

  // Filter States
  const [search, setSearch] = useState("");
  const [filterSeverity, setFilterSeverity] = useState("All");
  const [filterPlatform, setFilterPlatform] = useState("All");
  const [filterGate, setFilterGate] = useState("All");
  const [filterAttack, setFilterAttack] = useState("All");

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
      
      if (rulesRes.ok && Array.isArray(rulesData)) {
        setRules(rulesData);
      } else {
        console.error("Failed to load rules:", rulesData);
        setRules([]);
      }
      
      if (healthRes.ok) {
        setHealth(healthData);
      }
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

  // Derived Filter Data
  const uniqueAttacks = Array.from(new Set(rules.flatMap(r => r.attack_mappings || []))).sort();
  const uniquePlatforms = Array.from(new Set(rules.map(r => r.platform || "Unknown"))).sort();

  // Summary Stats
  const totalRules = rules.length;
  const clearedGates = rules.filter(r => r.evidence_report?.gates?.passed_all_gates === true).length;
  const blockedGates = rules.filter(r => r.evidence_report && r.evidence_report.gates?.passed_all_gates === false).length;

  // Filtered Rules
  const filteredRules = rules.filter(r => {
    if (search && !r.name.toLowerCase().includes(search.toLowerCase()) && !r.id.toLowerCase().includes(search.toLowerCase())) return false;
    if (filterSeverity !== "All" && r.severity?.toLowerCase() !== filterSeverity.toLowerCase()) return false;
    if (filterPlatform !== "All" && r.platform?.toLowerCase() !== filterPlatform.toLowerCase()) return false;
    
    if (filterAttack !== "All") {
      const mappings = r.attack_mappings || [];
      if (!mappings.some((m: string) => m.toLowerCase().includes(filterAttack.toLowerCase()))) return false;
    }

    if (filterGate !== "All") {
      const passed = r.evidence_report?.gates?.passed_all_gates;
      if (filterGate === "Cleared" && passed !== true) return false;
      if (filterGate === "Blocked" && passed !== false) return false;
    }

    return true;
  });

  return (
    <div className="flex h-screen bg-gray-950 text-gray-200 font-sans overflow-hidden">
      {/* Sidebar */}
      <aside className="w-64 bg-gray-900 border-r border-gray-800 flex flex-col z-20 shrink-0">
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
            onClick={() => setActiveTab('runs')}
            className={`w-full flex items-center gap-3 px-4 py-3 rounded-lg text-sm font-medium transition-colors ${activeTab === 'runs' ? 'bg-blue-600/10 text-blue-400 border border-blue-500/20' : 'text-gray-400 hover:text-gray-200 hover:bg-gray-800'}`}
          >
            <GitBranch size={18} />
            Pipeline Runs
          </button>
          <button 
            onClick={() => setActiveTab('settings')}
            className={`w-full flex items-center gap-3 px-4 py-3 rounded-lg text-sm font-medium transition-colors ${activeTab === 'settings' ? 'bg-blue-600/10 text-blue-400 border border-blue-500/20' : 'text-gray-400 hover:text-gray-200 hover:bg-gray-800'}`}
          >
            <SettingsIcon size={18} />
            API Keys & Integrations
          </button>
        </nav>
      </aside>

      {/* Main Content */}
      <main className="flex-1 flex flex-col min-w-0 overflow-hidden relative">
        {/* Topbar */}
        <header className="h-16 border-b border-gray-800 bg-gray-900/50 flex items-center justify-between px-8 z-10 shrink-0">
          <h2 className="text-lg font-semibold text-white flex items-center gap-2">
            {activeTab === 'rules' && 'Active Detections'}
            {activeTab === 'runs' && 'Pipeline Runs'}
            {activeTab === 'settings' && 'Settings'}
          </h2>
          
          <div className="flex gap-4 items-center">
            {activeTab === 'rules' && (
              <div className="relative group">
                <button 
                  disabled
                  className="flex items-center gap-2 bg-gray-800 text-gray-500 px-4 py-1.5 rounded-md text-sm font-medium whitespace-nowrap cursor-not-allowed border border-gray-700"
                >
                  <Plus size={16} /> New Rule
                </button>
                <div className="absolute top-full mt-2 right-0 hidden group-hover:block w-[240px] z-50 bg-gray-900 border border-gray-700 text-xs text-gray-300 p-3 rounded-lg shadow-xl text-left leading-relaxed">
                  <span className="font-bold text-white block mb-1">UI Authoring Disabled</span>
                  Rules must be authored via Git to ensure CI/CD validation. Open a PR to <code className="bg-gray-800 text-gray-200 px-1 py-0.5 rounded text-[10px]">main</code> to add new detections.
                </div>
              </div>
            )}
            <div className="w-8 h-8 rounded-full bg-gray-800 border border-gray-700 overflow-hidden flex items-center justify-center">
              <UserButton appearance={{ elements: { userButtonAvatarBox: "w-full h-full" } }} />
            </div>
          </div>
        </header>

        {/* Content Area */}
        <div className="flex-1 overflow-y-auto bg-[#0a0a0c]">
          {activeTab === 'settings' && (
            <div className="p-8 max-w-4xl">
              <Settings />
            </div>
          )}

          {activeTab === 'runs' && (
            <div className="p-8 h-full flex flex-col items-center justify-center text-gray-500">
              <GitBranch size={64} className="mb-4 opacity-20" />
              <h2 className="text-2xl font-bold text-gray-300 mb-2">Pipeline Runs</h2>
              <p>Historical CI execution logs coming soon.</p>
            </div>
          )}

          {activeTab === 'rules' && (
            <div className="p-8 w-full max-w-[1600px] mx-auto flex flex-col gap-6 pb-24">
              
              {/* Summary Header */}
              <div className="grid grid-cols-1 md:grid-cols-4 gap-4">
                <div className="bg-gray-900 border border-gray-800 p-4 rounded-lg flex items-center justify-between">
                  <div>
                    <p className="text-sm text-gray-400 font-medium mb-1">Total Rules</p>
                    <p className="text-3xl font-bold text-white">{totalRules}</p>
                  </div>
                  <div className="w-12 h-12 bg-blue-500/10 rounded-full flex items-center justify-center text-blue-500">
                    <LayoutDashboard size={24} />
                  </div>
                </div>
                
                <div className="bg-gray-900 border border-gray-800 p-4 rounded-lg flex items-center justify-between">
                  <div>
                    <p className="text-sm text-gray-400 font-medium mb-1">Avg Health Score</p>
                    <p className="text-3xl font-bold text-green-400">{health.average_health.toFixed(1)}</p>
                  </div>
                  <div className="w-12 h-12 bg-green-500/10 rounded-full flex items-center justify-center text-green-500">
                    <Activity size={24} />
                  </div>
                </div>

                <div className="bg-gray-900 border border-gray-800 p-4 rounded-lg flex items-center justify-between">
                  <div>
                    <p className="text-sm text-gray-400 font-medium mb-1">Cleared Gates</p>
                    <p className="text-3xl font-bold text-gray-200">{clearedGates}</p>
                  </div>
                  <div className="w-12 h-12 bg-emerald-500/10 rounded-full flex items-center justify-center text-emerald-500">
                    <ShieldCheck size={24} />
                  </div>
                </div>

                <div className="bg-gray-900 border border-gray-800 p-4 rounded-lg flex items-center justify-between">
                  <div>
                    <p className="text-sm text-gray-400 font-medium mb-1">Blocked Gates</p>
                    <p className="text-3xl font-bold text-gray-200">{blockedGates}</p>
                  </div>
                  <div className="w-12 h-12 bg-red-500/10 rounded-full flex items-center justify-center text-red-500">
                    <ShieldAlert size={24} />
                  </div>
                </div>
              </div>

              {/* Filter Bar */}
              <div className="bg-gray-900 border border-gray-800 rounded-lg p-3 flex flex-wrap gap-3 items-center sticky top-0 z-20 shadow-xl shadow-gray-950/20">
                <div className="flex-1 min-w-[200px] relative">
                  <Search className="absolute left-3 top-1/2 -translate-y-1/2 text-gray-500 w-4 h-4" />
                  <input 
                    type="text" 
                    placeholder="Search by name or ID..."
                    value={search}
                    onChange={e => setSearch(e.target.value)}
                    className="w-full bg-gray-950 border border-gray-800 rounded-md py-1.5 pl-9 pr-3 text-sm text-gray-200 focus:outline-none focus:border-blue-500 transition-colors"
                  />
                </div>
                
                <div className="flex items-center gap-2">
                  <Filter className="text-gray-500 w-4 h-4" />
                  <select 
                    value={filterSeverity} 
                    onChange={e => setFilterSeverity(e.target.value)}
                    className="bg-gray-950 border border-gray-800 rounded-md py-1.5 px-3 text-sm text-gray-300 focus:outline-none focus:border-blue-500"
                  >
                    <option value="All">All Severities</option>
                    <option value="critical">Critical</option>
                    <option value="high">High</option>
                    <option value="medium">Medium</option>
                    <option value="low">Low</option>
                  </select>

                  <select 
                    value={filterGate} 
                    onChange={e => setFilterGate(e.target.value)}
                    className="bg-gray-950 border border-gray-800 rounded-md py-1.5 px-3 text-sm text-gray-300 focus:outline-none focus:border-blue-500"
                  >
                    <option value="All">All Gate Status</option>
                    <option value="Cleared">Cleared</option>
                    <option value="Blocked">Blocked</option>
                  </select>

                  <select 
                    value={filterPlatform} 
                    onChange={e => setFilterPlatform(e.target.value)}
                    className="bg-gray-950 border border-gray-800 rounded-md py-1.5 px-3 text-sm text-gray-300 focus:outline-none focus:border-blue-500 max-w-[140px]"
                  >
                    <option value="All">All Platforms</option>
                    {uniquePlatforms.map(p => <option key={p as string} value={p as string}>{p as string}</option>)}
                  </select>

                  <select 
                    value={filterAttack} 
                    onChange={e => setFilterAttack(e.target.value)}
                    className="bg-gray-950 border border-gray-800 rounded-md py-1.5 px-3 text-sm text-gray-300 focus:outline-none focus:border-blue-500 max-w-[160px]"
                  >
                    <option value="All">All Techniques</option>
                    {uniqueAttacks.map(a => <option key={a as string} value={a as string}>{a as string}</option>)}
                  </select>
                </div>
              </div>

              {/* Dense List View */}
              <div className="w-full bg-gray-900 border border-gray-800 rounded-lg overflow-x-auto">
                <div className="min-w-[1100px]">
                  {filteredRules.length === 0 ? (
                    <div className="py-20 text-center text-gray-500">
                      No rules match the current filters.
                    </div>
                  ) : (
                    <div className="flex flex-col">
                      {/* Header Row */}
                      <div className="flex items-center gap-4 px-6 py-3 border-b border-gray-800 bg-gray-900/80 text-xs font-semibold text-gray-400 uppercase tracking-wider sticky top-[68px] z-10 shadow-sm backdrop-blur-md">
                        <div className="w-[30%] min-w-[250px]">Rule Details</div>
                        <div className="flex-1 min-w-[650px] text-center">Pipeline Stages</div>
                        <div className="w-[20%] min-w-[200px] text-right">Deployment</div>
                      </div>

                      {/* Rule Rows */}
                      <div className="flex flex-col">
                        {filteredRules.map((rule, idx) => {
                          const severityColors: Record<string, string> = {
                            high: "text-red-400 bg-red-400/10 border-red-400/20",
                            medium: "text-orange-400 bg-orange-400/10 border-orange-400/20",
                            low: "text-blue-400 bg-blue-400/10 border-blue-400/20",
                            critical: "text-purple-400 bg-purple-400/10 border-purple-400/20"
                          };
                          const sevStyle = severityColors[rule.severity?.toLowerCase()] || "text-gray-400 bg-gray-400/10 border-gray-400/20";
                          const isLast = idx === filteredRules.length - 1;
                          
                          // Parse last synced time
                          let lastSyncedStr = "Never";
                          if (rule.evidence_report && Object.keys(rule.evidence_report).length > 0) {
                            lastSyncedStr = new Date(rule.updated_at).toLocaleString(undefined, {
                              month: 'short', day: 'numeric', hour: '2-digit', minute: '2-digit'
                            });
                          }
                          
                          return (
                            <div key={rule.id} className={`relative flex items-center gap-4 px-6 py-3 hover:bg-gray-800/50 hover:z-30 transition-all ${isLast ? '' : 'border-b border-gray-800/50'}`}>
                              {/* Left: Rule Info */}
                              <div className="w-[30%] min-w-[250px] flex flex-col justify-center">
                                <div className="flex items-center gap-2 mb-1.5">
                                  <h3 className="text-sm font-bold text-gray-100 truncate" title={rule.name}>{rule.name}</h3>
                                  <span className={`shrink-0 px-1.5 py-0.5 rounded text-[9px] font-bold uppercase tracking-wider border ${sevStyle}`}>
                                    {rule.severity}
                                  </span>
                                </div>
                                <p className="text-gray-500 font-mono text-[10px] mb-2 truncate" title={rule.id}>{rule.id}</p>
                                <div className="flex flex-wrap gap-1.5">
                                  {rule.attack_mappings?.map((m: string) => (
                                    <span key={m} className="px-1.5 py-0.5 bg-gray-950 border border-gray-800 rounded text-[10px] text-gray-400 font-mono">
                                      {m}
                                    </span>
                                  ))}
                                </div>
                              </div>

                              {/* Middle: Pipeline Stage View */}
                              <div className="flex-1 min-w-[650px] flex items-center justify-center relative">
                                <PipelineStageView evidence={rule.evidence_report} />
                              </div>

                              {/* Right: Actions */}
                              <div className="w-[20%] min-w-[200px] flex flex-col items-end justify-center gap-2">
                                 <div className="text-[11px] text-gray-500 font-medium mb-1 flex items-center gap-1">
                                   <Activity className="w-3 h-3 opacity-70" /> Synced: {lastSyncedStr}
                                 </div>
                                 <div className="flex items-center gap-2 w-full justify-end">
                                   <button className="bg-transparent hover:bg-gray-800 text-gray-400 hover:text-white px-3 py-1.5 rounded text-xs font-medium transition-colors border border-gray-700 hover:border-gray-600">
                                     JSON
                                   </button>
                                   <button
                                     onClick={() => setSelectedDeployRule(rule)}
                                     className="bg-blue-600/10 hover:bg-blue-600/20 text-blue-400 border border-blue-500/20 hover:border-blue-500/40 px-4 py-1.5 rounded text-xs font-bold transition-all shadow-sm"
                                   >
                                     Deploy
                                   </button>
                                 </div>
                              </div>
                            </div>
                          );
                        })}
                      </div>
                    </div>
                  )}
                </div>
              </div>
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

