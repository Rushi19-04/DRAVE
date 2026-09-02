import { useEffect, useState } from 'react';
import { useAuth } from '@clerk/clerk-react';
import { Activity, RefreshCw, CheckCircle2, XCircle, AlertCircle, Clock, ChevronRight } from 'lucide-react';

interface ValidationRun {
  id: string;
  rule_id: string;
  rule_name: string;
  status: string;
  score: number;
  timestamp: string;
  evidence_report: any;
}

export function ValidationRuns() {
  const { getToken } = useAuth();
  const API_BASE_URL = import.meta.env.VITE_API_BASE_URL || 'http://localhost:8000';
  const [runs, setRuns] = useState<ValidationRun[]>([]);
  const [loading, setLoading] = useState(true);
  const [selectedRun, setSelectedRun] = useState<ValidationRun | null>(null);

  const fetchRuns = async () => {
    setLoading(true);
    try {
      const token = await getToken();
      const res = await fetch(`${API_BASE_URL}/api/v1/validations`, {
        headers: { 'Authorization': `Bearer ${token}` }
      });
      if (res.ok) {
        const data = await res.json();
        setRuns(data);
      }
    } catch (err) {
      console.error("Failed to fetch validations", err);
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    fetchRuns();
  }, []);

  const formatDate = (dateString: string) => {
    const d = new Date(dateString);
    return new Intl.DateTimeFormat('en-US', {
      month: 'short', day: 'numeric', hour: '2-digit', minute: '2-digit', second: '2-digit'
    }).format(d);
  };

  return (
    <div className="w-full flex flex-col h-full">
      <div className="flex items-center justify-between mb-6">
        <div>
          <h2 className="text-xl font-bold text-white flex items-center gap-2">
            <Activity className="text-blue-500" />
            CI Validation Runs
          </h2>
          <p className="text-sm text-gray-400 mt-1">Live feed of detection engine results from your CI pipeline.</p>
        </div>
        <button 
          onClick={fetchRuns}
          disabled={loading}
          className="flex items-center gap-2 bg-gray-800 hover:bg-gray-700 text-gray-200 px-4 py-2 rounded-lg text-sm transition-colors border border-gray-700 disabled:opacity-50"
        >
          <RefreshCw size={16} className={loading ? "animate-spin" : ""} />
          Refresh
        </button>
      </div>

      <div className="flex-1 bg-gray-900 border border-gray-800 rounded-lg overflow-hidden flex flex-col">
        {loading && runs.length === 0 ? (
          <div className="flex-1 flex items-center justify-center text-gray-500 py-12">
            <RefreshCw className="animate-spin mr-2" size={20} /> Loading runs...
          </div>
        ) : runs.length === 0 ? (
          <div className="flex-1 flex flex-col items-center justify-center text-gray-500 p-8 text-center border-dashed border-2 border-gray-800 m-4 rounded-lg py-12">
            <Activity size={48} className="mb-4 opacity-50" />
            <h3 className="text-lg font-medium text-gray-400 mb-1">No Validation Runs</h3>
            <p className="text-sm max-w-md">Push a rule to your GitHub repository to trigger the DRAVE GitHub Action. Results will appear here automatically.</p>
          </div>
        ) : (
          <div className="overflow-auto flex-1">
            <table className="w-full text-left text-sm text-gray-400">
              <thead className="text-xs uppercase bg-gray-900 border-b border-gray-800 text-gray-500 sticky top-0">
                <tr>
                  <th className="px-6 py-4 font-medium">Status</th>
                  <th className="px-6 py-4 font-medium">Rule Name</th>
                  <th className="px-6 py-4 font-medium">Health Score</th>
                  <th className="px-6 py-4 font-medium">Timestamp</th>
                  <th className="px-6 py-4 font-medium text-right">Details</th>
                </tr>
              </thead>
              <tbody>
                {runs.map((run) => (
                  <tr key={run.id} className="border-b border-gray-800 hover:bg-gray-800/50 transition-colors">
                    <td className="px-6 py-4">
                      {run.status === "PASS" ? (
                        <span className="flex items-center gap-2 text-green-400 font-medium bg-green-400/10 px-3 py-1 rounded-full w-fit">
                          <CheckCircle2 size={16} /> Passed
                        </span>
                      ) : (
                        <span className="flex items-center gap-2 text-red-400 font-medium bg-red-400/10 px-3 py-1 rounded-full w-fit">
                          <XCircle size={16} /> Failed
                        </span>
                      )}
                    </td>
                    <td className="px-6 py-4 font-medium text-gray-200">
                      {run.rule_name}
                      <div className="text-xs text-gray-500 font-mono mt-1">{run.rule_id}</div>
                    </td>
                    <td className="px-6 py-4">
                      <span className="font-mono text-gray-300">{run.score}/100</span>
                    </td>
                    <td className="px-6 py-4">
                      <div className="flex items-center gap-2 text-gray-400">
                        <Clock size={14} />
                        {formatDate(run.timestamp)}
                      </div>
                    </td>
                    <td className="px-6 py-4 text-right">
                      <button 
                        onClick={() => setSelectedRun(run)}
                        className="text-blue-400 hover:text-blue-300 transition-colors flex items-center justify-end gap-1 w-full"
                      >
                        View <ChevronRight size={16} />
                      </button>
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )}
      </div>

      {/* Details Modal */}
      {selectedRun && (
        <div className="fixed inset-0 z-50 flex items-center justify-center bg-black/60 backdrop-blur-sm p-4">
          <div className="bg-gray-900 border border-gray-800 rounded-xl shadow-2xl w-full max-w-4xl max-h-[90vh] flex flex-col overflow-hidden animate-in fade-in zoom-in-95 duration-200">
            <div className="p-6 border-b border-gray-800 flex justify-between items-center bg-gray-900/50">
              <div>
                <h3 className="text-xl font-bold text-white flex items-center gap-3">
                  {selectedRun.status === "PASS" ? (
                    <CheckCircle2 className="text-green-400" size={24} />
                  ) : (
                    <XCircle className="text-red-400" size={24} />
                  )}
                  Validation Details
                </h3>
                <p className="text-sm text-gray-400 mt-1">
                  {selectedRun.rule_name} <span className="text-gray-600 px-2">•</span> {formatDate(selectedRun.timestamp)}
                </p>
              </div>
              <button 
                onClick={() => setSelectedRun(null)}
                className="text-gray-400 hover:text-white p-2 rounded-lg hover:bg-gray-800 transition-colors"
              >
                Close
              </button>
            </div>
            
            <div className="p-6 overflow-y-auto flex-1 bg-[#0a0a0c]">
              <div className="grid grid-cols-1 md:grid-cols-2 gap-6">
                
                {/* Gates Box */}
                <div className="bg-gray-900 border border-gray-800 rounded-lg p-5">
                  <h4 className="text-sm uppercase tracking-wider text-gray-500 font-bold mb-4">Hard Gates</h4>
                  <ul className="space-y-3">
                    <li className="flex items-center justify-between text-sm">
                      <span className="text-gray-300">Syntax Valid</span>
                      {selectedRun.evidence_report?.gates?.syntax_valid ? <CheckCircle2 size={16} className="text-green-400"/> : <XCircle size={16} className="text-red-400"/>}
                    </li>
                    <li className="flex items-center justify-between text-sm">
                      <span className="text-gray-300">All Tests Passed</span>
                      {selectedRun.evidence_report?.gates?.all_required_tests_pass ? <CheckCircle2 size={16} className="text-green-400"/> : <XCircle size={16} className="text-red-400"/>}
                    </li>
                    <li className="flex items-center justify-between text-sm">
                      <span className="text-gray-300">No Missed Attacks</span>
                      {selectedRun.evidence_report?.gates?.no_known_attack_missed ? <CheckCircle2 size={16} className="text-green-400"/> : <XCircle size={16} className="text-red-400"/>}
                    </li>
                    <li className="flex items-center justify-between text-sm">
                      <span className="text-gray-300">Volume within Policy</span>
                      {selectedRun.evidence_report?.gates?.volume_within_policy ? <CheckCircle2 size={16} className="text-green-400"/> : <AlertCircle size={16} className="text-yellow-400"/>}
                    </li>
                  </ul>
                </div>

                {/* Metrics Box */}
                <div className="bg-gray-900 border border-gray-800 rounded-lg p-5">
                  <h4 className="text-sm uppercase tracking-wider text-gray-500 font-bold mb-4">Execution Metrics</h4>
                  <ul className="space-y-3">
                    <li className="flex items-center justify-between text-sm">
                      <span className="text-gray-300">Unit Tests</span>
                      <span className="font-mono text-gray-400">{selectedRun.evidence_report?.tests_passed ?? 0} / {selectedRun.evidence_report?.tests_total ?? 0}</span>
                    </li>
                    <li className="flex items-center justify-between text-sm">
                      <span className="text-gray-300">Schema Compatibility</span>
                      <span className="font-mono text-gray-400">{selectedRun.evidence_report?.schema_compatibility_pct ?? 0}%</span>
                    </li>
                    {selectedRun.evidence_report?.robustness_score !== null && (
                      <li className="flex items-center justify-between text-sm">
                        <span className="text-gray-300">Variation Coverage</span>
                        <span className="font-mono text-gray-400">{(selectedRun.evidence_report?.robustness_score * 100).toFixed(0)}%</span>
                      </li>
                    )}
                    {selectedRun.evidence_report?.attack_expected !== null && (
                      <li className="flex items-center justify-between text-sm">
                        <span className="text-gray-300">Attack Replay</span>
                        <span className="font-mono text-gray-400">Missed {selectedRun.evidence_report?.attack_missed} of {selectedRun.evidence_report?.attack_expected}</span>
                      </li>
                    )}
                  </ul>
                </div>

                {/* Raw JSON */}
                <div className="md:col-span-2 bg-gray-900 border border-gray-800 rounded-lg overflow-hidden">
                  <div className="px-4 py-2 bg-gray-800/50 border-b border-gray-800 text-xs font-mono text-gray-400">
                    Raw Evidence Report
                  </div>
                  <pre className="p-4 text-xs font-mono text-gray-300 overflow-x-auto max-h-[300px] overflow-y-auto">
                    {JSON.stringify(selectedRun.evidence_report, null, 2)}
                  </pre>
                </div>
                
              </div>
            </div>
          </div>
        </div>
      )}
    </div>
  );
}
