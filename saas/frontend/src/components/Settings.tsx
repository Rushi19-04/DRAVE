import React, { useState, useEffect } from "react";
import { useAuth } from "@clerk/clerk-react";

interface ApiKey {
  id: string;
  label: string;
  created_at: string;
  last_used_at: string | null;
  revoked: boolean;
}

const API_URL = import.meta.env.VITE_API_BASE_URL || "http://localhost:8000";

export const Settings: React.FC = () => {
  const { getToken } = useAuth();
  const [keys, setKeys] = useState<ApiKey[]>([]);
  const [newKeyLabel, setNewKeyLabel] = useState("");
  const [revealedKey, setRevealedKey] = useState<string | null>(null);
  const [loading, setLoading] = useState(false);

  const fetchKeys = async () => {
    try {
      const token = await getToken();
      const res = await fetch(`${API_URL}/api/v1/ci-keys`, {
        headers: { Authorization: `Bearer ${token}` }
      });
      if (res.ok) {
        setKeys(await res.json());
      }
    } catch (err) {
      console.error("Failed to fetch API keys", err);
    }
  };

  useEffect(() => {
    fetchKeys();
  }, []);

  const generateKey = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!newKeyLabel) return;
    setLoading(true);
    try {
      const token = await getToken();
      const res = await fetch(`${API_URL}/api/v1/ci-keys`, {
        method: "POST",
        headers: { 
          "Authorization": `Bearer ${token}`,
          "Content-Type": "application/json"
        },
        body: JSON.stringify({ label: newKeyLabel })
      });
      if (res.ok) {
        const data = await res.json();
        setRevealedKey(data.raw_key);
        setNewKeyLabel("");
        fetchKeys();
      }
    } catch (err) {
      console.error("Failed to generate key", err);
    }
    setLoading(false);
  };

  const revokeKey = async (id: string) => {
    try {
      const token = await getToken();
      const res = await fetch(`${API_URL}/api/v1/ci-keys/${id}`, {
        method: "DELETE",
        headers: { Authorization: `Bearer ${token}` }
      });
      if (res.ok) fetchKeys();
    } catch (err) {
      console.error("Failed to revoke key", err);
    }
  };

  return (
    <div className="bg-gray-800 p-6 rounded-lg shadow-md border border-gray-700">
      <h2 className="text-xl font-bold mb-4 text-white">API Keys & Integrations</h2>
      <p className="text-gray-400 mb-6 text-sm">
        Generate API keys for CI/CD pipelines (e.g., GitHub Actions) to sync validation scores to DRAVE.
      </p>

      {revealedKey && (
        <div className="bg-yellow-900 border border-yellow-700 p-4 rounded-md mb-6">
          <h3 className="text-yellow-400 font-bold mb-2">⚠️ Copy this key now!</h3>
          <p className="text-yellow-200 text-sm mb-3">
            For security reasons, you will never be able to see this key again.
          </p>
          <div className="flex items-center gap-2">
            <code className="bg-gray-950 p-2 rounded text-green-400 flex-1 font-mono">{revealedKey}</code>
            <button 
              onClick={() => navigator.clipboard.writeText(revealedKey)}
              className="bg-gray-700 hover:bg-gray-600 px-3 py-2 rounded text-white text-sm transition-colors"
            >
              Copy
            </button>
          </div>
          <button 
            onClick={() => setRevealedKey(null)}
            className="mt-4 text-sm text-yellow-400 hover:text-yellow-300 underline"
          >
            I have saved it securely
          </button>
        </div>
      )}

      <form onSubmit={generateKey} className="flex gap-2 mb-8">
        <input
          type="text"
          value={newKeyLabel}
          onChange={(e) => setNewKeyLabel(e.target.value)}
          placeholder="e.g. GitHub Actions - main repo"
          className="flex-1 bg-gray-900 border border-gray-700 rounded px-4 py-2 text-white focus:outline-none focus:border-blue-500"
          required
        />
        <button 
          type="submit" 
          disabled={loading || !newKeyLabel}
          className="bg-blue-600 hover:bg-blue-700 px-4 py-2 rounded text-white font-medium disabled:opacity-50 transition-colors"
        >
          {loading ? "Generating..." : "Generate New Key"}
        </button>
      </form>

      <div className="overflow-x-auto">
        <table className="w-full text-left border-collapse">
          <thead>
            <tr className="border-b border-gray-700">
              <th className="py-3 px-4 text-gray-400 font-medium text-sm">Label</th>
              <th className="py-3 px-4 text-gray-400 font-medium text-sm">Created</th>
              <th className="py-3 px-4 text-gray-400 font-medium text-sm">Last Used</th>
              <th className="py-3 px-4 text-gray-400 font-medium text-sm text-right">Actions</th>
            </tr>
          </thead>
          <tbody>
            {keys.map(key => (
              <tr key={key.id} className="border-b border-gray-750 hover:bg-gray-750">
                <td className="py-3 px-4 text-white font-medium">{key.label}</td>
                <td className="py-3 px-4 text-gray-400 text-sm">
                  {new Date(key.created_at).toLocaleDateString()}
                </td>
                <td className="py-3 px-4 text-gray-400 text-sm">
                  {key.last_used_at ? new Date(key.last_used_at).toLocaleDateString() : 'Never'}
                </td>
                <td className="py-3 px-4 text-right">
                  <button 
                    onClick={() => revokeKey(key.id)}
                    className="text-red-400 hover:text-red-300 text-sm font-medium transition-colors"
                  >
                    Revoke
                  </button>
                </td>
              </tr>
            ))}
            {keys.length === 0 && (
              <tr>
                <td colSpan={4} className="py-6 text-center text-gray-500">
                  No active API keys found.
                </td>
              </tr>
            )}
          </tbody>
        </table>
      </div>
    </div>
  );
};
