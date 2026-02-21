import React, { useEffect, useState } from 'react';
import { apiClient, RemediationConfig } from '../api/client';
import toast from 'react-hot-toast';
import { useTenantContext } from '../context/TenantContext';
import { Shield, Building2 } from 'lucide-react';

export const OrganizationSettings = () => {
    const { tenantId, role } = useTenantContext();
    const [config, setConfig] = useState<RemediationConfig | null>(null);

    useEffect(() => {
        // Only load if Admin
        if (role !== 'Admin') return;

        apiClient.get('/settings').then(res => setConfig(res.data)).catch(() => {
            toast.error('Failed to load settings');
        });
    }, [role]);

    const handleSave = async (e: React.FormEvent) => {
        e.preventDefault();
        if (!config) return;
        try {
            await apiClient.post('/settings', config);
            toast.success('Organization Settings updated');
        } catch (err) {
            toast.error('Failed to update settings');
        }
    };

    if (role !== 'Admin') {
        return (
            <div className="flex flex-col items-center justify-center h-full text-center">
                <Shield className="w-16 h-16 text-red-500 mb-4" />
                <h2 className="text-2xl font-bold text-white mb-2">Access Denied</h2>
                <p className="text-gray-400 max-w-md">
                    Your current role ({role}) does not have permission to view or modify Organization Settings.
                </p>
            </div>
        );
    }

    if (!config) return <div>Loading...</div>;

    return (
        <div className="space-y-6">
            <header className="mb-8">
                <h1 className="text-3xl font-bold text-white tracking-wide flex items-center gap-3">
                    <Building2 className="text-soc-accent" />
                    Organization Settings
                </h1>
                <p className="text-gray-400 mt-2">Manage your tenant workspace and auto-remediation policies.</p>
                <div className="mt-4 p-4 bg-soc-800 border-l-4 border-soc-accent rounded flex items-center gap-4">
                    <div className="flex-1">
                        <p className="text-sm font-bold text-gray-400 uppercase tracking-widest">Active Tenant ID</p>
                        <p className="text-white font-mono mt-1">{tenantId}</p>
                    </div>
                </div>
            </header>

            <div className="bg-soc-800 p-6 rounded-xl border border-soc-700">
                <h2 className="text-xl font-bold text-white mb-6 flex items-center gap-2">
                    <Shield className="text-soc-accent" />
                    Auto-Remediation Policy
                </h2>

                <form onSubmit={handleSave} className="space-y-6">
                    <div className="flex items-center gap-4">
                        <label className="flex items-center gap-3 cursor-pointer">
                            <input
                                type="checkbox"
                                checked={config.auto_block_enabled}
                                onChange={(e) => setConfig({ ...config, auto_block_enabled: e.target.checked })}
                                className="w-5 h-5 accent-soc-accent rounded bg-soc-900 border-soc-700 focus:ring-soc-accent focus:ring-offset-soc-800"
                            />
                            <span className="text-white font-medium">Enable Autonomous Threat Remediation</span>
                        </label>
                    </div>

                    <div className="space-y-4">
                        <div>
                            <label className="block text-sm font-medium text-gray-400 mb-2">Strike Threshold (per 1 min)</label>
                            <input
                                type="number"
                                min="1"
                                value={config.threshold}
                                onChange={(e) => setConfig({ ...config, threshold: parseInt(e.target.value) })}
                                className="w-full bg-soc-900 border border-soc-700 rounded p-3 text-white focus:outline-none focus:border-soc-accent transition"
                            />
                        </div>

                        <div>
                            <label className="block text-sm font-medium text-gray-400 mb-2">SOC Alert Webhook URL (Slack/Teams)</label>
                            <input
                                type="text"
                                value={config.webhook_url}
                                onChange={(e) => setConfig({ ...config, webhook_url: e.target.value })}
                                className="w-full bg-soc-900 border border-soc-700 rounded p-3 text-white focus:outline-none focus:border-soc-accent transition"
                            />
                        </div>
                    </div>

                    <div className="pt-4">
                        <button type="submit" className="bg-soc-accent hover:bg-blue-600 text-white font-bold py-3 px-6 rounded transition tracking-wider w-full md:w-auto text-sm">
                            SAVE POLICIES
                        </button>
                    </div>
                </form>
            </div>
        </div>
    );
};
