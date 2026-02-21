import React, { useState, useEffect } from 'react';
import { useQuery, useMutation } from '@tanstack/react-query';
import { apiClient, RemediationConfig } from '../api/client';
import toast from 'react-hot-toast';
import { ShieldAlert, Zap, Save } from 'lucide-react';

const fetchSettings = async (): Promise<RemediationConfig> => {
    const { data } = await apiClient.get('/settings');
    return data;
};

const updateSettings = async (cfg: RemediationConfig) => {
    await apiClient.post('/settings', cfg);
};

export const Settings = () => {
    const { data: config, isLoading } = useQuery<RemediationConfig>({
        queryKey: ['settings'],
        queryFn: fetchSettings,
    });

    const [formData, setFormData] = useState<RemediationConfig>({
        auto_block_enabled: false,
        webhook_url: '',
        threshold: 5,
        time_window: '1 MINUTE',
    });

    useEffect(() => {
        if (config) setFormData(config);
    }, [config]);

    const mutation = useMutation({
        mutationFn: updateSettings,
        onSuccess: () => {
            toast.success('Auto-Remediation configuration saved successfully.');
        },
        onError: () => {
            toast.error('Failed to update config.');
        }
    });

    const handleSave = (e: React.FormEvent) => {
        e.preventDefault();
        mutation.mutate(formData);
    };

    if (isLoading) return <div className="text-gray-500 animate-pulse p-6">Loading engine metrics...</div>;

    return (
        <div className="max-w-2xl bg-soc-800 border border-soc-700 p-8 rounded-xl shadow-lg">
            <h2 className="text-2xl font-bold text-white mb-6 flex items-center gap-3">
                <Zap className="text-soc-warn" /> Auto-Remediation Engine
            </h2>
            <p className="text-gray-400 text-sm mb-8">
                Configure the autonomous intelligent firewall response. When conditions are met, the engine will automatically enforce blocks and trigger webhooks.
            </p>

            <form onSubmit={handleSave} className="space-y-6">
                <div className="flex items-center justify-between p-4 bg-soc-900 border border-soc-700 rounded-lg">
                    <div>
                        <h4 className="text-gray-200 font-semibold flex items-center gap-2">
                            <ShieldAlert className="w-4 h-4 text-soc-accent" /> Enable Autonomous Defense
                        </h4>
                        <p className="text-xs text-gray-500 mt-1">Automatically block malicious IPs globally rather than just rate-limiting.</p>
                    </div>
                    <label className="relative inline-flex items-center cursor-pointer">
                        <input
                            type="checkbox"
                            className="sr-only peer"
                            checked={formData.auto_block_enabled}
                            onChange={(e) => setFormData({ ...formData, auto_block_enabled: e.target.checked })}
                        />
                        <div className="w-11 h-6 bg-gray-600 peer-focus:outline-none rounded-full peer peer-checked:after:translate-x-full peer-checked:after:border-white after:content-[''] after:absolute after:top-[2px] after:left-[2px] after:bg-white after:border-gray-300 after:border after:rounded-full after:h-5 after:w-5 after:transition-all peer-checked:bg-soc-success"></div>
                    </label>
                </div>

                <div className="space-y-2">
                    <label className="text-sm font-semibold text-gray-300">Slack / Telegram Webhook URL</label>
                    <input
                        type="url"
                        placeholder="https://hooks.slack.com/services/..."
                        className="w-full bg-soc-900 border border-soc-700 rounded p-3 text-sm text-gray-200 focus:outline-none focus:border-soc-accent"
                        value={formData.webhook_url}
                        onChange={(e) => setFormData({ ...formData, webhook_url: e.target.value })}
                    />
                </div>

                <div className="grid grid-cols-2 gap-4">
                    <div className="space-y-2">
                        <label className="text-sm font-semibold text-gray-300">Strike Threshold</label>
                        <input
                            type="number"
                            className="w-full bg-soc-900 border border-soc-700 rounded p-3 text-sm text-gray-200 focus:outline-none focus:border-soc-accent"
                            value={formData.threshold}
                            onChange={(e) => setFormData({ ...formData, threshold: parseInt(e.target.value) || 5 })}
                        />
                    </div>
                    <div className="space-y-2">
                        <label className="text-sm font-semibold text-gray-300">Time Window</label>
                        <select
                            className="w-full bg-soc-900 border border-soc-700 rounded p-3 text-sm text-gray-200 focus:outline-none focus:border-soc-accent"
                            value={formData.time_window}
                            onChange={(e) => setFormData({ ...formData, time_window: e.target.value })}
                        >
                            <option value="1 MINUTE">1 Minute</option>
                            <option value="5 MINUTE">5 Minutes</option>
                        </select>
                    </div>
                </div>

                <div className="pt-6 border-t border-soc-700 flex justify-end">
                    <button
                        type="submit"
                        className="bg-soc-accent hover:bg-blue-500 text-white font-bold py-2 px-6 rounded flex items-center gap-2 transition"
                        disabled={mutation.isPending}
                    >
                        <Save className="w-4 h-4" />
                        {mutation.isPending ? 'Syncing...' : 'Deploy Policy'}
                    </button>
                </div>
            </form>
        </div>
    );
};
