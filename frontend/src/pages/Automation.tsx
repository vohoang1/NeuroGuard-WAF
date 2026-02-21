import React, { useEffect, useState } from 'react';
import { ShieldAlert, Unlock, Shield, ShieldCheck, Plus, Trash2 } from 'lucide-react';
import toast from 'react-hot-toast';
import { apiClient } from '../api/client';
import { useTenantContext } from '../context/TenantContext';

export const Automation = () => {
    const { role } = useTenantContext();
    const [enabled, setEnabled] = useState<boolean>(false);
    const [blocklist, setBlocklist] = useState<string[]>([]);
    const [whitelist, setWhitelist] = useState<string[]>([]);
    const [newIp, setNewIp] = useState('');

    const fetchData = () => {
        if (role !== 'Admin') return;
        apiClient.get('/remediation/status').then(res => setEnabled(res.data.enabled)).catch(console.error);
        apiClient.get('/remediation/blocklist').then(res => setBlocklist(res.data.blocked_ips || [])).catch(console.error);
        apiClient.get('/remediation/whitelist').then(res => setWhitelist(res.data.whitelist || [])).catch(console.error);
    };

    useEffect(() => {
        fetchData();
        const interval = setInterval(fetchData, 10000);
        return () => clearInterval(interval);
    }, [role]);

    const handleToggle = async (e: React.ChangeEvent<HTMLInputElement>) => {
        const val = e.target.checked;
        try {
            await apiClient.post('/remediation/toggle', { enabled: val });
            setEnabled(val);
            toast.success(val ? 'Auto-Remediation Enabled' : 'Auto-Remediation Disabled');
        } catch {
            toast.error('Failed to toggle Auto-Remediation');
        }
    };

    const handleUnblock = async (ip: string) => {
        try {
            await apiClient.post('/remediation/unblock', { ip });
            toast.success(`Unblocked ${ip}`);
            fetchData();
        } catch {
            toast.error('Failed to unblock IP');
        }
    };

    const handleWhitelist = async (action: 'add' | 'remove', ip: string) => {
        if (!ip) return;
        try {
            await apiClient.post('/remediation/whitelist', { action, ip });
            toast.success(`${action === 'add' ? 'Added' : 'Removed'} ${ip} ${action === 'add' ? 'to' : 'from'} whitelist`);
            if (action === 'add') setNewIp('');
            fetchData();
        } catch {
            toast.error('Failed to update whitelist');
        }
    };

    if (role !== 'Admin') {
        return (
            <div className="flex flex-col items-center justify-center h-full text-center">
                <ShieldAlert className="w-16 h-16 text-red-500 mb-4" />
                <h2 className="text-2xl font-bold text-white mb-2">Access Denied</h2>
                <p className="text-gray-400 max-w-md">Your current role does not have permission to access the Automation Center.</p>
            </div>
        );
    }

    return (
        <div className="space-y-6">
            <header className="mb-8 flex justify-between items-end">
                <div>
                    <h1 className="text-3xl font-bold text-white tracking-wide flex items-center gap-3">
                        <ShieldAlert className="text-soc-accent" />
                        Automation Center
                    </h1>
                    <p className="text-gray-400 mt-2">Manage automated threat responses, active blocklists, and trusted IPs.</p>
                </div>
                <div className="flex items-center gap-4 bg-soc-800 p-4 rounded-xl border border-soc-700">
                    <span className="text-white font-medium">Auto-Remediation Engine</span>
                    <label className="relative inline-flex items-center cursor-pointer">
                        <input type="checkbox" className="sr-only peer" checked={enabled} onChange={handleToggle} />
                        <div className="w-11 h-6 bg-soc-700 peer-focus:outline-none rounded-full peer peer-checked:after:translate-x-full peer-checked:after:border-white after:content-[''] after:absolute after:top-[2px] after:left-[2px] after:bg-white after:border-gray-300 after:border after:rounded-full after:h-5 after:w-5 after:transition-all peer-checked:bg-soc-accent"></div>
                    </label>
                </div>
            </header>

            <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
                {/* Active Blocks */}
                <div className="bg-soc-800 p-6 rounded-xl border border-soc-700 flex flex-col h-96">
                    <h2 className="text-xl font-bold text-white mb-6 flex items-center gap-2">
                        <Shield className="text-red-500" /> Active Blocks
                    </h2>
                    <div className="flex-1 overflow-y-auto pr-2 space-y-3">
                        {blocklist.length === 0 ? (
                            <p className="text-gray-500 italic">No automated blocks active.</p>
                        ) : (
                            blocklist.map(ip => (
                                <div key={ip} className="flex justify-between items-center bg-soc-900 p-3 rounded border border-soc-700">
                                    <span className="font-mono text-red-400">{ip}</span>
                                    <button
                                        onClick={() => handleUnblock(ip)}
                                        className="text-xs flex items-center gap-1 bg-soc-700 hover:bg-soc-600 text-white px-3 py-1.5 rounded transition"
                                    >
                                        <Unlock className="w-3 h-3" /> UNBLOCK
                                    </button>
                                </div>
                            ))
                        )}
                    </div>
                </div>

                {/* Whitelist */}
                <div className="bg-soc-800 p-6 rounded-xl border border-soc-700 flex flex-col h-96">
                    <h2 className="text-xl font-bold text-white mb-6 flex items-center gap-2">
                        <ShieldCheck className="text-green-500" /> Trusted IPs Whitelist
                    </h2>

                    <div className="flex gap-2 mb-4">
                        <input
                            type="text"
                            placeholder="Enter IP (e.g. 192.168.1.1)"
                            className="flex-1 bg-soc-900 border border-soc-700 rounded px-3 py-2 text-white focus:border-soc-accent outline-none font-mono text-sm"
                            value={newIp}
                            onChange={(e) => setNewIp(e.target.value)}
                        />
                        <button
                            onClick={() => handleWhitelist('add', newIp)}
                            className="bg-soc-accent hover:bg-blue-600 text-white px-4 rounded transition flex items-center gap-2"
                        >
                            <Plus className="w-4 h-4" /> Add
                        </button>
                    </div>

                    <div className="flex-1 overflow-y-auto pr-2 space-y-3">
                        {whitelist.map(ip => (
                            <div key={ip} className="flex justify-between items-center bg-soc-900 p-3 rounded border border-soc-700">
                                <span className="font-mono text-green-400">{ip}</span>
                                <button
                                    onClick={() => handleWhitelist('remove', ip)}
                                    className="text-gray-400 hover:text-red-400 transition"
                                >
                                    <Trash2 className="w-4 h-4" />
                                </button>
                            </div>
                        ))}
                    </div>
                </div>
            </div>
        </div>
    );
};
