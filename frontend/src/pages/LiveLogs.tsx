import { useQuery } from '@tanstack/react-query';
import { apiClient, WafLog } from '../api/client';
import { ShieldAlert } from 'lucide-react';

const fetchLogs = async (): Promise<WafLog[]> => {
    // Fetching last 50 directly for MVP SOC table
    const { data } = await apiClient.get('/logs?limit=50');
    return data;
};

export const LiveLogs = () => {
    const { data: logs, isLoading } = useQuery<WafLog[]>({
        queryKey: ['logs'],
        queryFn: fetchLogs,
        refetchInterval: 10000,
    });

    const getActionColor = (action: string) => {
        switch (action.toUpperCase()) {
            case 'BLOCK': return 'bg-soc-danger/20 text-soc-danger border-soc-danger';
            case 'CHALLENGE': return 'bg-soc-warn/20 text-soc-warn border-soc-warn';
            default: return 'bg-soc-success/20 text-soc-success border-soc-success';
        }
    };

    return (
        <div className="bg-soc-800 p-6 rounded-xl border border-soc-700 shadow-lg flex flex-col h-[calc(100vh-8rem)]">
            <div className="flex justify-between items-center mb-6">
                <h2 className="text-xl font-bold text-gray-200 flex items-center gap-2">
                    <ShieldAlert className="text-soc-accent" /> Real-Time Incident Feed
                </h2>
                {isLoading && <span className="text-xs bg-soc-accent px-2 py-1 rounded text-white animate-pulse">LIVE SYNC</span>}
            </div>

            <div className="flex-1 overflow-auto rounded-lg border border-soc-700">
                <table className="w-full text-left text-sm">
                    <thead className="bg-soc-900 border-b border-soc-700 sticky top-0 z-10">
                        <tr>
                            <th className="p-4 text-gray-400 font-medium">Timestamp</th>
                            <th className="p-4 text-gray-400 font-medium">Source IP</th>
                            <th className="p-4 text-gray-400 font-medium">Method / URI</th>
                            <th className="p-4 text-gray-400 font-medium">Signature Matrix</th>
                            <th className="p-4 text-gray-400 font-medium text-right">Enforcement</th>
                        </tr>
                    </thead>
                    <tbody className="divide-y divide-soc-700">
                        {logs?.length === 0 ? (
                            <tr><td colSpan={5} className="p-8 text-center text-gray-500">No incident logs populated in current view.</td></tr>
                        ) : logs?.map((log, idx) => (
                            <tr key={idx} className="hover:bg-soc-700/50 transition duration-150">
                                <td className="p-4 text-gray-300 font-mono text-xs">
                                    {new Date(log.timestamp).toLocaleString()}
                                </td>
                                <td className="p-4 font-mono font-bold text-gray-200">
                                    {log.source_ip}
                                </td>
                                <td className="p-4">
                                    <div className="flex flex-col">
                                        <span className="font-bold text-soc-accent">{log.method}</span>
                                        <span className="text-gray-400 text-xs truncate max-w-xs" title={log.uri}>{log.uri}</span>
                                    </div>
                                </td>
                                <td className="p-4">
                                    <span className="bg-soc-900 border border-soc-700 px-2 py-1 rounded text-xs text-gray-300">
                                        {log.attack_type.replace('_', ' ')}
                                    </span>
                                </td>
                                <td className="p-4 text-right">
                                    <span className={`px-3 py-1 text-xs border rounded font-bold tracking-wide ${getActionColor(log.action)}`}>
                                        {log.action.toUpperCase()}
                                    </span>
                                </td>
                            </tr>
                        ))}
                    </tbody>
                </table>
            </div>
        </div>
    );
};
