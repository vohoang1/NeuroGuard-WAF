import { useQuery } from '@tanstack/react-query';
import { apiClient, ThreatHistoryLog } from '../api/client';
import { ShieldX } from 'lucide-react';

const fetchHistory = async (): Promise<ThreatHistoryLog[]> => {
    const { data } = await apiClient.get('/history');
    return data;
};

export const ThreatHistory = () => {
    const { data: logs, isLoading } = useQuery<ThreatHistoryLog[]>({
        queryKey: ['threat_history'],
        queryFn: fetchHistory,
        refetchInterval: 10000,
    });

    return (
        <div className="bg-soc-800 p-6 rounded-xl border border-soc-700 shadow-lg flex flex-col h-[calc(100vh-8rem)]">
            <div className="flex justify-between items-center mb-6">
                <h2 className="text-xl font-bold text-gray-200 flex items-center gap-2">
                    <ShieldX className="text-soc-danger" /> Automated Mitigations
                </h2>
                <span className="text-xs text-gray-400">Synced with Firewall Nodes</span>
            </div>

            <div className="flex-1 overflow-auto rounded-lg border border-soc-700">
                <table className="w-full text-left text-sm">
                    <thead className="bg-soc-900 border-b border-soc-700 sticky top-0 z-10">
                        <tr>
                            <th className="p-4 text-gray-400 font-medium">Mitigation Time</th>
                            <th className="p-4 text-gray-400 font-medium">Target IP</th>
                            <th className="p-4 text-gray-400 font-medium">Trigger Reason</th>
                            <th className="p-4 text-gray-400 font-medium">Enforced Action</th>
                            <th className="p-4 text-gray-400 font-medium text-right">Status</th>
                        </tr>
                    </thead>
                    <tbody className="divide-y divide-soc-700">
                        {isLoading ? (
                            <tr><td colSpan={5} className="p-8 text-center text-gray-500 animate-pulse">Syncing policy enforcements...</td></tr>
                        ) : logs?.length === 0 ? (
                            <tr><td colSpan={5} className="p-8 text-center text-gray-500">No autonomous enforcements logged yet.</td></tr>
                        ) : logs?.map((log, idx) => (
                            <tr key={idx} className="hover:bg-soc-700/50 transition duration-150">
                                <td className="p-4 text-gray-300 font-mono text-xs">
                                    {new Date(log.timestamp).toLocaleString()}
                                </td>
                                <td className="p-4 font-mono font-bold text-soc-danger">
                                    {log.source_ip}
                                </td>
                                <td className="p-4 text-gray-300">
                                    {log.reason}
                                </td>
                                <td className="p-4">
                                    <span className="bg-soc-900 border border-soc-700 px-2 py-1 rounded text-xs text-gray-300">
                                        {log.action}
                                    </span>
                                </td>
                                <td className="p-4 text-right">
                                    <span className="text-soc-success font-bold text-xs tracking-wider uppercase">
                                        {log.status}
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
