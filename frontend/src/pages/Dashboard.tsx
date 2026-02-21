import { useQuery } from '@tanstack/react-query';
import { apiClient, SummaryStats, TimeSeriesPoint } from '../api/client';
import { KPICard } from '../components/KPICard';
import { Globe, AlertTriangle, ShieldX, Activity } from 'lucide-react';
import {
    LineChart, Line, XAxis, YAxis, CartesianGrid, Tooltip, Legend, ResponsiveContainer,
    PieChart, Pie, Cell
} from 'recharts';

const fetchSummary = async (): Promise<SummaryStats> => {
    const { data } = await apiClient.get('/stats/summary');
    return data;
};

const fetchTimeSeries = async (): Promise<TimeSeriesPoint[]> => {
    const { data } = await apiClient.get('/stats/timeseries');
    return data;
};

export const Dashboard = () => {
    // Queries auto-refresh every 10 seconds via refetchInterval
    const { data: summary, isLoading: loadingSummary } = useQuery<SummaryStats>({
        queryKey: ['summary'],
        queryFn: fetchSummary,
        refetchInterval: 10000,
    });

    const { data: timeSeries, isLoading: loadingTS } = useQuery<TimeSeriesPoint[]>({
        queryKey: ['timeseries'],
        queryFn: fetchTimeSeries,
        refetchInterval: 10000,
    });

    const COLORS = ['#EF4444', '#F59E0B', '#3B82F6', '#10B981', '#8B5CF6'];

    const blockRate = summary && summary.total_requests > 0
        ? ((summary.blocked_requests / summary.total_requests) * 100).toFixed(1)
        : "0.0";

    return (
        <div className="space-y-6">
            {/* KPIs */}
            <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-6">
                <KPICard
                    title="Total Traffic (24h)"
                    value={loadingSummary ? "..." : summary?.total_requests.toLocaleString() || 0}
                    icon={<Globe />}
                />
                <KPICard
                    title="Mitigated Attacks"
                    value={loadingSummary ? "..." : summary?.blocked_requests.toLocaleString() || 0}
                    icon={<ShieldX className="text-soc-danger" />}
                    trend="Critical"
                    trendColor="text-soc-danger"
                />
                <KPICard
                    title="Block Rate"
                    value={`${blockRate}%`}
                    icon={<Activity className="text-soc-success" />}
                />
                <KPICard
                    title="Active Threat Vectors"
                    value={summary?.distribution.length || 0}
                    icon={<AlertTriangle className="text-soc-warn" />}
                />
            </div>

            {/* Charts Grid */}
            <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">

                {/* Main TimeSeries Chart */}
                <div className="lg:col-span-3 xl:col-span-2 bg-soc-800 p-6 rounded-xl border border-soc-700 shadow-lg">
                    <h3 className="text-lg font-semibold mb-4 text-gray-200">Attack Velocity & Timeline</h3>
                    <div className="h-80">
                        {loadingTS ? (
                            <div className="flex items-center justify-center h-full text-gray-500 animate-pulse">Analyzing telemetry...</div>
                        ) : (
                            <ResponsiveContainer width="100%" height="100%">
                                <LineChart data={timeSeries}>
                                    <CartesianGrid strokeDasharray="3 3" stroke="#374151" />
                                    <XAxis dataKey="time" stroke="#9CA3AF" />
                                    <YAxis stroke="#9CA3AF" />
                                    <Tooltip
                                        contentStyle={{ backgroundColor: '#1F2937', borderColor: '#374151', color: '#fff' }}
                                        itemStyle={{ color: '#E5E7EB' }}
                                    />
                                    <Legend />
                                    <Line type="monotone" dataKey="total" stroke="#3B82F6" strokeWidth={2} dot={false} name="Total Attempts" />
                                    <Line type="monotone" dataKey="blocked" stroke="#EF4444" strokeWidth={2} dot={false} name="Blocked" />
                                </LineChart>
                            </ResponsiveContainer>
                        )}
                    </div>
                </div>

                <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-1 gap-6 lg:col-span-3 xl:col-span-1">
                    {/* Threat Distribution */}
                    <div className="bg-soc-800 p-6 rounded-xl border border-soc-700 shadow-lg">
                        <h3 className="text-lg font-semibold mb-4 text-gray-200 text-center">Threat Classifications</h3>
                        <div className="h-64">
                            {loadingSummary ? (
                                <div className="flex items-center justify-center h-full text-gray-500 animate-pulse">Correlating signatures...</div>
                            ) : (
                                <ResponsiveContainer width="100%" height="100%">
                                    <PieChart>
                                        <Pie
                                            data={summary?.distribution || []}
                                            cx="50%"
                                            cy="50%"
                                            innerRadius={50}
                                            outerRadius={80}
                                            paddingAngle={5}
                                            dataKey="count"
                                            nameKey="type"
                                        >
                                            {summary?.distribution.map((_, index) => (
                                                <Cell key={`cell-${index}`} fill={COLORS[index % COLORS.length]} />
                                            ))}
                                        </Pie>
                                        <Tooltip contentStyle={{ backgroundColor: '#1F2937', border: 'none' }} />
                                        <Legend />
                                    </PieChart>
                                </ResponsiveContainer>
                            )}
                        </div>
                    </div>

                    {/* AI vs Rules Mitigation */}
                    <div className="bg-soc-800 p-6 rounded-xl border border-soc-700 shadow-lg">
                        <h3 className="text-lg font-semibold mb-4 text-gray-200 text-center">Mitigation Engine</h3>
                        <div className="h-64">
                            {loadingSummary ? (
                                <div className="flex items-center justify-center h-full text-gray-500 animate-pulse">Loading core engine data...</div>
                            ) : (
                                <ResponsiveContainer width="100%" height="100%">
                                    <PieChart>
                                        <Pie
                                            data={[
                                                { name: 'Regex Rules', value: summary?.blocked_by_rules || 0 },
                                                { name: 'AI Zero-Day', value: summary?.blocked_by_ai || 0 }
                                            ].filter(d => d.value > 0)}
                                            cx="50%"
                                            cy="50%"
                                            innerRadius={50}
                                            outerRadius={80}
                                            paddingAngle={5}
                                            dataKey="value"
                                            nameKey="name"
                                        >
                                            <Cell fill="#3B82F6" /> {/* Blue for Rules */}
                                            <Cell fill="#8B5CF6" /> {/* Purple for AI */}
                                        </Pie>
                                        <Tooltip contentStyle={{ backgroundColor: '#1F2937', border: 'none' }} />
                                        <Legend />
                                    </PieChart>
                                </ResponsiveContainer>
                            )}
                        </div>
                    </div>
                </div>

            </div>
        </div>
    );
};
