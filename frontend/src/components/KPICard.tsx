
interface KPICardProps {
    title: string;
    value: string | number;
    icon: React.ReactNode;
    trend?: string;
    trendColor?: string;
}

export const KPICard: React.FC<KPICardProps> = ({ title, value, icon, trend, trendColor }) => {
    return (
        <div className="bg-soc-800 border border-soc-700 p-6 rounded-xl shadow-lg flex flex-col justify-between hover:border-soc-accent transition duration-200">
            <div className="flex justify-between items-start">
                <div>
                    <p className="text-gray-400 text-sm font-semibold uppercase tracking-wider">{title}</p>
                    <h3 className="text-3xl font-bold text-white mt-2">{value}</h3>
                </div>
                <div className="p-3 bg-soc-900 rounded-lg text-soc-accent">
                    {icon}
                </div>
            </div>
            {trend && (
                <div className="mt-4 text-sm font-medium">
                    <span className={trendColor || "text-soc-accent"}>{trend}</span>
                    <span className="text-gray-500 ml-2">vs last hour</span>
                </div>
            )}
        </div>
    );
};
