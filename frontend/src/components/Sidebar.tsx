import { NavLink } from 'react-router-dom';
import { Shield, Activity, ListFilter, Settings, ShieldAlert } from 'lucide-react';
import { useTenantContext } from '../context/TenantContext';

export const Sidebar = () => {
    const { role } = useTenantContext();
    return (
        <aside className="w-64 bg-soc-900 border-r border-soc-700 hidden md:flex flex-col h-screen sticky top-0">
            <div className="p-6 flex items-center gap-3 border-b border-soc-700">
                <Shield className="text-soc-accent w-8 h-8" />
                <span className="text-white text-xl font-bold tracking-wide">NeuroGuard</span>
            </div>

            <nav className="flex-1 p-4 space-y-2">
                <NavLink
                    to="/"
                    className={({ isActive }) => `flex items-center gap-3 px-4 py-3 rounded-lg transition-colors ${isActive ? 'bg-soc-800 text-soc-accent' : 'text-gray-400 hover:text-white hover:bg-soc-800'}`}
                >
                    <Activity className="w-5 h-5" />
                    <span className="font-medium">Dashboard</span>
                </NavLink>

                <NavLink
                    to="/logs"
                    className={({ isActive }) => `flex items-center gap-3 px-4 py-3 rounded-lg transition-colors ${isActive ? 'bg-soc-800 text-soc-accent' : 'text-gray-400 hover:text-white hover:bg-soc-800'}`}
                >
                    <ListFilter className="w-5 h-5" />
                    <span className="font-medium">Live Logs</span>
                </NavLink>

                <NavLink
                    to="/history"
                    className={({ isActive }) => `flex items-center gap-3 px-4 py-3 rounded-lg transition-colors ${isActive ? 'bg-soc-800 text-soc-accent' : 'text-gray-400 hover:text-white hover:bg-soc-800'}`}
                >
                    <Shield className="w-5 h-5" />
                    <span className="font-medium">Threat History</span>
                </NavLink>

                {role === 'Admin' && (
                    <>
                        <NavLink
                            to="/settings"
                            className={({ isActive }) => `flex items-center gap-3 px-4 py-3 rounded-lg transition-colors ${isActive ? 'bg-soc-800 text-soc-accent' : 'text-gray-400 hover:text-white hover:bg-soc-800'}`}
                        >
                            <Settings className="w-5 h-5" />
                            <span className="font-medium">Settings</span>
                        </NavLink>

                        <NavLink
                            to="/automation"
                            className={({ isActive }) => `flex items-center gap-3 px-4 py-3 rounded-lg transition-colors ${isActive ? 'bg-soc-800 text-soc-accent' : 'text-gray-400 hover:text-white hover:bg-soc-800'}`}
                        >
                            <ShieldAlert className="w-5 h-5" />
                            <span className="font-medium">Automation Center</span>
                        </NavLink>
                    </>
                )}
            </nav>

            <div className="p-6 border-t border-soc-700">
                <div className="text-xs text-center text-gray-500">v1.0.0 Command Center</div>
            </div>
        </aside>
    );
};
