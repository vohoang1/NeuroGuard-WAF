import { User, LogOut, Bell } from 'lucide-react';
import { useNavigate } from 'react-router-dom';
import { useTenantContext } from '../context/TenantContext';

export const Topbar = () => {
    const navigate = useNavigate();
    const { role, clearAuthContext, tenantId } = useTenantContext();

    const handleLogout = () => {
        clearAuthContext();
        navigate('/login');
    };

    return (
        <header className="h-16 bg-soc-900 border-b border-soc-700 flex items-center justify-between px-6 sticky top-0 z-20">
            <div className="flex items-center gap-4 text-gray-400">
                <span className="text-sm font-medium uppercase tracking-widest hidden md:inline">Command Center Ops</span>
            </div>

            <div className="flex items-center gap-6">
                <button className="relative text-gray-400 hover:text-soc-accent transition">
                    <Bell className="w-5 h-5" />
                    <span className="absolute top-0 right-0 w-2 h-2 bg-soc-danger rounded-full ring-2 ring-soc-900"></span>
                </button>

                <div className="flex items-center gap-3 border-l border-soc-700 pl-6">
                    <div className="bg-soc-800 p-2 rounded-full border border-soc-700">
                        <User className="w-5 h-5 text-soc-accent" />
                    </div>
                    <div className="hidden md:block text-sm">
                        <p className="font-bold text-gray-200 capitalize">{role || 'User'}</p>
                        <p className="text-xs text-gray-500 font-mono" title="Active Tenant ID">{tenantId ? tenantId.substring(0, 8) + '...' : ''}</p>
                    </div>
                    <button
                        onClick={handleLogout}
                        className="ml-4 p-2 text-gray-500 hover:text-white hover:bg-soc-800 rounded transition"
                        title="Secure Logout"
                    >
                        <LogOut className="w-5 h-5" />
                    </button>
                </div>
            </div>
        </header>
    );
};
