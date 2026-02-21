import { BrowserRouter as Router, Routes, Route, Navigate, Outlet } from 'react-router-dom';
import { Login } from './pages/Login';
import { Dashboard } from './pages/Dashboard';
import { LiveLogs } from './pages/LiveLogs';
import { Sidebar } from './components/Sidebar';
import { Topbar } from './components/Topbar';
import { OrganizationSettings } from './pages/OrganizationSettings';
import { ThreatHistory } from './pages/ThreatHistory';
import { Automation } from './pages/Automation';

import { TenantProvider, useTenantContext } from './context/TenantContext';

const ProtectedRoute = () => {
    const token = localStorage.getItem('ng_token');
    const { tenantId } = useTenantContext();
    if (!token || !tenantId) return <Navigate to="/login" replace />;

    return (
        <div className="flex h-screen overflow-hidden bg-soc-900 text-gray-200 font-sans">
            <Sidebar />
            <div className="flex-1 flex flex-col min-w-0 overflow-y-auto">
                <Topbar />
                <main className="flex-1 p-6">
                    <Outlet />
                </main>
            </div>
        </div>
    );
};

export default function App() {
    return (
        <TenantProvider>
            <Router>
                <Routes>
                    <Route path="/login" element={<Login />} />

                    <Route element={<ProtectedRoute />}>
                        <Route path="/" element={<Dashboard />} />
                        <Route path="/logs" element={<LiveLogs />} />
                        <Route path="/settings" element={<OrganizationSettings />} />
                        <Route path="/history" element={<ThreatHistory />} />
                        <Route path="/automation" element={<Automation />} />
                    </Route>

                    <Route path="*" element={<Navigate to="/" replace />} />
                </Routes>
            </Router>
        </TenantProvider>
    );
}
