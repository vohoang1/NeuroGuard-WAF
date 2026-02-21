import React, { useState } from 'react';
import { useNavigate } from 'react-router-dom';
import { ShieldAlert } from 'lucide-react';
import { apiClient } from '../api/client';
import toast from 'react-hot-toast';
import { useTenantContext } from '../context/TenantContext';

export const Login = () => {
    const [username, setUsername] = useState('');
    const [password, setPassword] = useState('');
    const navigate = useNavigate();
    const { setAuthContext } = useTenantContext();

    const handleLogin = async (e: React.FormEvent) => {
        e.preventDefault();
        try {
            const res = await apiClient.post('/login', { username, password });
            const { token, tenant_id, role } = res.data;
            setAuthContext(tenant_id, role);
            localStorage.setItem('ng_token', token);
            toast.success('Authentication successful');
            navigate('/');
        } catch (err) {
            toast.error('Invalid credentials. Access denied.', {
                style: {
                    background: '#EF4444',
                    color: '#fff',
                }
            });
        }
    };

    return (
        <div className="flex h-screen items-center justify-center bg-soc-900 flex-col">
            <div className="bg-soc-800 p-8 rounded-xl shadow-2xl border border-soc-700 w-full max-w-sm">
                <div className="flex justify-center mb-6">
                    <ShieldAlert size={56} className="text-soc-accent" />
                </div>
                <h2 className="text-2xl font-bold text-center mb-6 text-white tracking-wide">NeuroGuard SOC</h2>
                <form onSubmit={handleLogin} className="space-y-4">
                    <input
                        type="text"
                        placeholder="Operator ID"
                        className="w-full p-3 bg-soc-900 border border-soc-700 rounded text-white focus:outline-none focus:border-soc-accent transition"
                        value={username}
                        onChange={(e) => setUsername(e.target.value)}
                    />
                    <input
                        type="password"
                        placeholder="Passphrase"
                        className="w-full p-3 bg-soc-900 border border-soc-700 rounded text-white focus:outline-none focus:border-soc-accent transition"
                        value={password}
                        onChange={(e) => setPassword(e.target.value)}
                    />
                    <button type="submit" className="w-full p-3 bg-soc-accent text-white font-bold rounded hover:bg-blue-600 transition tracking-wider">
                        AUTHORIZE
                    </button>
                </form>
                <p className="mt-6 text-xs text-center text-gray-500 uppercase tracking-widest">Authorized Personnel Only</p>
            </div>
        </div>
    );
};
