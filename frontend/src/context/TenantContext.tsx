import React, { createContext, useContext, useState, ReactNode } from 'react';

interface TenantContextProps {
    tenantId: string | null;
    role: string | null;
    setAuthContext: (tenantId: string, role: string) => void;
    clearAuthContext: () => void;
}

const TenantContext = createContext<TenantContextProps | undefined>(undefined);

export const TenantProvider: React.FC<{ children: ReactNode }> = ({ children }) => {
    const [tenantId, setTenantId] = useState<string | null>(localStorage.getItem('ng_tenant_id'));
    const [role, setRole] = useState<string | null>(localStorage.getItem('ng_role'));

    const setAuthContext = (newTenantId: string, newRole: string) => {
        setTenantId(newTenantId);
        setRole(newRole);
        localStorage.setItem('ng_tenant_id', newTenantId);
        localStorage.setItem('ng_role', newRole);
    };

    const clearAuthContext = () => {
        setTenantId(null);
        setRole(null);
        localStorage.removeItem('ng_tenant_id');
        localStorage.removeItem('ng_role');
        localStorage.removeItem('ng_token');
    };

    return (
        <TenantContext.Provider value={{ tenantId, role, setAuthContext, clearAuthContext }}>
            {children}
        </TenantContext.Provider>
    );
};

export const useTenantContext = () => {
    const context = useContext(TenantContext);
    if (!context) {
        throw new Error('useTenantContext must be used within a TenantProvider');
    }
    return context;
};
