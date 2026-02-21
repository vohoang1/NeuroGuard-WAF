import axios from 'axios';

// Vite env vars are prefixed with VITE_
const baseURL = import.meta.env.VITE_API_URL || '/api';

export const apiClient = axios.create({
    baseURL,
    timeout: 10000,
});

apiClient.interceptors.request.use((config) => {
    const token = localStorage.getItem('ng_token');
    if (token) {
        config.headers.Authorization = `Bearer ${token}`;
    }
    return config;
});

// Types & Interfaces
export interface SummaryStats {
    total_requests: number;
    blocked_requests: number;
    blocked_by_ai: number;
    blocked_by_rules: number;
    distribution: { type: string; count: number }[];
}

export interface WafLog {
    timestamp: string;
    correlation_id: string;
    source_ip: string;
    method: string;
    uri: string;
    attack_type: string;
    confidence: number;
    rule_id: number | null;
    action: string;
    user_agent: string;
    country_code: string;
}

export interface TimeSeriesPoint {
    time: string;
    total: number;
    blocked: number;
}

export interface RemediationConfig {
    auto_block_enabled: boolean;
    webhook_url: string;
    threshold: number;
    time_window: string;
}

export interface ThreatHistoryLog {
    timestamp: string;
    source_ip: string;
    action: string;
    reason: string;
    status: string;
}
