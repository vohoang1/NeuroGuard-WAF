-- Create dedicated database
CREATE DATABASE IF NOT EXISTS neuroguard;

-- 1. Main WAF Logs Table (Raw Data)
-- Optimized for high-throughput inserts and time-range queries
CREATE TABLE IF NOT EXISTS neuroguard.waf_logs
(
    tenant_id String,
    timestamp DateTime64(3, 'UTC'),
    attack_type String,
    confidence Float32,
    evidence String,
    rule_id Nullable(UInt32),
    method String,
    path String,
    source_ip String,
    user_agent String,
    country_code String,
    ai_score Float32,
    action String
)
ENGINE = MergeTree()
PARTITION BY toYYYYMMDD(timestamp)
ORDER BY (tenant_id, timestamp, action, attack_type)
TTL toDateTime(timestamp) + INTERVAL 30 DAY; -- Auto-purge logs older than 30 days

-- Row-Level Security Policy for Tenant Isolation
CREATE ROW POLICY IF NOT EXISTS tenant_isolation_policy ON neuroguard.waf_logs
FOR SELECT USING tenant_id = getSetting('custom_tenant_id') TO ALL;

-- 2. Materialized View: Traffic & Action Statistics (Req/Sec Aggregation)
-- Powers the main dashboard time-series chart
CREATE MATERIALIZED VIEW IF NOT EXISTS neuroguard.waf_metrics_minute_mv
ENGINE = SummingMergeTree()
PARTITION BY toYYYYMMDD(minute)
ORDER BY (tenant_id, minute)
AS SELECT
    tenant_id,
    toStartOfMinute(timestamp) AS minute,
    count() AS total_requests,
    countIf(action = 'Block') AS blocked_requests,
    countIf(action = 'Challenge') AS challenged_requests,
    countIf(action = 'Allow') AS allowed_requests
FROM neuroguard.waf_logs
GROUP BY tenant_id, minute;

-- 3. Materialized View: Top Attacking IPs
-- Powers the "Top Threat Actors" table
CREATE MATERIALIZED VIEW IF NOT EXISTS neuroguard.waf_top_ips_mv
ENGINE = SummingMergeTree()
PARTITION BY toYYYYMMDD(date)
ORDER BY (tenant_id, date, source_ip)
AS SELECT
    tenant_id,
    toDate(timestamp) AS date,
    source_ip,
    count() AS block_count
FROM neuroguard.waf_logs
WHERE action = 'Block' OR action = 'Challenge'
GROUP BY tenant_id, date, source_ip;

-- 4. Materialized View: Attack Types Distribution
-- Powers the pie chart/donut chart for attack vectors
CREATE MATERIALIZED VIEW IF NOT EXISTS neuroguard.waf_attack_types_mv
ENGINE = SummingMergeTree()
PARTITION BY toYYYYMMDD(date)
ORDER BY (tenant_id, date, attack_type)
AS SELECT
    tenant_id,
    toDate(timestamp) AS date,
    attack_type,
    count() AS occurrences
FROM neuroguard.waf_logs
WHERE attack_type != 'Unknown'
GROUP BY tenant_id, date, attack_type;
