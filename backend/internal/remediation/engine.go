package remediation

import (
	"context"
	"log"
	"sync"
	"time"

	"neuroguard-api/internal/db"
	"neuroguard-api/internal/notifiers"
)

type Config struct {
	AutoBlockEnabled bool   `json:"auto_block_enabled"`
	WebhookURL       string `json:"webhook_url"`
	Threshold        int    `json:"threshold"`
	TimeWindow       string `json:"time_window"` // "1 MINUTE", "5 MINUTE"
}

// Global mutable config for simplicity
var (
	mu            sync.RWMutex
	Configs       = make(map[string]Config)
	DefaultConfig = Config{
		AutoBlockEnabled: false,
		WebhookURL:       "https://hooks.slack.com/services/MOCK/WEBHOOK/URL",
		Threshold:        5,
		TimeWindow:       "1 MINUTE",
	}

	blockedIPsMu sync.RWMutex
	BlockedIPs   = make(map[string]time.Time)
)

func UpdateConfig(tenantID string, cfg Config) {
	mu.Lock()
	defer mu.Unlock()
	existing, ok := Configs[tenantID]
	if !ok {
		existing = DefaultConfig
	}
	existing.AutoBlockEnabled = cfg.AutoBlockEnabled
	if cfg.WebhookURL != "" {
		existing.WebhookURL = cfg.WebhookURL
	}
	if cfg.Threshold > 0 {
		existing.Threshold = cfg.Threshold
	}
	Configs[tenantID] = existing
}

func GetConfig(tenantID string) Config {
	mu.RLock()
	defer mu.RUnlock()
	if cfg, ok := Configs[tenantID]; ok {
		return cfg
	}
	return DefaultConfig
}

func StartEngine() {
	go func() {
		ticker := time.NewTicker(10 * time.Second)
		for range ticker.C {
			mu.RLock()
			activeTenants := make(map[string]Config)
			for t, c := range Configs {
				if c.AutoBlockEnabled {
					activeTenants[t] = c
				}
			}
			mu.RUnlock()

			for tenantID, cfg := range activeTenants {
				processRemediation(tenantID, cfg)
			}
		}
	}()
	log.Println("[Remediation] Auto-Remediation Engine Started (Tenant-Aware).")
}

func processRemediation(tenantID string, cfg Config) {
	ctx := context.Background()

	// Query ClickHouse to find IPs exceeding the threshold or critical rules for this tenant
	query := `
		SELECT source_ip, max(confidence) as max_conf, count() as cnt
		FROM neuroguard.waf_logs
		WHERE tenant_id = ? AND timestamp >= now() - INTERVAL 1 MINUTE
		AND action IN ('Block', 'Challenge')
		GROUP BY source_ip
		HAVING cnt > ? OR max_conf > 0.95
	`

	rows, err := db.Conn.Query(ctx, query, tenantID, cfg.Threshold)
	if err != nil {
		log.Printf("[Remediation Tenant %s] Query Error: %v", tenantID, err)
		return
	}
	defer rows.Close()

	var ipsToBlock []string
	var reasons []string

	for rows.Next() {
		var ip string
		var maxConf float32
		var cnt uint64
		if err := rows.Scan(&ip, &maxConf, &cnt); err == nil {
			if IsWhitelisted(ip) {
				log.Printf("[Remediation Tenant %s] Whitelisted IP bypassed: %s", tenantID, ip)
				continue
			}
			reason := "Critical Rule Violation"
			if cnt > uint64(cfg.Threshold) {
				reason = "High Request Velocity"
			}
			ipsToBlock = append(ipsToBlock, ip)
			reasons = append(reasons, reason)
		}
	}

	for i, ip := range ipsToBlock {
		executeBlock(tenantID, ip, reasons[i], cfg.WebhookURL)
	}
}

func executeBlock(tenantID string, ip string, reason string, webhookURL string) {
	ctx := context.Background()

	// Check if already blocked recently (e.g. 1 hour) to avoid spam
	var count uint64
	err := db.Conn.QueryRow(ctx, "SELECT count() FROM neuroguard.remediation_logs WHERE tenant_id = ? AND source_ip = ? AND timestamp >= now() - INTERVAL 1 HOUR", tenantID, ip).Scan(&count)
	if err != nil || count > 0 {
		return // Already processed
	}

	log.Printf("[FIREWALL SYNC] Banning IP for Tenant %s: %s (Reason: %s)", tenantID, ip, reason)

	// Persist to ClickHouse
	db.Conn.Exec(ctx, "INSERT INTO neuroguard.remediation_logs (tenant_id, timestamp, source_ip, action, reason, status) VALUES (?, now(), ?, 'BlockIP', ?, 'Success')", tenantID, ip, reason)

	// Add to memory cache
	blockedIPsMu.Lock()
	BlockedIPs[ip] = time.Now()
	blockedIPsMu.Unlock()

	// Send notification (Async)
	go notifiers.SendTelegramAlert(ip, reason)
}

func GetBlocklist() []string {
	blockedIPsMu.RLock()
	defer blockedIPsMu.RUnlock()
	var ips []string
	// filter expired (e.g. 1 hour)
	for ip, added := range BlockedIPs {
		if time.Since(added) < time.Hour {
			ips = append(ips, ip)
		}
	}
	return ips
}

func UnblockIP(ip string) {
	blockedIPsMu.Lock()
	defer blockedIPsMu.Unlock()
	delete(BlockedIPs, ip)
}
