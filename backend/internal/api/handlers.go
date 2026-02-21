package api

import (
	"context"
	"fmt"
	"net/http"
	"strconv"
	"time"

	"github.com/gin-gonic/gin"

	"neuroguard-api/internal/db"
	"neuroguard-api/internal/models"
	"neuroguard-api/internal/remediation"
)

// Helper to get tenant ID from context.
func getTenantID(c *gin.Context) string {
	tenant := "00000000-0000-0000-0000-000000000000"
	if t, exists := c.Get("tenant_id"); exists {
		tenant = t.(string)
	}
	return tenant
}

// Global Error Handler Middleware
func ErrorHandler() gin.HandlerFunc {
	return func(c *gin.Context) {
		c.Next()
		if len(c.Errors) > 0 {
			c.JSON(http.StatusInternalServerError, models.APIError{
				Error:   "Server Error",
				Message: c.Errors.String(),
			})
		}
	}
}

// GET /api/stats/summary
func GetSummaryStats(c *gin.Context) {
	tenantID := getTenantID(c)

	summaryQuery := `
		SELECT 
			count() as total_requests,
			countIf(action IN ('Block', 'Challenge')) as blocked_requests,
			countIf(action IN ('Block', 'Challenge') AND ai_score >= 0.90) as blocked_by_ai,
			countIf(action IN ('Block', 'Challenge') AND ai_score < 0.90) as blocked_by_rules
		FROM neuroguard.waf_logs
		WHERE tenant_id = ? AND timestamp >= now() - INTERVAL 24 HOUR
	`

	var total, blocked, blockedByAI, blockedByName uint64
	if err := db.Conn.QueryRow(context.Background(), summaryQuery, tenantID).Scan(&total, &blocked, &blockedByAI, &blockedByName); err != nil {
		c.Error(err)
		return
	}

	queryAttackTypes := `
		SELECT attack_type, count() 
		FROM neuroguard.waf_logs 
		WHERE tenant_id = ? AND timestamp >= now() - INTERVAL 24 HOUR AND attack_type != 'Unknown'
		GROUP BY attack_type
	`

	rows, err := db.Conn.Query(context.Background(), queryAttackTypes, tenantID)
	if err != nil {
		c.Error(err)
		return
	}
	defer rows.Close()

	var dist []map[string]interface{}
	for rows.Next() {
		var attackType string
		var count uint64
		if err := rows.Scan(&attackType, &count); err == nil {
			dist = append(dist, map[string]interface{}{"type": attackType, "count": count})
		}
	}

	c.JSON(http.StatusOK, gin.H{
		"total_requests":   total,
		"blocked_requests": blocked,
		"blocked_by_ai":    blockedByAI,
		"blocked_by_rules": blockedByName,
		"distribution":     dist,
	})
}

// GET /api/logs
func GetLogs(c *gin.Context) {
	tenantID := getTenantID(c)
	page, _ := strconv.Atoi(c.DefaultQuery("page", "1"))
	limit, _ := strconv.Atoi(c.DefaultQuery("limit", "50"))
	offset := (page - 1) * limit

	ipFilter := c.Query("ip")
	actionFilter := c.Query("action")
	typeFilter := c.Query("type")

	query := `
		SELECT timestamp, correlation_id, source_ip, method, uri, attack_type, confidence, rule_id, action, user_agent, country_code 
		FROM neuroguard.waf_logs
	`
	whereClause := " WHERE tenant_id = ?"
	var args []interface{}
	args = append(args, tenantID)

	if ipFilter != "" {
		whereClause += " AND source_ip = ?"
		args = append(args, ipFilter)
	}
	if actionFilter != "" {
		whereClause += " AND action = ?"
		args = append(args, actionFilter)
	}
	if typeFilter != "" {
		whereClause += " AND attack_type = ?"
		args = append(args, typeFilter)
	}

	query += whereClause + fmt.Sprintf(" ORDER BY timestamp DESC LIMIT %d OFFSET %d", limit, offset)

	rows, err := db.Conn.Query(context.Background(), query, args...)
	if err != nil {
		c.Error(err)
		return
	}
	defer rows.Close()

	var logs []models.WafLog
	for rows.Next() {
		var log models.WafLog
		if err := rows.Scan(&log.Timestamp, &log.CorrelationID, &log.SourceIP, &log.Method, &log.URI, &log.AttackType, &log.Confidence, &log.RuleID, &log.Action, &log.UserAgent, &log.CountryCode); err == nil {
			logs = append(logs, log)
		}
	}

	c.JSON(http.StatusOK, logs)
}

// GET /api/stats/timeseries
func GetTimeSeries(c *gin.Context) {
	tenantID := getTenantID(c)

	query := `
		SELECT
			toStartOfHour(timestamp) as hour,
			count() as total_attacks,
			countIf(action = 'Block') as blocked_attacks
		FROM neuroguard.waf_logs
		WHERE tenant_id = ? AND timestamp >= now() - INTERVAL 24 HOUR AND action != 'Allow'
		GROUP BY hour
		ORDER BY hour ASC
	`

	rows, err := db.Conn.Query(context.Background(), query, tenantID)
	if err != nil {
		c.Error(err)
		return
	}
	defer rows.Close()

	var data []map[string]interface{}
	for rows.Next() {
		var hour time.Time
		var total, blocked uint64
		if err := rows.Scan(&hour, &total, &blocked); err == nil {
			data = append(data, map[string]interface{}{
				"time":    hour.Format("15:00"),
				"total":   total,
				"blocked": blocked,
			})
		}
	}

	c.JSON(http.StatusOK, data)
}

// GET /api/settings
func GetSettings(c *gin.Context) {
	tenantID, exists := c.Get("tenant_id")
	if !exists {
		c.JSON(http.StatusUnauthorized, models.APIError{Error: "Unauthorized"})
		return
	}
	c.JSON(http.StatusOK, remediation.GetConfig(tenantID.(string)))
}

// POST /api/settings
func UpdateSettings(c *gin.Context) {
	tenantID, exists := c.Get("tenant_id")
	if !exists {
		c.JSON(http.StatusUnauthorized, models.APIError{Error: "Unauthorized"})
		return
	}

	var cfg remediation.Config
	if err := c.ShouldBindJSON(&cfg); err != nil {
		c.JSON(http.StatusBadRequest, models.APIError{Error: "Invalid payload", Message: err.Error()})
		return
	}
	remediation.UpdateConfig(tenantID.(string), cfg)
	c.JSON(http.StatusOK, gin.H{"status": "success", "message": "Settings updated"})
}

// GET /api/history
func GetThreatHistory(c *gin.Context) {
	tenantID := getTenantID(c)

	query := `
		SELECT timestamp, source_ip, action, reason, status
		FROM neuroguard.remediation_logs
		WHERE tenant_id = ?
		ORDER BY timestamp DESC
		LIMIT 100
	`
	rows, err := db.Conn.Query(context.Background(), query, tenantID)
	if err != nil {
		c.Error(err)
		return
	}
	defer rows.Close()

	var history []map[string]interface{}
	for rows.Next() {
		var ts time.Time
		var ip, action, reason, status string
		if err := rows.Scan(&ts, &ip, &action, &reason, &status); err == nil {
			history = append(history, map[string]interface{}{
				"timestamp": ts,
				"source_ip": ip,
				"action":    action,
				"reason":    reason,
				"status":    status,
			})
		}
	}
	c.JSON(http.StatusOK, history)
}
