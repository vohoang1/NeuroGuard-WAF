package api

import (
	"net/http"

	"github.com/gin-gonic/gin"

	"neuroguard-api/internal/models"
	"neuroguard-api/internal/remediation"
)

// GET /api/remediation/status
func GetRemediationStatus(c *gin.Context) {
	tenantID, exists := c.Get("tenant_id")
	if !exists {
		c.JSON(http.StatusUnauthorized, models.APIError{Error: "Unauthorized"})
		return
	}
	cfg := remediation.GetConfig(tenantID.(string))
	blocks := remediation.GetBlocklist()

	c.JSON(http.StatusOK, gin.H{
		"enabled":         cfg.AutoBlockEnabled,
		"blocklist_count": len(blocks),
	})
}

// POST /api/remediation/toggle
func ToggleRemediation(c *gin.Context) {
	tenantID, exists := c.Get("tenant_id")
	if !exists {
		c.JSON(http.StatusUnauthorized, models.APIError{Error: "Unauthorized"})
		return
	}
	var payload struct {
		Enabled bool `json:"enabled"`
	}
	if err := c.ShouldBindJSON(&payload); err != nil {
		c.JSON(http.StatusBadRequest, models.APIError{Error: "Invalid payload"})
		return
	}

	cfg := remediation.GetConfig(tenantID.(string))
	cfg.AutoBlockEnabled = payload.Enabled
	remediation.UpdateConfig(tenantID.(string), cfg)

	c.JSON(http.StatusOK, gin.H{"status": "success", "enabled": cfg.AutoBlockEnabled})
}

// GET /api/remediation/blocklist
func GetBlocklist(c *gin.Context) {
	blocks := remediation.GetBlocklist()
	c.JSON(http.StatusOK, gin.H{"blocked_ips": blocks})
}

// POST /api/remediation/unblock
func UnblockIP(c *gin.Context) {
	var payload struct {
		IP string `json:"ip"`
	}
	if err := c.ShouldBindJSON(&payload); err != nil {
		c.JSON(http.StatusBadRequest, models.APIError{Error: "Invalid payload"})
		return
	}

	remediation.UnblockIP(payload.IP)
	c.JSON(http.StatusOK, gin.H{"status": "success", "message": "IP unblocked"})
}

// GET /api/remediation/whitelist
func GetWhitelist(c *gin.Context) {
	c.JSON(http.StatusOK, gin.H{"whitelist": remediation.GetWhitelist()})
}

// POST /api/remediation/whitelist
func UpdateWhitelist(c *gin.Context) {
	var payload struct {
		IP     string `json:"ip"`
		Action string `json:"action"` // "add" or "remove"
	}
	if err := c.ShouldBindJSON(&payload); err != nil {
		c.JSON(http.StatusBadRequest, models.APIError{Error: "Invalid payload"})
		return
	}

	if payload.Action == "add" {
		remediation.AddToWhitelist(payload.IP)
	} else if payload.Action == "remove" {
		remediation.RemoveFromWhitelist(payload.IP)
	} else {
		c.JSON(http.StatusBadRequest, models.APIError{Error: "Invalid action"})
		return
	}

	c.JSON(http.StatusOK, gin.H{"status": "success", "whitelist": remediation.GetWhitelist()})
}

// Internal route for WAF Rust Plugin (No JWT required, ideally protected by network rules)
// GET /api/internal/blocklist
func InternalGetBlocklist(c *gin.Context) {
	blocks := remediation.GetBlocklist()
	c.JSON(http.StatusOK, gin.H{"blocked_ips": blocks})
}
