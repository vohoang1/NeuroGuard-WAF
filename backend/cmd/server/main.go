package main

import (
	"log"
	"time"

	"github.com/gin-contrib/cors"
	"github.com/gin-gonic/gin"

	"neuroguard-api/internal/api"
	"neuroguard-api/internal/config"
	"neuroguard-api/internal/db"
	"neuroguard-api/internal/remediation"
)

func main() {
	cfg := config.LoadConfig()
	db.InitPostgres(cfg)
	db.Init(cfg)
	remediation.StartEngine()

	// Set gin to release mode in production
	gin.SetMode(gin.ReleaseMode)
	r := gin.Default()

	// Apply global error handler
	r.Use(api.ErrorHandler())

	// CORS Setup - Strict Commercial Standards
	r.Use(cors.New(cors.Config{
		AllowOrigins:     []string{"http://localhost:5173", "http://localhost:80", "http://localhost"},
		AllowMethods:     []string{"GET", "POST", "PUT", "OPTIONS"},
		AllowHeaders:     []string{"Origin", "Content-Type", "Authorization", "Accept"},
		ExposeHeaders:    []string{"Content-Length"},
		AllowCredentials: true,
		MaxAge:           12 * time.Hour,
	}))

	authHandler := &api.AuthHandler{JWTSecret: []byte(cfg.JWTSecret)}

	// Public routes
	r.GET("/health", func(c *gin.Context) { c.JSON(200, gin.H{"status": "UP"}) })
	r.POST("/api/login", authHandler.Login)
	r.GET("/api/internal/blocklist", api.InternalGetBlocklist)

	// Protected API group
	authRoutes := r.Group("/api")
	authRoutes.Use(api.AuthMiddleware(cfg.JWTSecret))
	{
		authRoutes.GET("/stats/summary", api.GetSummaryStats)
		authRoutes.GET("/logs", api.GetLogs)
		authRoutes.GET("/stats/timeseries", api.GetTimeSeries)

		// Auto-Remediation endpoints
		authRoutes.GET("/settings", api.GetSettings)
		authRoutes.POST("/settings", api.RequireRole("Admin"), api.UpdateSettings)
		authRoutes.GET("/history", api.GetThreatHistory)

		authRoutes.GET("/remediation/status", api.GetRemediationStatus)
		authRoutes.POST("/remediation/toggle", api.RequireRole("Admin"), api.ToggleRemediation)
		authRoutes.GET("/remediation/blocklist", api.GetBlocklist)
		authRoutes.POST("/remediation/unblock", api.RequireRole("Admin"), api.UnblockIP)
		authRoutes.GET("/remediation/whitelist", api.GetWhitelist)
		authRoutes.POST("/remediation/whitelist", api.RequireRole("Admin"), api.UpdateWhitelist)
	}

	log.Printf("Starting NeuroGuard API Server on port %s...", cfg.Port)
	if err := r.Run(":" + cfg.Port); err != nil {
		log.Fatalf("Server stopped: %v", err)
	}
}
