package db

import (
	"context"
	"log"

	"github.com/ClickHouse/clickhouse-go/v2"
	"github.com/ClickHouse/clickhouse-go/v2/lib/driver"

	"neuroguard-api/internal/config"
)

var Conn driver.Conn

func Init(cfg *config.Config) {
	var err error
	Conn, err = clickhouse.Open(&clickhouse.Options{
		Addr: []string{cfg.ClickHouseHost},
		Auth: clickhouse.Auth{
			Database: cfg.ClickHouseDB,
			Username: cfg.ClickHouseUser,
			Password: cfg.ClickHousePass,
		},
		Debug: false,
	})
	if err != nil {
		log.Fatalf("Failed to connect to ClickHouse: %v", err)
	}

	if err := Conn.Ping(context.Background()); err != nil {
		log.Fatalf("Failed to ping ClickHouse: %v", err)
	}
	
	setupTables()
	log.Println("Successfully connected to ClickHouse database and verified schema!")
}

func setupTables() {
	query := `
		CREATE TABLE IF NOT EXISTS neuroguard.remediation_logs
		(
			timestamp DateTime64(3, 'UTC'),
			source_ip String,
			action String,
			reason String,
			status String
		)
		ENGINE = MergeTree()
		PARTITION BY toYYYYMMDD(timestamp)
		ORDER BY (timestamp, source_ip);
	`
	if err := Conn.Exec(context.Background(), query); err != nil {
		log.Fatalf("Failed to create remediation_logs table: %v", err)
	}
}
