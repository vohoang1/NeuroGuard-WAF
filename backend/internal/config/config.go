package config

import (
	"strings"

	"github.com/spf13/viper"
)

type Config struct {
	Port           string
	JWTSecret      string
	ClickHouseHost string
	ClickHouseUser string
	ClickHousePass string
	ClickHouseDB   string
	PostgresDSN    string
}

func LoadConfig() *Config {
	viper.AutomaticEnv()
	viper.SetEnvKeyReplacer(strings.NewReplacer(".", "_"))

	viper.SetDefault("PORT", "8081")
	viper.SetDefault("JWT_SECRET", "super_secret_commercial_key_123!")
	viper.SetDefault("CLICKHOUSE_HOST", "localhost:9000") // From docker compose network: "clickhouse:9000"
	viper.SetDefault("CLICKHOUSE_USER", "admin")
	viper.SetDefault("CLICKHOUSE_PASS", "neuroguard_secure_pwd")
	viper.SetDefault("CLICKHOUSE_DB", "neuroguard")
	viper.SetDefault("POSTGRES_DSN", "host=postgres user=admin password=neuroguard_secure_pwd dbname=neuroguard port=5432 sslmode=disable TimeZone=UTC")

	return &Config{
		Port:           viper.GetString("PORT"),
		JWTSecret:      viper.GetString("JWT_SECRET"),
		ClickHouseHost: viper.GetString("CLICKHOUSE_HOST"),
		ClickHouseUser: viper.GetString("CLICKHOUSE_USER"),
		ClickHousePass: viper.GetString("CLICKHOUSE_PASS"),
		ClickHouseDB:   viper.GetString("CLICKHOUSE_DB"),
		PostgresDSN:    viper.GetString("POSTGRES_DSN"),
	}
}
