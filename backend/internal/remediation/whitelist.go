package remediation

import (
	"encoding/json"
	"log"
	"os"
	"sync"
)

var (
	whitelistMu sync.RWMutex
	Whitelist   = make(map[string]bool)
	configPath  = "data/whitelist.json"
)

func init() {
	// Initialize with some defaults and try to load
	Whitelist["127.0.0.1"] = true
	Whitelist["10.0.0.1"] = true

	LoadWhitelist()
}

func LoadWhitelist() {
	whitelistMu.Lock()
	defer whitelistMu.Unlock()

	err := os.MkdirAll("data", 0755)
	if err != nil {
		log.Printf("[Whitelist] Failed to create data dir: %v", err)
	}

	data, err := os.ReadFile(configPath)
	if err != nil {
		if os.IsNotExist(err) {
			SaveWhitelistLocked()
		}
		return
	}

	var ips []string
	if err := json.Unmarshal(data, &ips); err == nil {
		// Clear existing and reload
		Whitelist = make(map[string]bool)
		for _, ip := range ips {
			Whitelist[ip] = true
		}
		// ensure default is always present
		Whitelist["127.0.0.1"] = true
	}
}

func SaveWhitelistLocked() {
	var ips []string
	for ip, active := range Whitelist {
		if active {
			ips = append(ips, ip)
		}
	}
	data, _ := json.MarshalIndent(ips, "", "  ")
	os.WriteFile(configPath, data, 0644)
}

func IsWhitelisted(ip string) bool {
	whitelistMu.RLock()
	defer whitelistMu.RUnlock()
	return Whitelist[ip]
}

func AddToWhitelist(ip string) {
	whitelistMu.Lock()
	defer whitelistMu.Unlock()
	Whitelist[ip] = true
	SaveWhitelistLocked()
}

func RemoveFromWhitelist(ip string) {
	whitelistMu.Lock()
	defer whitelistMu.Unlock()
	delete(Whitelist, ip)
	SaveWhitelistLocked()
}

func GetWhitelist() []string {
	whitelistMu.RLock()
	defer whitelistMu.RUnlock()
	var ips []string
	for ip := range Whitelist {
		ips = append(ips, ip)
	}
	return ips
}
