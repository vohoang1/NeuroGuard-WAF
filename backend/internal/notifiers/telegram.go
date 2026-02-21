package notifiers

import (
	"bytes"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"os"
)

func SendTelegramAlert(ip string, reason string) {
	botToken := os.Getenv("TELEGRAM_BOT_TOKEN")
	chatID := os.Getenv("TELEGRAM_CHAT_ID")

	if botToken == "" || chatID == "" {
		log.Println("[Telegram] Bot token or Chat ID not configured. Skipping alert.")
		return
	}

	url := fmt.Sprintf("https://api.telegram.org/bot%s/sendMessage", botToken)

	message := fmt.Sprintf("🚨 *NeuroGuard Auto-Remediation Alert*\n\n*IP:* `%s`\n*Reason:* %s\n*Action:* Blocked", ip, reason)

	payload := map[string]interface{}{
		"chat_id":    chatID,
		"text":       message,
		"parse_mode": "MarkdownV2",
	}

	jsonPayload, _ := json.Marshal(payload)

	resp, err := http.Post(url, "application/json", bytes.NewBuffer(jsonPayload))
	if err != nil {
		log.Printf("[Telegram] Failed to send alert: %v", err)
		return
	}
	defer resp.Body.Close()

	if resp.StatusCode != 200 {
		log.Printf("[Telegram] API returned status: %d", resp.StatusCode)
	}
}
