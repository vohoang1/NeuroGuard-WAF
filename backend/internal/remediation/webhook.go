package remediation

import (
	"bytes"
	"encoding/json"
	"log"
	"net/http"
	"time"
)

type WebhookPayload struct {
	Text   string `json:"text"`
	Blocks []struct {
		Type string `json:"type"`
		Text *struct {
			Type string `json:"type"`
			Text string `json:"text"`
		} `json:"text,omitempty"`
	} `json:"blocks,omitempty"`
}

func NotifyWebhook(webhookURL, ip, reason string) {
	if webhookURL == "" || webhookURL == "https://hooks.slack.com/services/MOCK/WEBHOOK/URL" {
		log.Printf("[Webhook] Mock Notification Sent: Banned IP %s due to %s", ip, reason)
		return
	}

	payload := WebhookPayload{
		Text: "🚨 *NeuroGuard Auto-Remediation Triggered*",
	}

	// Example structure for Slack
	blockText := "🚨 *NeuroGuard Auto-Remediation*\n" +
		"*Target IP:* `" + ip + "`\n" +
		"*Action Taken:* `Global Ban`\n" +
		"*Trigger Reason:* " + reason + "\n\n" +
		"<https://admin.neuroguard.local/remediation|View on Dashboard>"

	payload.Blocks = append(payload.Blocks, struct {
		Type string `json:"type"`
		Text *struct {
			Type string `json:"type"`
			Text string `json:"text"`
		} `json:"text,omitempty"`
	}{
		Type: "section",
		Text: &struct {
			Type string `json:"type"`
			Text string `json:"text"`
		}{
			Type: "mrkdwn",
			Text: blockText,
		},
	})

	body, _ := json.Marshal(payload)
	req, err := http.NewRequest("POST", webhookURL, bytes.NewBuffer(body))
	if err != nil {
		log.Printf("[Webhook] Request Creation Error: %v", err)
		return
	}
	req.Header.Set("Content-Type", "application/json")

	client := &http.Client{Timeout: 5 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		log.Printf("[Webhook] Delivery Failed: %v", err)
		return
	}
	defer resp.Body.Close()
	
	if resp.StatusCode >= 400 {
		log.Printf("[Webhook] Delivery returned status %d", resp.StatusCode)
	} else {
		log.Printf("[Webhook] Delivered alert for IP %s", ip)
	}
}
